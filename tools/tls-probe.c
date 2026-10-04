/*
 * tools/tls-probe.c -- try the TLS client (src/net/tls.c) against a server.
 *
 * Connects to ADDR on port 853, runs the handshake, sends one DNS query over
 * it and prints what came back: the suite, whether the server took ALPN
 * "dot", how long each step took, and the answer's rcode.  It is for
 * checking the engine against real TLS stacks -- public DoT services,
 * authoritative servers that offer 853, openssl s_server -- and is not built
 * by `make` or installed.
 *
 *   make tls-probe
 *   bin/elpis-tls-probe 1.1.1.1 example.com A
 *   bin/elpis-tls-probe 127.0.0.1@8853 . NS --no-alpn
 */
#include "elpis/tls.h"
#include "elpis/util.h"
#include "elpis/sock.h"
#include "elpis/simd.h"
#include "elpis/log.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_MS 5000

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static unsigned qtype_of(const char *s)
{
    static const struct { const char *name; unsigned type; } map[] = {
        { "A", 1 }, { "NS", 2 }, { "SOA", 6 }, { "MX", 15 }, { "TXT", 16 },
        { "AAAA", 28 }, { "DS", 43 }, { "DNSKEY", 48 }, { "HTTPS", 65 }
    };
    size_t i;
    for (i = 0; i < sizeof map / sizeof map[0]; i++)
        if (elpis_strcasecmp_ascii(s, map[i].name) == 0)
            return map[i].type;
    return (unsigned)atoi(s);
}

/* A query with its two-byte length prefix, as DNS over TCP and TLS want. */
static size_t build_query(uint8_t *q, const char *name, unsigned type)
{
    size_t n = 2;
    const char *p = name;

    elpis_put16(q + n, (uint16_t)elpis_random_u32());  n += 2;
    elpis_put16(q + n, 0x0100);  n += 2;               /* RD */
    elpis_put16(q + n, 1);  n += 2;
    memset(q + n, 0, 6);  n += 6;
    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63)
            break;
        q[n++] = (uint8_t)l;
        memcpy(q + n, p, l);
        n += l;
        p += l;
        if (*p == '.')
            p++;
    }
    q[n++] = 0;
    elpis_put16(q + n, (uint16_t)type);  n += 2;
    elpis_put16(q + n, 1);  n += 2;
    elpis_put16(q, (uint16_t)(n - 2));
    return n;
}

/* Send what is queued and feed what arrives until `done` says so, the
 * engine fails, or the time runs out.  0, or -1 with a reason printed. */
static int pump(int fd, elpis_tls_t *t, double deadline,
                int (*done)(elpis_tls_t *))
{
    uint8_t buf[16384];

    for (;;) {
        const uint8_t *p;
        size_t n = elpis_tls_out(t, &p);
        struct pollfd pfd;
        int left = (int)(deadline - now_ms());

        if (t->state == ELPIS_TLS_FAILED) {
            /* Send the alert we queued, for the server's log. */
            if (n > 0) {
                ssize_t best_effort = write(fd, p, n);
                (void)best_effort;
            }
            printf("  failed: %s, alert %u\n", elpis_tls_err_name(t->err), t->alert);
            return -1;
        }
        if (done(t))
            return 0;
        if (t->state == ELPIS_TLS_CLOSED) {
            printf("  closed by the server\n");
            return -1;
        }
        if (left <= 0) {
            printf("  timed out\n");
            return -1;
        }
        pfd.fd = fd;
        pfd.events = (short)(POLLIN | (n > 0 ? POLLOUT : 0));
        pfd.revents = 0;
        if (poll(&pfd, 1, left) < 0 && errno != EINTR) {
            printf("  poll: %s\n", strerror(errno));
            return -1;
        }
        if (pfd.revents & POLLOUT) {
            ssize_t w = write(fd, p, n);
            if (w < 0 && errno != EAGAIN && errno != EINTR) {
                printf("  write: %s\n", strerror(errno));
                return -1;
            }
            if (w > 0)
                elpis_tls_out_done(t, (size_t)w);
        }
        if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = read(fd, buf, sizeof buf);
            if (r == 0) {
                printf("  connection closed%s\n",
                       t->state == ELPIS_TLS_HANDSHAKE ? " during the handshake" : "");
                return -1;
            }
            if (r < 0 && errno != EAGAIN && errno != EINTR) {
                printf("  read: %s\n", strerror(errno));
                return -1;
            }
            if (r > 0)
                elpis_tls_feed(t, buf, (size_t)r);
        }
    }
}

static int is_open(elpis_tls_t *t)
{
    return t->state == ELPIS_TLS_OPEN;
}

/* A whole DNS message, length prefix and all, has been decrypted. */
static int have_answer(elpis_tls_t *t)
{
    size_t n = elpis_tls_pending(t);
    const uint8_t *p = t->app.p + t->app.off;
    return n >= 2 && n >= 2u + elpis_get16(p);
}

static int all_sent(elpis_tls_t *t)
{
    const uint8_t *p;
    return elpis_tls_out(t, &p) == 0;
}

int main(int argc, char **argv)
{
    static const char *const rcodes[] = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"
    };
    const char *addr = NULL, *qname = ".", *qtype = "NS", *sni = NULL;
    const char *alpn = "dot";
    elpis_addr_t a;
    elpis_tls_t t;
    uint8_t q[600], ans[65538];
    char astr[80];
    double t0, t1, t2, t3;
    size_t qn, an;
    int fd, i, pos = 0, rc = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-alpn") == 0)
            alpn = NULL;
        else if (strcmp(argv[i], "--sni") == 0 && i + 1 < argc)
            sni = argv[++i];
        else if (pos == 0 && ++pos)
            addr = argv[i];
        else if (pos == 1 && ++pos)
            qname = argv[i];
        else if (pos == 2 && ++pos)
            qtype = argv[i];
    }
    if (addr == NULL) {
        fprintf(stderr, "usage: %s ADDR[@PORT] [QNAME [QTYPE]] [--sni NAME] [--no-alpn]\n",
                argv[0]);
        return 2;
    }
    elpis_log_init(ELPIS_LOG_DST_STDERR, NULL, ELPIS_LOG_ERROR);
    elpis_simd_init();
    elpis_random_init();

    if (elpis_addr_parse(&a, addr, 853) != 0) {
        fprintf(stderr, "%s: not an address\n", addr);
        return 2;
    }
    elpis_addr_str(&a, astr, sizeof astr);
    printf("%s\n", astr);

    t0 = now_ms();
    if (elpis_sock_tcp_connect(&a, NULL, &fd) != ELPIS_OK) {
        printf("  connect: %s\n", strerror(errno));
        return 1;
    }
    {
        struct pollfd pfd;
        int err = 0;
        socklen_t el = sizeof err;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        if (poll(&pfd, 1, TIMEOUT_MS) <= 0) {
            printf("  connect: timed out\n");
            goto out;
        }
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err != 0) {
            printf("  connect: %s\n", strerror(err));
            goto out;
        }
    }
    t1 = now_ms();

    if (elpis_tls_init(&t, alpn, sni) != 0) {
        printf("  init failed\n");
        goto out;
    }
    if (pump(fd, &t, t1 + TIMEOUT_MS, is_open) != 0)
        goto done;
    t2 = now_ms();
    printf("  TCP %.1f ms, TLS %.1f ms  %s  alpn %s\n", t1 - t0, t2 - t1,
           elpis_tls_suite_name(t.suite),
           alpn == NULL ? "not offered" : t.alpn_ok ? "dot" : "none chosen");

    qn = build_query(q, qname, qtype_of(qtype));
    if (elpis_tls_write(&t, q, qn) != 0 ||
        pump(fd, &t, t2 + TIMEOUT_MS, have_answer) != 0)
        goto done;
    t3 = now_ms();
    an = elpis_tls_read(&t, ans, sizeof ans);
    if (an >= 14) {
        unsigned rcode = ans[5] & 0x0f;
        printf("  %s %s: %s, %u answers, %zu bytes, %.1f ms\n", qname, qtype,
               rcode < 6 ? rcodes[rcode] : "rcode?", elpis_get16(ans + 8),
               an - 2, t3 - t2);
        rc = 0;
    }
    elpis_tls_close(&t);
    (void)pump(fd, &t, now_ms() + 500, all_sent);
done:
    /* Data that came but was not a whole DNS answer, e.g. from s_server. */
    if (elpis_tls_pending(&t) > 0) {
        size_t k, m = elpis_tls_read(&t, ans, sizeof ans);
        printf("  %zu bytes of data left: \"", m);
        for (k = 0; k < m && k < 60; k++)
            putchar(ans[k] >= 32 && ans[k] < 127 ? ans[k] : '.');
        printf("\"\n");
    }
    elpis_tls_free(&t);
out:
    close(fd);
    return rc;
}
