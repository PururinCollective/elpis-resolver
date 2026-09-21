/*
 * probe.c -- measure and rank the root servers at startup.
 *
 * Server selection is driven by the infrastructure cache's round-trip
 * estimates, and until a server has actually been queried that estimate is a
 * guess (ELPIS_RTT_INITIAL).  On a cold cache that means the first handful of
 * recursions pick roots effectively at random, and on a host with broken IPv6
 * every other pick burns a full timeout.
 *
 * So before serving gets interesting, ask all twenty-six root addresses the
 * same small question a few times and record what comes back.  The result
 * seeds the infra cache, so the very first real query already goes to a
 * server known to be close.
 *
 * The probe is a real DNS query rather than an ICMP ping: it measures the
 * path that will actually be used, including any middlebox that drops UDP/53,
 * and a server that answers ICMP but not DNS is worse than useless.
 */
#include "elpis/ctx.h"
#include "elpis/deleg.h"
#include "elpis/infra.h"
#include "elpis/sock.h"
#include "elpis/msg.h"
#include "elpis/crypto.h"
#include "elpis/log.h"
#include "elpis/resolver.h"

#include <errno.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#define PROBE_MAX      (ELPIS_DELEG_MAX_NS * 2)
#define PROBE_WAIT_MS  1500
#define PROBE_GAP_MS   250          /* spacing between rounds */

typedef struct {
    elpis_addr_t addr;
    char         name[64];
    int          family;
    uint16_t     txid;
    uint64_t     sent_ms;
    uint32_t     best_ms;
    uint32_t     last_ms;
    unsigned     sent;
    unsigned     replies;
    unsigned     outstanding;
} target_t;

/* ------------------------------------------------------------------ */

static size_t build_probe(uint8_t *buf, size_t cap, uint16_t id)
{
    elpis_bld_t b;
    elpis_cslot_t ctab[4];
    elpis_name_t root;

    elpis_name_init_root(&root);
    elpis_bld_init(&b, buf, cap, ctab, 1);
    /*
     * "SOA ." with RD clear: the smallest question every root answers
     * authoritatively, and one whose reply fits comfortably in a datagram.
     */
    if (elpis_bld_header(&b, id, 0) != ELPIS_OK)
        return 0;
    if (elpis_bld_question(&b, &root, ELPIS_T_SOA, ELPIS_CLASS_IN) != ELPIS_OK)
        return 0;
    elpis_bld_finish(&b);
    return b.overflow ? 0 : b.len;
}

static unsigned collect_targets(target_t *t, unsigned max)
{
    elpis_deleg_t d;
    unsigned n = 0, i, j;

    elpis_root_delegation(&d);
    for (i = 0; i < d.nns && n < max; i++) {
        char nb[ELPIS_MAX_NAME * 4];
        elpis_name_str(&d.ns[i].name, nb, sizeof nb);

        for (j = 0; j < d.ns[i].n4 && n < max; j++) {
            memset(&t[n], 0, sizeof t[n]);
            elpis_addr_from4(&t[n].addr, d.ns[i].a4[j], 53);
            elpis_strlcpy(t[n].name, nb, sizeof t[n].name);
            t[n].family = AF_INET;
            t[n].best_ms = 0xFFFFFFFFu;
            n++;
        }
        for (j = 0; j < d.ns[i].n6 && n < max; j++) {
            memset(&t[n], 0, sizeof t[n]);
            elpis_addr_from6(&t[n].addr, d.ns[i].a6[j], 53);
            elpis_strlcpy(t[n].name, nb, sizeof t[n].name);
            t[n].family = AF_INET6;
            t[n].best_ms = 0xFFFFFFFFu;
            n++;
        }
    }
    return n;
}

/* One round: send to every target, then gather whatever answers in time. */
static void probe_round(target_t *t, unsigned n, int fd4, int fd6)
{
    uint8_t buf[512];
    uint64_t deadline;
    unsigned i;

    for (i = 0; i < n; i++) {
        int fd = (t[i].family == AF_INET) ? fd4 : fd6;
        size_t len;

        t[i].outstanding = 0;
        if (fd < 0)
            continue;
        t[i].txid = (uint16_t)elpis_random_u32();
        len = build_probe(buf, sizeof buf, t[i].txid);
        if (len == 0)
            continue;
        if (elpis_sock_send(fd, buf, len, &t[i].addr, NULL) == (ssize_t)len) {
            t[i].sent_ms = elpis_now_ms();
            t[i].sent++;
            t[i].outstanding = 1;
        }
    }

    deadline = elpis_now_ms() + PROBE_WAIT_MS;
    for (;;) {
        struct pollfd p[2];
        int np = 0, i4 = -1, i6 = -1, r;
        int64_t remain = (int64_t)deadline - (int64_t)elpis_now_ms();

        if (remain <= 0)
            break;
        if (fd4 >= 0) { p[np].fd = fd4; p[np].events = POLLIN; p[np].revents = 0; i4 = np++; }
        if (fd6 >= 0) { p[np].fd = fd6; p[np].events = POLLIN; p[np].revents = 0; i6 = np++; }
        if (np == 0)
            break;

        r = poll(p, (nfds_t)np, (int)remain);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (r == 0)
            break;

        {
            int k;
            for (k = 0; k < np; k++) {
                int fd = p[k].fd;
                if (!(p[k].revents & POLLIN))
                    continue;
                for (;;) {
                    elpis_addr_t from;
                    uint8_t rx[1024];
                    ssize_t got;
                    elpis_hdr_t h;
                    uint64_t now;

                    memset(&from, 0, sizeof from);
                    got = elpis_sock_recv(fd, rx, sizeof rx, &from, NULL);
                    if (got < 0)
                        break;
                    if (got < ELPIS_HDR_LEN)
                        continue;
                    if (elpis_hdr_parse(&h, rx, (size_t)got) != ELPIS_OK)
                        continue;
                    if (!(h.flags & ELPIS_FLAG_QR))
                        continue;

                    now = elpis_now_ms();
                    for (i = 0; i < n; i++) {
                        uint32_t rtt;
                        if (!t[i].outstanding || t[i].txid != h.id)
                            continue;
                        if (!elpis_addr_eq(&t[i].addr, &from))
                            continue;
                        rtt = (uint32_t)(now - t[i].sent_ms);
                        t[i].last_ms = rtt;
                        if (rtt < t[i].best_ms)
                            t[i].best_ms = rtt;
                        t[i].replies++;
                        t[i].outstanding = 0;
                        break;
                    }
                }
            }
        }
        (void)i4; (void)i6;
    }
}

/* ------------------------------------------------------------------ */

static int cmp_target(const void *a, const void *b)
{
    const target_t *x = (const target_t *)a;
    const target_t *y = (const target_t *)b;

    if (x->replies == 0 && y->replies == 0) return 0;
    if (x->replies == 0) return 1;         /* unreachable sorts last */
    if (y->replies == 0) return -1;
    if (x->best_ms != y->best_ms)
        return x->best_ms < y->best_ms ? -1 : 1;
    return 0;
}

int elpis_probe_roots(elpis_ctx_t *ctx)
{
    static target_t t[PROBE_MAX];
    unsigned n, i, rounds;
    int fd4 = -1, fd6 = -1;
    unsigned ok4 = 0, ok6 = 0, tried4 = 0, tried6 = 0;
    const elpis_conf_t *c = &ctx->conf;

    if (!c->probe_roots)
        return ELPIS_OK;

    n = collect_targets(t, PROBE_MAX);
    if (n == 0)
        return ELPIS_ERR;

    if (c->do_ipv4 &&
        elpis_sock_udp_client(AF_INET, c->have_src4 ? &c->out_src4 : NULL,
                              c->port_lo, c->port_hi, &fd4) != ELPIS_OK)
        fd4 = -1;
    if (c->do_ipv6 &&
        elpis_sock_udp_client(AF_INET6, c->have_src6 ? &c->out_src6 : NULL,
                              c->port_lo, c->port_hi, &fd6) != ELPIS_OK)
        fd6 = -1;

    if (fd4 < 0 && fd6 < 0) {
        elpis_warn("root probe: no usable outbound socket");
        return ELPIS_ERR;
    }

    rounds = c->probe_rounds ? c->probe_rounds : 3u;
    if (rounds > 10)
        rounds = 10;

    for (i = 0; i < rounds; i++) {
        if (ctx->shutdown)
            break;
        probe_round(t, n, fd4, fd6);
        if (i + 1 < rounds) {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = (long)PROBE_GAP_MS * 1000000L;
            nanosleep(&ts, NULL);
        }
    }

    if (fd4 >= 0) close(fd4);
    if (fd6 >= 0) close(fd6);

    /*
     * Feed the results in.  A server that answered gets its measured time; one
     * that never did gets a timeout recorded, which the cost function already
     * knows how to deprioritise.
     */
    for (i = 0; i < n; i++) {
        if (t[i].family == AF_INET) tried4++; else tried6++;
        if (t[i].replies > 0) {
            unsigned k;
            /* Repeat the measurement so the smoothed estimate settles on it
             * rather than on the 376 ms default it starts from. */
            for (k = 0; k < 3; k++)
                elpis_infra_rtt_ok(ctx->infra, &t[i].addr, t[i].best_ms);
            if (t[i].family == AF_INET) ok4++; else ok6++;
        } else if (t[i].sent > 0) {
            elpis_infra_timeout(ctx->infra, &t[i].addr);
        }
    }

    qsort(t, n, sizeof t[0], cmp_target);

    elpis_info("root probe: %u of %u addresses answered "
               "(IPv4 %u/%u, IPv6 %u/%u), %u round%s",
               ok4 + ok6, n, ok4, tried4, ok6, tried6,
               rounds, rounds == 1 ? "" : "s");
    for (i = 0; i < n; i++) {
        char ab[80];
        if (t[i].replies == 0)
            continue;
        elpis_info("  %2u. %-22s %-30s %4u ms  (%u/%u)",
                   i + 1, t[i].name,
                   elpis_addr_str(&t[i].addr, ab, sizeof ab),
                   t[i].best_ms, t[i].replies, t[i].sent);
    }
    for (i = 0; i < n; i++) {
        char ab[80];
        if (t[i].replies != 0 || t[i].sent == 0)
            continue;
        elpis_info("   -- %-22s %-30s unreachable", t[i].name,
                   elpis_addr_str(&t[i].addr, ab, sizeof ab));
    }

    /*
     * If every IPv6 root is silent while IPv4 works, this host has no working
     * IPv6 path.  Leaving it enabled means half of every server selection is
     * spent waiting for a timeout, so turn it off for this run and say so
     * plainly -- the operator can override it in the config if the probe was
     * wrong about a transient outage.
     */
    if (tried6 > 0 && ok6 == 0 && ok4 > 0) {
        ctx->conf.do_ipv6 = 0;
        elpis_warn("root probe: no IPv6 root server answered while IPv4 works; "
                   "disabling outbound IPv6 for this run "
                   "(set 'do-ipv6: yes' and restart to force it back on)");
    } else if (tried4 > 0 && ok4 == 0 && ok6 > 0) {
        ctx->conf.do_ipv4 = 0;
        elpis_warn("root probe: no IPv4 root server answered while IPv6 works; "
                   "disabling outbound IPv4 for this run");
    } else if (ok4 + ok6 == 0) {
        elpis_error("root probe: nothing answered on either family -- "
                    "outbound DNS appears to be blocked");
    }

    return ELPIS_OK;
}
