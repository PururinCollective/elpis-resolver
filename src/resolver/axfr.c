/*
 * axfr.c -- root zone transfer.
 *
 * ICANN publishes the root zone by AXFR from xfr.dns.icann.org (and a few
 * mirrors).  Pulling it once at startup turns "resolve anything under .com"
 * into a single cache lookup from the very first query, instead of learning
 * each TLD delegation the slow way.  Roughly 1,500 delegations arrive in one
 * transfer of a couple of megabytes.
 *
 * This runs on its own thread with blocking I/O and hard timeouts.  It is a
 * bulk, once-per-day operation, and threading it through the event loop would
 * add a lot of state for no benefit.  A failure is not fatal: the resolver
 * simply learns the TLDs from referrals as it goes.
 */
#include "elpis/ctx.h"
#include "elpis/resolver.h"
#include "elpis/sock.h"
#include "elpis/msg.h"
#include "elpis/rdata.h"
#include "elpis/deleg.h"
#include "elpis/crypto.h"
#include "elpis/simd.h"
#include "elpis/log.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>

#define AXFR_TIMEOUT_MS  30000
#define AXFR_MAX_BYTES   (64u * 1024u * 1024u)
#define GLUE_BUCKETS     16384u

/* ------------------------------------------------------------------ */
/* Collected data                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    elpis_name_t zone;
    elpis_name_t ns;
} nspair_t;

typedef struct {
    elpis_name_t name;
    uint8_t      family;
    uint8_t      ip[16];
    int32_t      next;          /* hash chain */
} glue_t;

typedef struct {
    nspair_t *ns;
    size_t    nns, cns;
    glue_t   *glue;
    size_t    nglue, cglue;
    int32_t  *bucket;
    uint32_t  soa_serial;
    unsigned  tlds;
} zone_acc_t;

static int acc_init(zone_acc_t *a)
{
    size_t i;
    memset(a, 0, sizeof *a);
    a->bucket = (int32_t *)elpis_malloc(GLUE_BUCKETS * sizeof(int32_t));
    if (a->bucket == NULL)
        return ELPIS_ENOMEM;
    for (i = 0; i < GLUE_BUCKETS; i++)
        a->bucket[i] = -1;
    return ELPIS_OK;
}

static void acc_free(zone_acc_t *a)
{
    elpis_free(a->ns);
    elpis_free(a->glue);
    elpis_free(a->bucket);
    memset(a, 0, sizeof *a);
}

static int acc_add_ns(zone_acc_t *a, const elpis_name_t *zone,
                      const elpis_name_t *ns)
{
    if (a->nns == a->cns) {
        size_t want = a->cns ? a->cns * 2u : 4096u;
        nspair_t *p = (nspair_t *)elpis_realloc(a->ns, want * sizeof *p);
        if (p == NULL)
            return ELPIS_ENOMEM;
        a->ns = p;
        a->cns = want;
    }
    a->ns[a->nns].zone = *zone;
    a->ns[a->nns].ns   = *ns;
    a->nns++;
    return ELPIS_OK;
}

static int acc_add_glue(zone_acc_t *a, const elpis_name_t *name, int family,
                        const uint8_t *ip)
{
    uint64_t h;
    unsigned b;

    if (a->nglue == a->cglue) {
        size_t want = a->cglue ? a->cglue * 2u : 8192u;
        glue_t *p = (glue_t *)elpis_realloc(a->glue, want * sizeof *p);
        if (p == NULL)
            return ELPIS_ENOMEM;
        a->glue = p;
        a->cglue = want;
    }
    h = elpis_name_hash(name);
    b = (unsigned)(h & (GLUE_BUCKETS - 1u));

    a->glue[a->nglue].name   = *name;
    a->glue[a->nglue].family = (uint8_t)family;
    memcpy(a->glue[a->nglue].ip, ip, family == AF_INET ? 4u : 16u);
    a->glue[a->nglue].next   = a->bucket[b];
    a->bucket[b] = (int32_t)a->nglue;
    a->nglue++;
    return ELPIS_OK;
}

static void acc_attach_glue(const zone_acc_t *a, elpis_deleg_t *d,
                            const elpis_name_t *ns)
{
    uint64_t h = elpis_name_hash(ns);
    unsigned b = (unsigned)(h & (GLUE_BUCKETS - 1u));
    int32_t i;

    for (i = a->bucket[b]; i >= 0; i = a->glue[i].next) {
        if (!elpis_name_eq(&a->glue[i].name, ns))
            continue;
        elpis_deleg_add_addr(d, ns, a->glue[i].ip,
                             a->glue[i].family == AF_INET ? AF_INET : AF_INET6,
                             ELPIS_NSF_GLUE);
    }
}

/* ------------------------------------------------------------------ */
/* Transfer                                                            */
/* ------------------------------------------------------------------ */

static int io_wait(int fd, int want_write, int timeout_ms)
{
    struct pollfd p;
    int r;

    p.fd = fd;
    p.events = (short)(want_write ? POLLOUT : POLLIN);
    p.revents = 0;
    do {
        r = poll(&p, 1, timeout_ms);
    } while (r < 0 && errno == EINTR);
    return r > 0 ? ELPIS_OK : ELPIS_ETIMEOUT;
}

static int read_full(int fd, uint8_t *buf, size_t n, int timeout_ms)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r;
        if (io_wait(fd, 0, timeout_ms) != ELPIS_OK)
            return ELPIS_ETIMEOUT;
        r = read(fd, buf + got, n - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0)
            return ELPIS_ERR;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

static int write_full(int fd, const uint8_t *buf, size_t n, int timeout_ms)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t r;
        if (io_wait(fd, 1, timeout_ms) != ELPIS_OK)
            return ELPIS_ETIMEOUT;
        r = write(fd, buf + sent, n - sent);
        if (r > 0) { sent += (size_t)r; continue; }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

static int scan_message(zone_acc_t *acc, const uint8_t *wire, size_t len,
                        int *saw_soa)
{
    elpis_msg_t m;
    elpis_rr_iter_t it;
    elpis_rr_t rr;
    int drop = 0;

    if (elpis_msg_parse(&m, wire, len, ELPIS_PARSE_RESPONSE, &drop) != ELPIS_OK) {
        elpis_warn("root AXFR: malformed message (%s)",
                   elpis_drop_name((elpis_drop_t)drop));
        return ELPIS_EFORMAT;
    }
    if (elpis_msg_rcode(&m) != ELPIS_RC_NOERROR) {
        elpis_warn("root AXFR refused: %s", elpis_rcode_name(elpis_msg_rcode(&m)));
        return ELPIS_EREFUSED;
    }

    elpis_rr_iter(&it, &m, ELPIS_SEC_ANSWER);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        elpis_name_t owner = rr.name;
        elpis_name_lower(&owner);

        if (rr.klass != ELPIS_CLASS_IN)
            continue;

        if (rr.type == ELPIS_T_SOA && owner.len == 1) {
            uint8_t rd[1024];
            size_t rdlen;
            (*saw_soa)++;
            if (elpis_rdata_canonical(ELPIS_T_SOA, m.wire, m.len, rr.rdoff,
                                      rr.rdlen, rd, sizeof rd, &rdlen, 0) == ELPIS_OK &&
                rdlen >= 20)
                acc->soa_serial = elpis_get32(rd + rdlen - 20);
            continue;
        }

        /* TLD delegations: NS records exactly one label below the root. */
        if (rr.type == ELPIS_T_NS && owner.labels == 1) {
            uint8_t rd[ELPIS_MAX_NAME + 8];
            size_t rdlen;
            elpis_name_t target;
            if (elpis_rdata_canonical(ELPIS_T_NS, m.wire, m.len, rr.rdoff,
                                      rr.rdlen, rd, sizeof rd, &rdlen, 0) != ELPIS_OK)
                continue;
            if (elpis_rdata_target(ELPIS_T_NS, rd, rdlen, &target) != ELPIS_OK)
                continue;
            elpis_name_lower(&target);
            acc_add_ns(acc, &owner, &target);
            continue;
        }

        if (rr.type == ELPIS_T_A && rr.rdlen == 4) {
            acc_add_glue(acc, &owner, AF_INET, m.wire + rr.rdoff);
            continue;
        }
        if (rr.type == ELPIS_T_AAAA && rr.rdlen == 16) {
            acc_add_glue(acc, &owner, AF_INET6, m.wire + rr.rdoff);
            continue;
        }
    }
    return ELPIS_OK;
}

static int axfr_from(elpis_ctx_t *ctx, const elpis_addr_t *server,
                     zone_acc_t *acc)
{
    int fd = -1;
    uint8_t qbuf[512];
    elpis_bld_t b;
    elpis_cslot_t ctab[8];
    elpis_name_t root;
    size_t total = 0;
    int saw_soa = 0;
    int rc = ELPIS_ERR;
    uint8_t *msg = NULL;
    size_t msgcap = 0;
    char ab[80];

    elpis_addr_str(server, ab, sizeof ab);

    if (elpis_sock_tcp_connect(server, NULL, &fd) != ELPIS_OK) {
        elpis_warn("root AXFR: cannot connect to %s: %s", ab, strerror(errno));
        return ELPIS_ERR;
    }
    if (io_wait(fd, 1, AXFR_TIMEOUT_MS) != ELPIS_OK) {
        elpis_warn("root AXFR: connect to %s timed out", ab);
        goto out;
    }
    {
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            elpis_warn("root AXFR: connect to %s failed: %s", ab, strerror(err));
            goto out;
        }
    }

    elpis_name_init_root(&root);
    elpis_bld_init(&b, qbuf + 2, sizeof qbuf - 2, ctab, 1);
    elpis_bld_header(&b, (uint16_t)elpis_random_u32(), 0);
    elpis_bld_question(&b, &root, ELPIS_T_AXFR, ELPIS_CLASS_IN);
    elpis_bld_finish(&b);
    elpis_put16(qbuf, (uint16_t)b.len);

    if (write_full(fd, qbuf, b.len + 2u, AXFR_TIMEOUT_MS) != ELPIS_OK) {
        elpis_warn("root AXFR: send to %s failed", ab);
        goto out;
    }

    for (;;) {
        uint8_t hdr[2];
        size_t want;

        if (read_full(fd, hdr, 2, AXFR_TIMEOUT_MS) != ELPIS_OK)
            break;
        want = elpis_get16(hdr);
        if (want < ELPIS_HDR_LEN)
            break;
        if (want > msgcap) {
            uint8_t *nb = (uint8_t *)elpis_realloc(msg, want);
            if (nb == NULL)
                goto out;
            msg = nb;
            msgcap = want;
        }
        if (read_full(fd, msg, want, AXFR_TIMEOUT_MS) != ELPIS_OK)
            break;

        total += want;
        if (total > AXFR_MAX_BYTES) {
            elpis_warn("root AXFR from %s exceeded %u MiB; aborting", ab,
                       (unsigned)(AXFR_MAX_BYTES / (1024 * 1024)));
            goto out;
        }

        if (scan_message(acc, msg, want, &saw_soa) != ELPIS_OK)
            goto out;

        /* The transfer ends with a second copy of the SOA. */
        if (saw_soa >= 2) {
            rc = ELPIS_OK;
            break;
        }
    }

    if (rc != ELPIS_OK)
        elpis_warn("root AXFR from %s ended early (%zu bytes, %d SOA)",
                   ab, total, saw_soa);
    else
        elpis_info("root AXFR from %s: %zu bytes, serial %lu", ab, total,
                   (unsigned long)acc->soa_serial);

out:
    if (fd >= 0)
        close(fd);
    elpis_free(msg);
    (void)ctx;
    return rc;
}

/* ------------------------------------------------------------------ */
/* Install                                                             */
/* ------------------------------------------------------------------ */

static unsigned install(elpis_ctx_t *ctx, zone_acc_t *acc)
{
    size_t i, j;
    unsigned zones = 0;
    uint8_t *done;

    if (acc->nns == 0)
        return 0;
    done = (uint8_t *)elpis_calloc(acc->nns, 1);
    if (done == NULL)
        return 0;

    for (i = 0; i < acc->nns; i++) {
        elpis_deleg_t d;

        if (done[i])
            continue;
        memset(&d, 0, sizeof d);
        d.zone     = acc->ns[i].zone;
        d.sec      = ELPIS_SEC_UNCHECKED;
        d.ds_state = ELPIS_DS_UNKNOWN;
        d.pinned   = 1;
        d.ttl      = 172800;             /* the root publishes 2 days */

        for (j = i; j < acc->nns; j++) {
            if (done[j] || !elpis_name_eq(&acc->ns[j].zone, &d.zone))
                continue;
            done[j] = 1;
            elpis_deleg_add_ns(&d, &acc->ns[j].ns);
            acc_attach_glue(acc, &d, &acc->ns[j].ns);
        }

        /*
         * Pin only delegations that came with usable glue.  A TLD whose
         * nameservers all live outside it (rare, but it happens) still has to
         * be resolved the ordinary way.
         */
        if (elpis_deleg_addr_count(&d) > 0) {
            elpis_dcache_put(ctx->dcache, &d, d.ttl, 1);
            zones++;
        }
    }

    elpis_free(done);
    acc->tlds = zones;
    return zones;
}

int elpis_axfr_root(elpis_ctx_t *ctx)
{
    zone_acc_t acc;
    unsigned i;
    int rc = ELPIS_ERR;

    if (!ctx->conf.root_zone_transfer || ctx->conf.n_root_xfr == 0)
        return ELPIS_OK;

    if (acc_init(&acc) != ELPIS_OK)
        return ELPIS_ENOMEM;

    for (i = 0; i < ctx->conf.n_root_xfr; i++) {
        if (axfr_from(ctx, &ctx->conf.root_xfr_addr[i], &acc) == ELPIS_OK) {
            rc = ELPIS_OK;
            break;
        }
        /* Start clean before trying the next mirror. */
        acc_free(&acc);
        if (acc_init(&acc) != ELPIS_OK)
            return ELPIS_ENOMEM;
    }

    if (rc == ELPIS_OK) {
        unsigned n = install(ctx, &acc);
        elpis_info("root zone: %u TLD delegations pinned in cache "
                   "(%zu NS records, %zu glue addresses)",
                   n, acc.nns, acc.nglue);
    }

    acc_free(&acc);
    return rc;
}
