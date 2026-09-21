/*
 * infra.c -- per-nameserver state cache.
 */
#include "elpis/infra.h"
#include "elpis/log.h"
#include "elpis/simd.h"

typedef struct {
    elpis_chdr_t hdr;
    elpis_addr_t addr;
    elpis_infra_info_t info;
} ient_t;

typedef struct {
    const elpis_addr_t *addr;
    uint64_t hash;
} ikey_t;

static void ient_free(void *p) { elpis_free(p); }

static int ient_eq(const void *entry, const void *key)
{
    const ient_t *e = (const ient_t *)entry;
    const ikey_t *k = (const ikey_t *)key;
    return elpis_addr_eq(&e->addr, k->addr);
}

static void ikey_init(ikey_t *k, const elpis_addr_t *a)
{
    k->addr = a;
    k->hash = elpis_mix64(elpis_addr_hash(a) ^ 0x9E3779B97F4A7C15ull);
}

elpis_cache_t *elpis_infra_new(uint64_t bytes, unsigned shards)
{
    return elpis_cache_new("infra-cache", bytes, shards, ient_free, ient_eq);
}

/* Entries are kept for an hour of disuse; longer and the RTT is fiction. */
#define INFRA_TTL 3600u

void elpis_infra_get(elpis_cache_t *c, const elpis_addr_t *a,
                     elpis_infra_info_t *out)
{
    ikey_t k;
    unsigned shard;
    ient_t *e;

    memset(out, 0, sizeof *out);
    out->srtt       = ELPIS_RTT_INITIAL;
    out->rttvar     = ELPIS_RTT_INITIAL / 2u;
    out->edns_state = ELPIS_EDNS_UNKNOWN;

    ikey_init(&k, a);
    e = (ient_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e != NULL) {
        *out = e->info;
        elpis_cache_read_end(c, shard);
    }
}

/*
 * Read-modify-write.  The window between the read and the insert can lose a
 * concurrent update; for an RTT estimate that is a non-event, and avoiding a
 * second lock class here keeps the send path free of ordering rules.
 */
static void infra_update(elpis_cache_t *c, const elpis_addr_t *a,
                         void (*fn)(elpis_infra_info_t *, void *), void *ctx)
{
    ikey_t k;
    unsigned shard;
    ient_t *e, *ne;
    elpis_infra_info_t info;

    ikey_init(&k, a);
    e = (ient_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e != NULL) {
        info = e->info;
        elpis_cache_read_end(c, shard);
    } else {
        memset(&info, 0, sizeof info);
        info.srtt       = ELPIS_RTT_INITIAL;
        info.rttvar     = ELPIS_RTT_INITIAL / 2u;
        info.edns_state = ELPIS_EDNS_UNKNOWN;
    }

    fn(&info, ctx);
    info.last_used = elpis_cached_now_s();

    ne = (ient_t *)elpis_malloc(sizeof *ne);
    if (ne == NULL)
        return;
    memset(ne, 0, sizeof *ne);
    ne->hdr.hash   = k.hash;
    ne->hdr.size   = (uint32_t)(sizeof *ne + 64u);
    ne->hdr.ref    = 1;
    ne->hdr.expiry = elpis_cached_now_s() + INFRA_TTL;
    ne->addr       = *a;
    ne->info       = info;
    elpis_cache_insert(c, ne, &k);
}

static void fn_rtt_ok(elpis_infra_info_t *i, void *ctx)
{
    uint32_t rtt = *(uint32_t *)ctx;
    int32_t err;

    if (rtt > ELPIS_RTT_MAX)
        rtt = ELPIS_RTT_MAX;

    if (i->queries == 0) {
        i->srtt   = rtt;
        i->rttvar = rtt / 2u;
    } else {
        /* Jacobson/Karels, as in TCP: srtt += (err >> 3), var += (|err| - var) >> 2 */
        err = (int32_t)rtt - (int32_t)i->srtt;
        i->srtt = (uint32_t)((int32_t)i->srtt + (err >> 3));
        if (err < 0)
            err = -err;
        i->rttvar = (uint32_t)((int32_t)i->rttvar + ((err - (int32_t)i->rttvar) >> 2));
    }
    if (i->srtt > ELPIS_RTT_MAX)
        i->srtt = ELPIS_RTT_MAX;
    i->timeouts = 0;
    i->queries++;
}

void elpis_infra_rtt_ok(elpis_cache_t *c, const elpis_addr_t *a, uint32_t rtt_ms)
{
    infra_update(c, a, fn_rtt_ok, &rtt_ms);
}

static void fn_timeout(elpis_infra_info_t *i, void *ctx)
{
    (void)ctx;
    if (i->timeouts < 1000u)
        i->timeouts++;
    /* Back off exponentially but keep the estimate bounded. */
    i->srtt = i->srtt * 2u;
    if (i->srtt > ELPIS_RTT_MAX)
        i->srtt = ELPIS_RTT_MAX;
    i->queries++;
}

void elpis_infra_timeout(elpis_cache_t *c, const elpis_addr_t *a)
{
    infra_update(c, a, fn_timeout, NULL);
}

typedef struct { uint8_t state; uint16_t maxsize; } edns_arg_t;

static void fn_edns(elpis_infra_info_t *i, void *ctx)
{
    edns_arg_t *e = (edns_arg_t *)ctx;
    i->edns_state = e->state;
    if (e->maxsize != 0)
        i->edns_max = e->maxsize;
}

void elpis_infra_set_edns(elpis_cache_t *c, const elpis_addr_t *a,
                          uint8_t state, uint16_t maxsize)
{
    edns_arg_t arg;
    arg.state   = state;
    arg.maxsize = maxsize;
    infra_update(c, a, fn_edns, &arg);
}

typedef struct { uint8_t flag; int on; } flag_arg_t;

static void fn_flag(elpis_infra_info_t *i, void *ctx)
{
    flag_arg_t *f = (flag_arg_t *)ctx;
    if (f->on)
        i->flags = (uint8_t)(i->flags | f->flag);
    else
        i->flags = (uint8_t)(i->flags & ~f->flag);
}

void elpis_infra_set_flag(elpis_cache_t *c, const elpis_addr_t *a,
                          uint8_t flag, int on)
{
    flag_arg_t arg;
    arg.flag = flag;
    arg.on   = on;
    infra_update(c, a, fn_flag, &arg);
}

typedef struct { const uint8_t *p; size_t n; } cookie_arg_t;

static void fn_cookie(elpis_infra_info_t *i, void *ctx)
{
    cookie_arg_t *a = (cookie_arg_t *)ctx;
    size_t n = a->n;
    if (n > sizeof i->cookie)
        n = sizeof i->cookie;
    memcpy(i->cookie, a->p, n);
    i->cookie_len = (uint8_t)n;
    i->flags = (uint8_t)(i->flags | ELPIS_INF_COOKIE_OK);
}

void elpis_infra_set_cookie(elpis_cache_t *c, const elpis_addr_t *a,
                            const uint8_t *cookie, size_t len)
{
    cookie_arg_t arg;
    arg.p = cookie;
    arg.n = len;
    infra_update(c, a, fn_cookie, &arg);
}

uint32_t elpis_infra_cost(const elpis_infra_info_t *i)
{
    uint32_t cost = i->srtt + i->rttvar;

    if (i->flags & ELPIS_INF_LAME)
        return ELPIS_RTT_BAN;
    if (i->timeouts >= 3)
        return ELPIS_RTT_BAN;
    /* Each recent timeout adds a second of apparent latency. */
    cost += i->timeouts * 1000u;
    if (cost > ELPIS_RTT_BAN)
        cost = ELPIS_RTT_BAN;
    return cost;
}
