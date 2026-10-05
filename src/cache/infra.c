/*
 * infra.c -- per-nameserver state cache.
 */
#include "elpis/infra.h"
#include "elpis/dns.h"
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

static void info_defaults(elpis_infra_info_t *i)
{
    memset(i, 0, sizeof *i);
    i->srtt       = ELPIS_RTT_INITIAL;
    i->rttvar     = ELPIS_RTT_INITIAL / 2u;
    i->edns_state = ELPIS_EDNS_UNKNOWN;
}

/*
 * An entry can outlive the hour for its DoT state alone (dot_keep): a server
 * that failed DoT has to stay failed between its hourly tests, and one that
 * gave up has to stay given up.  Everything else in it is as stale as it
 * ever was by then, so it starts over and only the DoT fields carry on.
 */
static void freshen(elpis_infra_info_t *i, uint32_t now)
{
    elpis_infra_info_t keep;

    if (i->last_used == 0 || now < i->last_used + INFRA_TTL)
        return;
    keep = *i;
    info_defaults(i);
    i->dot_state = keep.dot_state;
    i->dot_tries = keep.dot_tries;
    i->dot_until = keep.dot_until;
    i->dot_keep  = keep.dot_keep;
    i->last_used = keep.last_used;
}

void elpis_infra_get(elpis_cache_t *c, const elpis_addr_t *a,
                     elpis_infra_info_t *out)
{
    ikey_t k;
    unsigned shard;
    ient_t *e;

    info_defaults(out);

    ikey_init(&k, a);
    e = (ient_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e != NULL) {
        *out = e->info;
        elpis_cache_read_end(c, shard);
        freshen(out, elpis_cached_now_s());
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

    uint32_t now = elpis_cached_now_s(), expiry;

    ikey_init(&k, a);
    e = (ient_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e != NULL) {
        info = e->info;
        elpis_cache_read_end(c, shard);
        freshen(&info, now);
    } else {
        info_defaults(&info);
    }

    fn(&info, ctx);
    info.last_used = now;
    expiry = now + INFRA_TTL;
    if (info.dot_state != ELPIS_DOT_UNKNOWN && info.dot_keep > expiry)
        expiry = info.dot_keep;

    ne = (ient_t *)elpis_malloc(sizeof *ne);
    if (ne == NULL)
        return;
    memset(ne, 0, sizeof *ne);
    ne->hdr.hash   = k.hash;
    ne->hdr.size   = (uint32_t)(sizeof *ne + 64u);
    ne->hdr.ref    = 1;
    ne->hdr.expiry = expiry;
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
    i->silent_types = 0;
    i->silent_since = 0;
    i->hold_until   = 0;
    i->queries++;
}

void elpis_infra_rtt_ok(elpis_cache_t *c, const elpis_addr_t *a, uint32_t rtt_ms)
{
    infra_update(c, a, fn_rtt_ok, &rtt_ms);
}

typedef struct {
    uint16_t qtype;
    uint32_t now;
    uint32_t hold_s;
    int      held;          /* out: this timeout set the hold */
} timeout_arg_t;

static void fn_timeout(elpis_infra_info_t *i, void *ctx)
{
    timeout_arg_t *t = (timeout_arg_t *)ctx;

    if (i->timeouts == 0 || i->silent_since == 0)
        i->silent_since = t->now ? t->now : 1u;
    if (i->timeouts < 1000u)
        i->timeouts++;
    i->silent_types = (uint8_t)(i->silent_types | elpis_infra_qclass(t->qtype));
    /* Back off exponentially but keep the estimate bounded. */
    i->srtt = i->srtt * 2u;
    if (i->srtt > ELPIS_RTT_MAX)
        i->srtt = ELPIS_RTT_MAX;
    i->queries++;
    /*
     * Both conditions, not either.  A burst of queries in flight when a path
     * blips can time out three at a time; and a server asked once a minute
     * can be silent for ten seconds without having missed anything.
     */
    if (t->hold_s != 0 && i->timeouts >= ELPIS_HOLD_AFTER &&
        t->now >= i->silent_since + ELPIS_HOLD_SILENT_S) {
        i->hold_until = t->now + t->hold_s;
        t->held = 1;
    }
}

int elpis_infra_timeout(elpis_cache_t *c, const elpis_addr_t *a,
                        uint16_t qtype, uint32_t now, uint32_t hold_s)
{
    timeout_arg_t arg;
    arg.qtype  = qtype;
    arg.now    = now;
    arg.hold_s = hold_s;
    arg.held   = 0;
    infra_update(c, a, fn_timeout, &arg);
    return arg.held;
}

unsigned elpis_infra_qclass(uint16_t qtype)
{
    switch (qtype) {
    case ELPIS_T_A:     return ELPIS_QC_A;
    case ELPIS_T_AAAA:  return ELPIS_QC_AAAA;
    case ELPIS_T_HTTPS:
    case ELPIS_T_SVCB:  return ELPIS_QC_SVCB;
    default:            return ELPIS_QC_OTHER;
    }
}

int elpis_infra_held(const elpis_infra_info_t *i, uint16_t qtype, uint32_t now)
{
    return i->hold_until != 0 && now < i->hold_until &&
           (i->silent_types & elpis_infra_qclass(qtype)) != 0;
}

int elpis_infra_probe_due(const elpis_infra_info_t *i, uint16_t qtype,
                          uint32_t now)
{
    return i->hold_until != 0 && now >= i->hold_until &&
           (i->silent_types & elpis_infra_qclass(qtype)) != 0;
}

static void fn_hold(elpis_infra_info_t *i, void *ctx)
{
    uint32_t until = *(const uint32_t *)ctx;
    /* An answer may have landed since the caller looked. */
    if (i->hold_until != 0)
        i->hold_until = until;
}

void elpis_infra_hold(elpis_cache_t *c, const elpis_addr_t *a, uint32_t until)
{
    infra_update(c, a, fn_hold, &until);
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

static void fn_ecs_off(elpis_infra_info_t *i, void *ctx)
{
    i->ecs_off_until = *(const uint32_t *)ctx;
}

void elpis_infra_ecs_off(elpis_cache_t *c, const elpis_addr_t *a, uint32_t until)
{
    infra_update(c, a, fn_ecs_off, &until);
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

/* ------------------------------------------------------------------ */
/* DNS over TLS                                                        */
/* ------------------------------------------------------------------ */

int elpis_infra_dot_mode(const elpis_infra_info_t *i, uint32_t now)
{
    int claimed = i->dot_claim != 0 && now < i->dot_claim;

    switch (i->dot_state) {
    case ELPIS_DOT_AVAILABLE:
        if (now < i->dot_until)
            return ELPIS_DOTM_USE;
        return claimed ? ELPIS_DOTM_PLAIN : ELPIS_DOTM_TEST;
    case ELPIS_DOT_FAILED:
        if (now < i->dot_until || claimed)
            return ELPIS_DOTM_PLAIN;
        return ELPIS_DOTM_TEST;
    case ELPIS_DOT_UNAVAILABLE:
        return ELPIS_DOTM_PLAIN;
    default:
        return claimed ? ELPIS_DOTM_PLAIN : ELPIS_DOTM_TEST;
    }
}

typedef struct { uint32_t now; int got; } claim_arg_t;

static void fn_dot_claim(elpis_infra_info_t *i, void *ctx)
{
    claim_arg_t *a = (claim_arg_t *)ctx;
    if (i->dot_claim != 0 && a->now < i->dot_claim)
        return;
    i->dot_claim = a->now + ELPIS_DOT_CLAIM_S;
    a->got = 1;
}

int elpis_infra_dot_claim(elpis_cache_t *c, const elpis_addr_t *a, uint32_t now)
{
    claim_arg_t arg;
    arg.now = now;
    arg.got = 0;
    infra_update(c, a, fn_dot_claim, &arg);
    return arg.got;
}

typedef struct {
    uint32_t now, ttl_s, retry_s, max_try;
    int      state;
} dot_arg_t;

static void fn_dot_ok(elpis_infra_info_t *i, void *ctx)
{
    dot_arg_t *a = (dot_arg_t *)ctx;
    i->dot_state = ELPIS_DOT_AVAILABLE;
    i->dot_tries = 0;
    i->dot_until = a->now + a->ttl_s;
    i->dot_claim = 0;
    i->dot_keep  = i->dot_until;
}

void elpis_infra_dot_ok(elpis_cache_t *c, const elpis_addr_t *a, uint32_t now,
                        uint32_t ttl_s)
{
    dot_arg_t arg;
    memset(&arg, 0, sizeof arg);
    arg.now   = now;
    arg.ttl_s = ttl_s;
    infra_update(c, a, fn_dot_ok, &arg);
}

static void fn_dot_fail(elpis_infra_info_t *i, void *ctx)
{
    dot_arg_t *a = (dot_arg_t *)ctx;

    if (i->dot_tries < 255)
        i->dot_tries++;
    i->dot_claim = 0;
    /* The first failure, then max_try retries an interval apart. */
    if (a->max_try != 0 && i->dot_tries > a->max_try) {
        i->dot_state = ELPIS_DOT_UNAVAILABLE;
        i->dot_until = 0;
        i->dot_keep  = a->now + ELPIS_DOT_GIVE_UP_KEEP_S;
    } else {
        i->dot_state = ELPIS_DOT_FAILED;
        i->dot_until = a->now + a->retry_s;
        /* A day past the next test, so a server asked now and then still
         * counts its retries rather than starting over. */
        i->dot_keep  = i->dot_until + 86400u;
    }
    a->state = i->dot_state;
}

int elpis_infra_dot_fail(elpis_cache_t *c, const elpis_addr_t *a,
                         uint32_t now, uint32_t retry_s, uint32_t max_try)
{
    dot_arg_t arg;
    memset(&arg, 0, sizeof arg);
    arg.now     = now;
    arg.retry_s = retry_s;
    arg.max_try = max_try;
    infra_update(c, a, fn_dot_fail, &arg);
    return arg.state;
}
