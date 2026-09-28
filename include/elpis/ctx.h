/*
 * elpis/ctx.h -- process-wide runtime state shared by every worker.
 */
#ifndef ELPIS_CTX_H
#define ELPIS_CTX_H

#include "elpis/conf.h"
#include "elpis/cache.h"
#include "elpis/deleg.h"
#include "elpis/infra.h"
#include "elpis/store.h"

/* C99 forbids repeating a typedef; both headers need this name. */
#ifndef ELPIS_TA_STORE_TYPEDEF
#define ELPIS_TA_STORE_TYPEDEF
typedef struct elpis_ta_store elpis_ta_store_t;
#endif

typedef struct {
    uint64_t queries, cache_hits, cache_stale, recursions, upstream_queries;
    uint64_t answers, nxdomain, servfail, refused, formerr, timeouts;
    uint64_t tcp_queries, truncated, dnssec_secure, dnssec_insecure;
    uint64_t dnssec_bogus, dns64_synth, prefetches, dropped;
    uint64_t cookie_ok, cookie_bad;
    uint64_t tasks;            /* tasks created, client and internal alike */
    /*
     * Public-key signature verifications.  This is the expensive thing the
     * resolver does -- a rate here is a real measure of what the machine can
     * take, in a way that counting SIMD helpers over forty-byte names is not.
     */
    uint64_t dnssec_verifies;
    /*
     * Queries sent only to measure a server we have never used: raced beside
     * the real one, or probing the rest of a slow delegation.  Bounded by the
     * number of such servers, so a rate that stays high means addresses keep
     * expiring out of the infra cache.
     */
    uint64_t races;
    /* Queries answered SERVFAIL at once because max-pending was reached. */
    uint64_t overload;
    /*
     * Resolutions ended SERVFAIL because every server left to ask in the zone
     * was held down (server-hold-down), rather than asked again.  When the
     * whole zone is held that is at once; otherwise it is after the servers
     * that were not held had their turn.
     */
    uint64_t held;
    /*
     * EDNS Client Subnet: queries sent with a subnet, and answers that came
     * back tailored to it (SCOPE above 0).
     */
    uint64_t ecs_sent, ecs_tailored;
} elpis_stats_t;

/*
 * What the event loops did in the last second, summed over the workers.  Not
 * a counter like the rest -- it is replaced each second, not accumulated --
 * so it lives outside elpis_stats_t, which publish_stats() folds by delta.
 */
/* What the internet sees this resolver as; filled in by selfinfo.c. */
typedef struct {
    char     v4[64];
    char     v6[80];
    char     asn[24];
    char     asname[160];
    uint64_t at_ms;
    /*
     * The same two addresses as bytes, for ecs-ip-type: this, which every
     * worker reads on its send path.  selfinfo.c writes them under `seq`
     * (odd while a write is under way) so no reader takes half of one.
     */
    uint32_t seq;
    uint32_t pub4;          /* network order; valid when have & 1 */
    uint64_t pub6[2];       /* network order; valid when have & 2 */
    uint32_t have;
} elpis_selfinfo_t;

typedef struct {
    uint64_t turns, idle, nosleep;
    uint32_t slowest_ms;
    unsigned timers;
} elpis_loopstat_t;

typedef struct {
    elpis_conf_t        conf;
    elpis_cache_plan_t  plan;

    elpis_cache_t      *mcache;
    elpis_cache_t      *rcache;
    elpis_cache_t      *dcache;
    elpis_cache_t      *infra;

    elpis_deleg_t       root_hints;
    elpis_ta_store_t   *ta;

    elpis_stats_t       stats;
    elpis_loopstat_t    loop;
    elpis_selfinfo_t    self;
    elpis_licence_t     licence;    /* checked once, at startup */
    uint64_t            start_ms;

    volatile int        shutdown;
    volatile int        reload;
} elpis_ctx_t;

extern elpis_ctx_t *elpis_g;      /* set once by main() */

int  elpis_ctx_init(elpis_ctx_t *ctx, const char *conf_path);
void elpis_ctx_fini(elpis_ctx_t *ctx);
void elpis_stats_report(elpis_ctx_t *ctx);

/* Counter bump; safe from any worker. */
void elpis_stat_inc(uint64_t *counter, uint64_t n);

#endif /* ELPIS_CTX_H */
