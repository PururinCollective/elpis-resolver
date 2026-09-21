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
} elpis_stats_t;

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
