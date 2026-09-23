/*
 * stats.c -- counters and the periodic report.
 */
#include "elpis/ctx.h"
#include "elpis/cache.h"
#include "elpis/log.h"
#include "elpis/atomic.h"
#include "elpis/util.h"
#include "elpis/simd.h"

void elpis_stat_inc(uint64_t *counter, uint64_t n)
{
    elpis_atomic_add64(counter, n);
}

static void report_cache(const elpis_cache_t *c)
{
    elpis_cache_stats_t s;
    uint64_t total;

    if (c == NULL)
        return;
    elpis_cache_stats(c, &s);
    total = s.hits + s.misses;
    elpis_info("  %-12s entries=%llu bytes=%lluMiB/%lluMiB hit=%.1f%% "
               "evict=%llu expire=%llu pinned=%llu",
               elpis_cache_name(c),
               (unsigned long long)s.entries,
               (unsigned long long)(s.bytes / (1024 * 1024)),
               (unsigned long long)(s.bytes_max / (1024 * 1024)),
               total ? (double)s.hits * 100.0 / (double)total : 0.0,
               (unsigned long long)s.evictions,
               (unsigned long long)s.expired,
               (unsigned long long)s.pinned_entries);
}

void elpis_stats_report(elpis_ctx_t *ctx)
{
    const elpis_stats_t *s = &ctx->stats;
    uint64_t up = (elpis_now_ms() - ctx->start_ms) / 1000u;
    uint64_t served = s->queries;
    int i;

    elpis_info("statistics after %llus:", (unsigned long long)up);
    elpis_info("  queries=%llu hits=%llu (%.1f%%) stale=%llu recursions=%llu "
               "upstream=%llu raced=%llu",
               (unsigned long long)served,
               (unsigned long long)s->cache_hits,
               served ? (double)s->cache_hits * 100.0 / (double)served : 0.0,
               (unsigned long long)s->cache_stale,
               (unsigned long long)s->recursions,
               (unsigned long long)s->upstream_queries,
               (unsigned long long)s->races);
    elpis_info("  tasks=%llu", (unsigned long long)s->tasks);
    elpis_info("  loop: turns/s=%llu idle=%llu nosleep=%llu timers=%u "
               "slowest-turn=%ums",
               (unsigned long long)ctx->loop.turns,
               (unsigned long long)ctx->loop.idle,
               (unsigned long long)ctx->loop.nosleep,
               ctx->loop.timers, (unsigned)ctx->loop.slowest_ms);
    elpis_info("  nxdomain=%llu servfail=%llu timeouts=%llu tcp=%llu "
               "truncated=%llu dns64=%llu",
               (unsigned long long)s->nxdomain,
               (unsigned long long)s->servfail,
               (unsigned long long)s->timeouts,
               (unsigned long long)s->tcp_queries,
               (unsigned long long)s->truncated,
               (unsigned long long)s->dns64_synth);
    if (s->cookie_ok || s->cookie_bad)
        elpis_info("  cookies verified=%llu rejected=%llu",
                   (unsigned long long)s->cookie_ok,
                   (unsigned long long)s->cookie_bad);
    elpis_info("  dnssec secure=%llu insecure=%llu bogus=%llu",
               (unsigned long long)s->dnssec_secure,
               (unsigned long long)s->dnssec_insecure,
               (unsigned long long)s->dnssec_bogus);
    /*
     * Signature verifications, total and per second of uptime.  This is the
     * costly work, so the rate is the closest thing to "what can this machine
     * take" that the resolver can report about itself while it is running.
     */
    {
        uint64_t secs = up ? up : 1u;
        elpis_info("  dnssec verifies=%llu (%.1f/s over %llus of uptime)",
                   (unsigned long long)s->dnssec_verifies,
                   (double)s->dnssec_verifies / (double)secs,
                   (unsigned long long)secs);
    }

    report_cache(ctx->mcache);
    report_cache(ctx->rcache);
    report_cache(ctx->dcache);
    report_cache(ctx->infra);

    if (elpis_drop_total() > 0) {
        char line[512];
        size_t o = 0;
        line[0] = '\0';
        for (i = 1; i < ELPIS_DROP__MAX; i++) {
            uint64_t n = elpis_drop_count((elpis_drop_t)i);
            int k;
            if (n == 0)
                continue;
            k = snprintf(line + o, sizeof line - o, "%s%s=%llu",
                         o ? " " : "", elpis_drop_name((elpis_drop_t)i),
                         (unsigned long long)n);
            if (k < 0 || (size_t)k >= sizeof line - o)
                break;
            o += (size_t)k;
        }
        elpis_info("  dropped %llu: %s",
                   (unsigned long long)elpis_drop_total(), line);
    }
}
