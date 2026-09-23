/*
 * main.c -- process setup, worker threads, signals.
 *
 * Model: N worker threads, each with its own event loop and its own listening
 * sockets opened with SO_REUSEPORT so the kernel spreads incoming datagrams
 * across them.  The caches are shared and internally sharded; nothing else is.
 */
#include "elpis/ctx.h"
#include "elpis/resolver.h"
#include "elpis/sock.h"
#include "elpis/edns.h"
#include "elpis/crypto.h"
#include "elpis/dnssec.h"
#include "elpis/conflict.h"
#include "elpis/simd.h"
#include "elpis/util.h"
#include "elpis/log.h"
#include "elpis/webui.h"

#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>

elpis_ctx_t *elpis_g;

/* ================================================================== */
/* Context                                                             */
/* ================================================================== */

/*
 * edns-buffer-size: auto.  Offer each family the largest payload one packet
 * carries on the route this host would take to the roots, capped at 1400.
 *
 * Only the host's own route is visible from here.  A narrower link further
 * along -- a router's PPPoE uplink, a tunnel on another box -- cannot be seen
 * until something is too big for it, which is what the cap is for: 1400 fits
 * a 1500-byte link less PPPoE or a typical tunnel header.  Where the route
 * cannot be read at all, the family gets the size that fits any path.
 */
static void resolve_edns_auto(elpis_conf_t *c)
{
    static const struct { int family; const char *name, *dst; } fam[2] = {
        { AF_INET,  "IPv4", "198.41.0.4@53" },
        { AF_INET6, "IPv6", "[2001:503:ba3e::2:30]@53" },
    };
    char say[2][96];
    unsigned i, lowest = 0;

    for (i = 0; i < 2; i++) {
        int v6 = (fam[i].family == AF_INET6);
        uint16_t *slot = v6 ? &c->edns_buffer6 : &c->edns_buffer4;
        const elpis_addr_t *src = v6 ? (c->have_src6 ? &c->out_src6[0] : NULL)
                                     : (c->have_src4 ? &c->out_src4[0] : NULL);
        elpis_addr_t dst;
        unsigned mtu = 0;
        char ifn[64];

        *slot = ELPIS_EDNS_SAFE;
        if (v6 ? !c->do_ipv6 : !c->do_ipv4) {
            snprintf(say[i], sizeof say[i], "%s off", fam[i].name);
            continue;
        }
        if (elpis_addr_parse(&dst, fam[i].dst, 53) != 0 ||
            elpis_sock_route_mtu(&dst, src, &mtu, ifn, sizeof ifn) != ELPIS_OK) {
            snprintf(say[i], sizeof say[i], "%s %u (no route MTU to read)",
                     fam[i].name, (unsigned)*slot);
            continue;
        }
        *slot = elpis_edns_for_mtu(mtu, fam[i].family);
        if (lowest == 0 || *slot < lowest)
            lowest = *slot;
        snprintf(say[i], sizeof say[i], "%s %u (MTU %u%s%s)", fam[i].name,
                 (unsigned)*slot, mtu, ifn[0] ? " on " : "", ifn);
    }
    /* What clients are told: one figure, good for whichever family they use. */
    c->edns_buffer = (uint16_t)(lowest ? lowest : ELPIS_EDNS_SAFE);
    elpis_info("edns-buffer-size auto: %s, %s", say[0], say[1]);
}

int elpis_ctx_init(elpis_ctx_t *ctx, const char *conf_path)
{
    elpis_conf_t *c = &ctx->conf;

    memset(ctx, 0, sizeof *ctx);
    ctx->start_ms = elpis_now_ms();

    if (elpis_conf_load(c, conf_path) != ELPIS_OK)
        return ELPIS_ERR;

    elpis_log_init(c->log_dst, c->log_file, c->log_level);

    elpis_cache_plan(&ctx->plan, c->cache_size, elpis_cpu_count());
    {
        const elpis_cpu_t *cpu = elpis_cpu();
        char feat[96];
        feat[0] = '\0';
        if (cpu->sse2)     elpis_strlcat(feat, " sse2", sizeof feat);
        if (cpu->ssse3)    elpis_strlcat(feat, " ssse3", sizeof feat);
        if (cpu->sse41)    elpis_strlcat(feat, " sse4.1", sizeof feat);
        if (cpu->avx2)     elpis_strlcat(feat, " avx2", sizeof feat);
        if (cpu->bmi2)     elpis_strlcat(feat, " bmi2", sizeof feat);
        if (cpu->avx512f)  elpis_strlcat(feat, " avx512f", sizeof feat);
        if (cpu->neon)     elpis_strlcat(feat, " neon", sizeof feat);
        if (cpu->crc32)    elpis_strlcat(feat, " crc32", sizeof feat);
        elpis_info("elpis %s starting: %s kernels (cpu:%s), %s, %s, %s %s, "
                   "%llu MiB RAM detected, cache budget %llu MiB",
                   ELPIS_VERSION, elpis_simd_backend(),
                   feat[0] ? feat : " none", elpis_loop_backend(),
                   elpis_compiler(), elpis_build_arch(), elpis_build_target(),
                   (unsigned long long)(ctx->plan.ram_total / (1024 * 1024)),
                   (unsigned long long)(ctx->plan.budget_total / (1024 * 1024)));
    }

    /*
     * A cache larger than half the memory we can actually use is a promise the
     * host may not be able to keep.  Automatic sizing never gets here -- it
     * takes a quarter at most -- so this only fires on an explicit cache-size,
     * where the number came from someone who may have been reading the host's
     * memory rather than the container's.  Filling it then means swapping, or
     * on a container with no swap, the OOM killer.
     */
    if (c->cache_size != 0 && ctx->plan.ram_total != 0 &&
        ctx->plan.budget_total > ctx->plan.ram_total / 2u) {
        elpis_warn("cache-size %llu MiB is more than half the %llu MiB "
                   "available to this process -- filling it will need swap, "
                   "and without swap the kernel will kill this process first",
                   (unsigned long long)(ctx->plan.budget_total / (1024 * 1024)),
                   (unsigned long long)(ctx->plan.ram_total / (1024 * 1024)));
    }

    ctx->mcache = elpis_mcache_new(ctx->plan.msg_bytes, ctx->plan.shards);
    ctx->rcache = elpis_rcache_new(ctx->plan.rrset_bytes, ctx->plan.shards);
    ctx->dcache = elpis_dcache_new(ctx->plan.deleg_bytes, ctx->plan.shards / 4u);
    ctx->infra  = elpis_infra_new(ctx->plan.infra_bytes, ctx->plan.shards / 4u);
    if (ctx->mcache == NULL || ctx->rcache == NULL ||
        ctx->dcache == NULL || ctx->infra == NULL) {
        elpis_error("cannot allocate caches");
        return ELPIS_ENOMEM;
    }

    /* Root hints: built-ins, optionally replaced by a hints file. */
    elpis_root_delegation(&ctx->root_hints);
    if (c->root_hints[0] != '\0') {
        elpis_deleg_t d;
        if (elpis_root_hints_load(c->root_hints, &d) == ELPIS_OK)
            ctx->root_hints = d;
    }
    elpis_dcache_put(ctx->dcache, &ctx->root_hints, ctx->root_hints.ttl, 1);

    if (c->dnssec) {
        ctx->ta = elpis_ta_new();
        if (ctx->ta == NULL)
            return ELPIS_ENOMEM;
        elpis_ta_add_builtin(ctx->ta);
        if (c->trust_anchor_file[0] != '\0')
            elpis_ta_load_file(ctx->ta, c->trust_anchor_file);
        if (ctx->ta->n == 0) {
            elpis_warn("no usable trust anchors; disabling DNSSEC validation");
            c->dnssec = 0;
        }
    }

    if (c->edns_auto)
        resolve_edns_auto(c);

    elpis_cookie_init();
    elpis_conf_dump(c);
    return ELPIS_OK;
}

void elpis_ctx_fini(elpis_ctx_t *ctx)
{
    elpis_cache_free(ctx->mcache);
    elpis_cache_free(ctx->rcache);
    elpis_cache_free(ctx->dcache);
    elpis_cache_free(ctx->infra);
    elpis_ta_free(ctx->ta);
    memset(ctx, 0, sizeof *ctx);
}

/* ================================================================== */
/* Workers                                                             */
/* ================================================================== */

/* Sockets opened by worker 0, shared when SO_REUSEPORT is unavailable. */
static int  g_primary_udp[ELPIS_MAX_LSOCK];
static int  g_primary_tcp[ELPIS_MAX_LSOCK];
static unsigned g_n_primary_udp, g_n_primary_tcp;

static void maint_tick(elpis_loop_t *lp, elpis_timer_t *tm);

int elpis_worker_init(elpis_worker_t *w, elpis_ctx_t *ctx, unsigned index)
{
    const elpis_conf_t *c = &ctx->conf;
    unsigned i;

    memset(w, 0, sizeof *w);
    w->ctx   = ctx;
    w->index = index;

    w->loop = elpis_loop_new(256);
    if (w->loop == NULL)
        return ELPIS_ERR;

    w->rxbuf   = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->txbuf   = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->rd1     = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->rd2     = (uint8_t *)elpis_malloc(ELPIS_MAX_MSG + 16);
    w->ctab    = (elpis_cslot_t *)elpis_calloc(ELPIS_BLD_CTAB, sizeof(elpis_cslot_t));
    w->rrbuf   = (elpis_rrset_buf_t *)elpis_malloc(sizeof(elpis_rrset_buf_t));
    w->ttl_off = (uint32_t *)elpis_malloc(4096 * sizeof(uint32_t));
    w->ttl_val = (uint32_t *)elpis_malloc(4096 * sizeof(uint32_t));
    if (w->rxbuf == NULL || w->txbuf == NULL || w->rd1 == NULL ||
        w->rd2 == NULL || w->ctab == NULL || w->rrbuf == NULL ||
        w->ttl_off == NULL || w->ttl_val == NULL)
        return ELPIS_ENOMEM;

    for (i = 0; i < c->nlisten; i++) {
        int fd;

        if (c->listen_udp) {
            if (elpis_sock_udp_listen(&c->listen[i], 1, &fd) == ELPIS_OK) {
                if (index == 0) {
                    char lb[80];
                    elpis_info("  bound udp %s",
                               elpis_addr_str(&c->listen[i], lb, sizeof lb));
                }
                w->udp_fd[w->n_udp] = fd;
                if (elpis_loop_add(w->loop, &w->udp_ev[w->n_udp], fd,
                                   ELPIS_EV_READ, elpis_server_udp_event, w) != ELPIS_OK)
                    return ELPIS_ERR;
                if (index == 0 && g_n_primary_udp < ELPIS_MAX_LSOCK)
                    g_primary_udp[g_n_primary_udp++] = fd;
                w->n_udp++;
            } else if (index > 0 && i < g_n_primary_udp) {
                /*
                 * No SO_REUSEPORT on this platform: share worker 0's socket.
                 * Wake-ups are less evenly spread but everything still works.
                 */
                fd = dup(g_primary_udp[i]);
                if (fd < 0)
                    return ELPIS_ERR;
                w->udp_fd[w->n_udp] = fd;
                if (elpis_loop_add(w->loop, &w->udp_ev[w->n_udp], fd,
                                   ELPIS_EV_READ, elpis_server_udp_event, w) != ELPIS_OK)
                    return ELPIS_ERR;
                w->n_udp++;
            } else {
                return ELPIS_ERR;
            }
        }

        if (c->listen_tcp) {
            if (elpis_sock_tcp_listen(&c->listen[i], 1, 512, &fd) == ELPIS_OK) {
                if (index == 0) {
                    char lb[80];
                    elpis_info("  bound tcp %s",
                               elpis_addr_str(&c->listen[i], lb, sizeof lb));
                }
                w->tcp_fd[w->n_tcp] = fd;
                if (elpis_loop_add(w->loop, &w->tcp_ev[w->n_tcp], fd,
                                   ELPIS_EV_READ, elpis_server_tcp_event, w) != ELPIS_OK)
                    return ELPIS_ERR;
                if (index == 0 && g_n_primary_tcp < ELPIS_MAX_LSOCK)
                    g_primary_tcp[g_n_primary_tcp++] = fd;
                w->n_tcp++;
            } else if (index > 0 && i < g_n_primary_tcp) {
                fd = dup(g_primary_tcp[i]);
                if (fd < 0)
                    return ELPIS_ERR;
                w->tcp_fd[w->n_tcp] = fd;
                if (elpis_loop_add(w->loop, &w->tcp_ev[w->n_tcp], fd,
                                   ELPIS_EV_READ, elpis_server_tcp_event, w) != ELPIS_OK)
                    return ELPIS_ERR;
                w->n_tcp++;
            } else {
                return ELPIS_ERR;
            }
        }
    }

    if (elpis_out_init(w) != ELPIS_OK)
        return ELPIS_ERR;

    elpis_timer_add(w->loop, &w->maint, 1000, maint_tick, w);
    return ELPIS_OK;
}

void elpis_worker_fini(elpis_worker_t *w)
{
    unsigned i;

    elpis_out_fini(w);
    for (i = 0; i < w->n_udp; i++) {
        elpis_loop_del(w->loop, &w->udp_ev[i]);
        close(w->udp_fd[i]);
    }
    for (i = 0; i < w->n_tcp; i++) {
        elpis_loop_del(w->loop, &w->tcp_ev[i]);
        close(w->tcp_fd[i]);
    }
    elpis_loop_free(w->loop);
    elpis_free(w->rxbuf);
    elpis_free(w->txbuf);
    elpis_free(w->rd1);
    elpis_free(w->rd2);
    elpis_free(w->ctab);
    elpis_free(w->rrbuf);
    elpis_free(w->ttl_off);
    elpis_free(w->ttl_val);
}

/* Fold this worker's counters into the shared totals. */
static void publish_stats(elpis_worker_t *w)
{
    /* Runs on this worker's own loop, so the thread-local count is this
     * worker's own. */
    {
        uint64_t nv = elpis_dnssec_take_verifies();
        w->stats.dnssec_verifies += nv;
        elpis_tm_verified(&w->tm, nv);
    }

    elpis_stats_t *g = &w->ctx->stats;
    const uint64_t *src = (const uint64_t *)&w->stats;
    uint64_t *dst = (uint64_t *)g;
    static ELPIS_TLS elpis_stats_t last;
    const uint64_t *prev = (const uint64_t *)&last;
    unsigned i, n = sizeof(elpis_stats_t) / sizeof(uint64_t);

    for (i = 0; i < n; i++)
        if (src[i] > prev[i])
            elpis_stat_inc(&dst[i], src[i] - prev[i]);
    last = w->stats;
}

typedef struct {
    elpis_worker_t w;
    pthread_t      th;
    int            started;
} wslot_t;

static wslot_t *g_workers;
static unsigned g_nworkers;

/*
 * Keep an eye on how the event loop is spending its time.
 *
 * A worker pinned at 100% looks the same in `top` whether it is resolving flat
 * out or going round an empty loop, and the second is very hard to find from
 * the outside.  The numbers that tell them apart are collected here every
 * second and reported by SIGUSR1 and on the status page.
 *
 * Only one case warns on its own, because only one is unambiguous: a healthy
 * loop turns over a few hundred times a second and almost never idly, so
 * hundreds of thousands of turns that did nothing cannot be anything but a
 * spin.  A single long turn is deliberately not warned about -- under load a
 * worker can legitimately spend most of a second working through one batch,
 * and calling that a bug would be crying wolf.
 */
static void report_spin(elpis_worker_t *w)
{
    static ELPIS_TLS uint64_t last_iters, last_idle, last_nosleep;
    static ELPIS_TLS uint64_t warned_at;
    uint64_t iters = 0, idle = 0, nosleep = 0;
    uint32_t slowest = 0;
    unsigned pending = 0;

    elpis_loop_spin_stats(w->loop, &iters, &idle, &nosleep, &pending, &slowest);
    w->loop_turns   = iters - last_iters;
    w->loop_idle    = idle - last_idle;
    w->loop_nosleep = nosleep - last_nosleep;
    w->loop_slowest = slowest;
    w->loop_timers  = pending;
    last_iters = iters; last_idle = idle; last_nosleep = nosleep;

    /*
     * Worker 0 publishes the sum for the whole process.  Exactness does not
     * matter here -- this is a health reading, not a counter -- so it is
     * gathered without locking the workers against each other.
     */
    if (w->index == 0) {
        elpis_loopstat_t sum;
        unsigned k;
        memset(&sum, 0, sizeof sum);
        for (k = 0; k < g_nworkers; k++) {
            const elpis_worker_t *o = &g_workers[k].w;
            sum.turns   += o->loop_turns;
            sum.idle    += o->loop_idle;
            sum.nosleep += o->loop_nosleep;
            sum.timers  += o->loop_timers;
            if (o->loop_slowest > sum.slowest_ms)
                sum.slowest_ms = o->loop_slowest;
        }
        w->ctx->loop = sum;
    }

    if (w->loop_turns > 100000u &&
        w->loop_idle > w->loop_turns - w->loop_turns / 8u) {
        uint64_t now = elpis_now_ms();
        if (now - warned_at > 30000u) {
            warned_at = now;
            elpis_warn("worker %u: the event loop went round %llu times in "
                       "the last second and %llu of those did nothing -- it "
                       "is spinning, not working. %llu turns did not wait, "
                       "%u timers pending. This is a bug; please report this "
                       "line.", w->index,
                       (unsigned long long)w->loop_turns,
                       (unsigned long long)w->loop_idle,
                       (unsigned long long)w->loop_nosleep, w->loop_timers);
        }
    }
}

static void maint_tick(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_worker_t *w = (elpis_worker_t *)tm->data;
    elpis_ctx_t *ctx = w->ctx;
    uint32_t now = elpis_cached_now_s();

    publish_stats(w);
    elpis_tm_publish(&w->tm);
    report_spin(w);

    /* Bounded incremental expiry so no single tick stalls the loop. */
    elpis_cache_expire(ctx->mcache, now, 512);
    elpis_cache_expire(ctx->rcache, now, 512);
    elpis_cache_expire(ctx->infra, now, 128);

    if (ctx->shutdown) {
        elpis_loop_stop(lp);
        return;
    }
    elpis_timer_add(lp, &w->maint, 1000, maint_tick, w);
}

void elpis_worker_run(elpis_worker_t *w)
{
    elpis_clock_tick();
    if (w->index == 0) {
        elpis_prime_start(w);
        elpis_tld_warm_start(w);
    }
    while (!w->ctx->shutdown && !elpis_loop_stopped(w->loop))
        elpis_loop_once(w->loop, 500);
    publish_stats(w);
    elpis_tm_publish(&w->tm);
    elpis_dnssec_thread_done();
}

/* ================================================================== */
/* Threads                                                             */
/* ================================================================== */


static void *worker_main(void *arg)
{
    wslot_t *s = (wslot_t *)arg;
    elpis_worker_run(&s->w);
    return NULL;
}

static void *axfr_main(void *arg)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)arg;
    elpis_axfr_root(ctx);
    return NULL;
}

/*
 * Root latency ranking.  It runs alongside the workers rather than before
 * them: the resolver is perfectly usable with default estimates, and blocking
 * startup for several seconds to measure is the wrong trade.
 */
static void *probe_main(void *arg)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)arg;

    elpis_probe_roots(ctx);

    while (ctx->conf.probe_interval > 0 && !ctx->shutdown) {
        uint32_t left = ctx->conf.probe_interval;
        while (left-- > 0 && !ctx->shutdown)
            sleep(1);
        if (ctx->shutdown)
            break;
        elpis_probe_roots(ctx);
    }
    return NULL;
}

/* ================================================================== */
/* Signals                                                             */
/* ================================================================== */

static volatile sig_atomic_t g_sig_quit;
static volatile sig_atomic_t g_sig_hup;
static volatile sig_atomic_t g_sig_stats;
static volatile sig_atomic_t g_sig_flush;

static void on_signal(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM: g_sig_quit  = 1; break;
    case SIGHUP:  g_sig_hup   = 1; break;
    case SIGUSR1: g_sig_stats = 1; break;
    case SIGUSR2: g_sig_flush = 1; break;
    default: break;
    }
}

static void install_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* ================================================================== */
/* Privilege drop                                                      */
/* ================================================================== */

/*
 * /etc/passwd is parsed directly rather than via getpwnam().  On glibc the
 * NSS machinery is loaded with dlopen(), which a statically linked binary
 * cannot do reliably -- and a resolver that silently fails to drop privilege
 * is worse than one that refuses to start.
 */
static int lookup_id(const char *file, const char *name, unsigned *id,
                     unsigned *gid)
{
    FILE *fp;
    char line[1024];
    int found = 0;

    {
        uint32_t v;
        if (elpis_parse_u32(name, &v) == 0) {
            *id = v;
            if (gid) *gid = v;
            return ELPIS_OK;
        }
    }

    fp = fopen(file, "r");
    if (fp == NULL)
        return ELPIS_ERR;
    while (fgets(line, sizeof line, fp) != NULL) {
        char *f[7];
        unsigned n = 0;
        char *p = line;
        while (n < 7) {
            f[n++] = p;
            p = strchr(p, ':');
            if (p == NULL)
                break;
            *p++ = '\0';
        }
        if (n < 4)
            continue;
        if (strcmp(f[0], name) != 0)
            continue;
        {
            uint32_t u = 0, g = 0;
            if (elpis_parse_u32(f[2], &u) != 0)
                continue;
            *id = u;
            if (gid != NULL && elpis_parse_u32(f[3], &g) == 0)
                *gid = g;
        }
        found = 1;
        break;
    }
    fclose(fp);
    return found ? ELPIS_OK : ELPIS_ERR;
}

/*
 * Can this process bind the ports the config asks for?
 *
 * Failing at bind() time produces "Permission denied" from inside a worker,
 * which tells the operator nothing about what to do next.  Checking here lets
 * us name the port, say exactly why it is refused, and list the three ways to
 * fix it.
 */

/* The privileged range is a sysctl on Linux; 1024 is only the default. */
static unsigned privileged_port_limit(void)
{
#if defined(__linux__)
    FILE *fp = fopen("/proc/sys/net/ipv4/ip_unprivileged_port_start", "r");
    if (fp != NULL) {
        unsigned v = 0;
        int got = fscanf(fp, "%u", &v);
        fclose(fp);
        if (got == 1 && v <= 65535)
            return v;
    }
#endif
    return 1024;
}

/* CAP_NET_BIND_SERVICE (capability 10) in the effective set. */
static int have_bind_capability(void)
{
#if defined(__linux__)
    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];
    int found = 0;

    if (fp == NULL)
        return 0;
    while (fgets(line, sizeof line, fp) != NULL) {
        unsigned long long eff;
        if (strncmp(line, "CapEff:", 7) != 0)
            continue;
        if (sscanf(line + 7, "%llx", &eff) == 1)
            found = (eff & (1ULL << 10)) != 0;
        break;
    }
    fclose(fp);
    return found;
#else
    return 0;
#endif
}

static int check_bind_privilege(const elpis_conf_t *c)
{
    unsigned limit = privileged_port_limit();
    unsigned i;
    uint16_t lowest = 0;
    char buf[80];
    int idx = -1;

    for (i = 0; i < c->nlisten; i++) {
        uint16_t port = elpis_addr_port(&c->listen[i]);
        if (port < limit && (idx < 0 || port < lowest)) {
            lowest = port;
            idx = (int)i;
        }
    }
    if (idx < 0)
        return ELPIS_OK;               /* nothing privileged is requested */

    if (geteuid() == 0 || have_bind_capability())
        return ELPIS_OK;

    elpis_fatal("cannot listen on %s: port %u is privileged on this system "
                "(ports below %u need root or CAP_NET_BIND_SERVICE), and this "
                "process is uid %ld with neither",
                elpis_addr_str(&c->listen[idx], buf, sizeof buf),
                (unsigned)lowest, limit, (long)geteuid());
    elpis_fatal("  pick one:");
    elpis_fatal("    - grant the capability once: "
                "sudo setcap cap_net_bind_service=+ep %s", elpis_exe_path());
    elpis_fatal("    - start as root and set 'user:' in elpis.conf so it "
                "drops privilege after binding");
    elpis_fatal("    - listen on an unprivileged port instead, e.g. "
                "'listen: 127.0.0.1@5335', and point AdGuard or Pi-hole at it");
#if defined(__linux__)
    if (limit == 1024)
        elpis_fatal("    - or lower the range system-wide: "
                    "sysctl net.ipv4.ip_unprivileged_port_start=53");
#endif
    return ELPIS_ERR;
}

/*
 * Something else already owns a port we want.
 *
 * The only case handled automatically is systemd-resolved, and only when we
 * are root and the config asked for a privileged port -- the two conditions
 * under which the conflict is both likely and fixable.  Anything else is
 * reported and refused: quietly killing an unrelated daemon is not this
 * program's business.
 */
/*
 * A specific address listed alongside a wildcard on the same port is covered
 * twice.  It works -- the kernel prefers the specific socket -- but it doubles
 * the descriptors for no gain, and it usually means someone was not sure the
 * wildcard would do the job.  Say so rather than leave them guessing.
 *
 * Also worth stating: IPV6_V6ONLY is set on every IPv6 listener, so "[::]"
 * serves IPv6 only.  Serving both families from wildcards needs both lines.
 */
static void warn_redundant_listeners(const elpis_conf_t *c)
{
    static const uint8_t zero16[16] = { 0 };
    unsigned i, j;
    int have_v4_wild = 0, have_v6_wild = 0;

    for (i = 0; i < c->nlisten; i++) {
        if (elpis_addr_family(&c->listen[i]) == AF_INET &&
            memcmp(&c->listen[i].u.v4.sin_addr, zero16, 4) == 0)
            have_v4_wild = 1;
        if (elpis_addr_family(&c->listen[i]) == AF_INET6 &&
            memcmp(&c->listen[i].u.v6.sin6_addr, zero16, 16) == 0)
            have_v6_wild = 1;
    }

    for (i = 0; i < c->nlisten; i++) {
        int wild_i = 0;
        if (elpis_addr_family(&c->listen[i]) == AF_INET)
            wild_i = memcmp(&c->listen[i].u.v4.sin_addr, zero16, 4) == 0;
        else if (elpis_addr_family(&c->listen[i]) == AF_INET6)
            wild_i = memcmp(&c->listen[i].u.v6.sin6_addr, zero16, 16) == 0;
        if (wild_i)
            continue;

        for (j = 0; j < c->nlisten; j++) {
            char a[80], b[80];
            int wild_j = 0;
            if (j == i)
                continue;
            if (elpis_addr_family(&c->listen[j]) == AF_INET)
                wild_j = memcmp(&c->listen[j].u.v4.sin_addr, zero16, 4) == 0;
            else if (elpis_addr_family(&c->listen[j]) == AF_INET6)
                wild_j = memcmp(&c->listen[j].u.v6.sin6_addr, zero16, 16) == 0;
            if (!wild_j)
                continue;
            if (!elpis_conflict_collides(&c->listen[j], &c->listen[i]))
                continue;

            elpis_warn("listen %s is already covered by %s; the specific line "
                       "is redundant and can be removed",
                       elpis_addr_str(&c->listen[i], a, sizeof a),
                       elpis_addr_str(&c->listen[j], b, sizeof b));
            break;
        }
    }

    if (have_v6_wild && !have_v4_wild)
        elpis_warn("only the IPv6 wildcard is configured: elpis sets "
                   "IPV6_V6ONLY, so '[::]' does not serve IPv4 -- add a "
                   "'listen: 0.0.0.0@<port>' line if you want both");
    if (have_v4_wild && !have_v6_wild)
        elpis_info("no IPv6 listener configured; add 'listen: [::]@<port>' "
                   "to serve IPv6 clients");
}

static int resolve_port_conflicts(elpis_conf_t *c)
{
    unsigned i;
    int stopped = 0;

    for (i = 0; i < c->nlisten; i++) {
        elpis_conflict_t k;
        char ab[80], cb[80];

        if (!elpis_conflict_find(&c->listen[i], &k))
            continue;

        elpis_addr_str(&c->listen[i], ab, sizeof ab);
        elpis_addr_str(&k.addr, cb, sizeof cb);

        if (k.is_resolved && geteuid() == 0 && c->stop_systemd_resolved) {
            if (stopped)
                continue;              /* one stop clears every listener */
            elpis_warn("systemd-resolved (pid %ld) is listening on %s, which "
                       "conflicts with 'listen: %s'", k.pid, cb, ab);
            /*
             * Left alone this does not even fail.  Elpis sets SO_REUSEADDR,
             * and as root Linux will happily bind a port systemd-resolved
             * already holds -- the kernel then hands each arriving query to
             * one of the two at random.
             */
            if (elpis_stop_systemd_resolved(&c->listen[i]) != ELPIS_OK) {
                elpis_fatal("could not free %s; refusing to start and share "
                            "the port with systemd-resolved", ab);
                return ELPIS_ERR;
            }
            stopped = 1;
            continue;
        }

        if (k.is_resolved && geteuid() != 0) {
            elpis_fatal("systemd-resolved (pid %ld) is listening on %s, which "
                        "conflicts with 'listen: %s', and this process is not "
                        "root so it cannot stop it", k.pid, cb, ab);
            elpis_fatal("  sudo systemctl disable --now systemd-resolved, "
                        "or listen on another port");
            return ELPIS_ERR;
        }
        if (k.is_resolved) {
            elpis_fatal("systemd-resolved (pid %ld) holds %s and "
                        "stop-systemd-resolved is off; refusing to share "
                        "the port", k.pid, cb);
            return ELPIS_ERR;
        }

        if (k.identified)
            elpis_fatal("%s (pid %ld) is already listening on %s/%s, which "
                        "conflicts with 'listen: %s'",
                        k.name[0] ? k.name : "another process", k.pid, cb,
                        k.proto[0] ? k.proto : "udp", ab);
        else
            elpis_fatal("something is already listening on %s/%s, which "
                        "conflicts with 'listen: %s' (run as root to see what)",
                        cb, k.proto[0] ? k.proto : "udp", ab);
        if (k.cmdline[0])
            elpis_fatal("  command: %s", k.cmdline);
        elpis_fatal("  stop it, or move elpis to another port");
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

static int drop_privilege(const elpis_conf_t *c)
{
    unsigned uid = 0, gid = 0;

    if (geteuid() != 0)
        return ELPIS_OK;

    if (c->chroot_dir[0] != '\0') {
        if (chroot(c->chroot_dir) != 0 || chdir("/") != 0) {
            elpis_error("chroot to '%s' failed: %s", c->chroot_dir, strerror(errno));
            return ELPIS_ERR;
        }
        elpis_info("chrooted to %s", c->chroot_dir);
    }

    if (c->group[0] != '\0') {
        if (lookup_id("/etc/group", c->group, &gid, NULL) != ELPIS_OK) {
            elpis_error("unknown group '%s'", c->group);
            return ELPIS_ERR;
        }
    }
    if (c->user[0] != '\0') {
        unsigned ugid = 0;
        if (lookup_id("/etc/passwd", c->user, &uid, &ugid) != ELPIS_OK) {
            elpis_error("unknown user '%s'", c->user);
            return ELPIS_ERR;
        }
        if (c->group[0] == '\0')
            gid = ugid;
    }

    if (gid != 0) {
        if (setgroups(0, NULL) != 0 && errno != EPERM)
            elpis_warn("setgroups failed: %s", strerror(errno));
        if (setgid((gid_t)gid) != 0) {
            elpis_error("setgid(%u) failed: %s", gid, strerror(errno));
            return ELPIS_ERR;
        }
    }
    if (uid != 0) {
        if (setuid((uid_t)uid) != 0) {
            elpis_error("setuid(%u) failed: %s", uid, strerror(errno));
            return ELPIS_ERR;
        }
        if (setuid(0) == 0) {
            elpis_error("privilege drop did not stick; refusing to run");
            return ELPIS_ERR;
        }
        elpis_info("running as uid %u gid %u", uid, gid);
    }
    return ELPIS_OK;
}

/* ================================================================== */
/* Entry point                                                         */
/* ================================================================== */

/*
 * Hash a status page password for pasting into the config.  The resolver will
 * do this itself when it can write the file, but a deployment worth running
 * does not let it: the shipped systemd unit mounts the install read-only, so
 * the hashing has to happen somewhere the sandbox is not.
 */
static int hash_password(const char *plain)
{
    char buf[256], hashed[256];

    elpis_random_init();

    if (plain == NULL) {
        size_t n;
        if (isatty(STDIN_FILENO))
            fprintf(stderr, "password: ");
        if (fgets(buf, sizeof buf, stdin) == NULL) {
            fprintf(stderr, "no password read\n");
            return 2;
        }
        n = strlen(buf);
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
            buf[--n] = '\0';
        plain = buf;
    }
    if (plain[0] == '\0') {
        fprintf(stderr, "refusing to hash an empty password\n");
        return 2;
    }

    elpis_webui_hash_password(plain, hashed, sizeof hashed);
    printf("webgui-password: %s\n", hashed);

    memset(buf, 0, sizeof buf);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "elpis %s -- recursive DNS resolver\n"
        "\n"
        "usage: %s [options]\n"
        "  -c FILE   configuration file (default: elpis.conf beside the\n"
        "            binary, then %s/elpis/elpis.conf, then %s/elpis.conf)\n"
        "  -d        stay in the foreground and log to stderr\n"
        "  -t        check the configuration and exit\n"
        "  -v        increase log verbosity (repeatable)\n"
        "  -V        print the version and exit\n"
        "  -h        this message\n"
        "\n"
        "  --hash-password [PASS]\n"
        "            print a webgui-password: line to paste into the config.\n"
        "            Use this when the config file is read-only, which under\n"
        "            the shipped systemd unit it is.  With no PASS, reads one\n"
        "            line from stdin so it stays out of your shell history.\n",
        ELPIS_VERSION, argv0, ELPIS_SYSCONFDIR, ELPIS_SYSCONFDIR);
}

/*
 * Check the licence once, here, and never again while running.  A resolver
 * that stopped answering because a signature or a date was wrong would be a
 * far worse failure than anything a licence protects against, so none of this
 * changes how a single query is handled: it decides what the resolver says
 * about itself, and that is all.
 */
/*
 * Settings that only a licensed build may change.  Applied after the licence
 * has been checked, because the config file is read long before that: at
 * parse time there is nothing to check against.
 *
 * A lapsed licence keeps them.  Expiry does not stop the resolver resolving
 * and it should not quietly move a name somebody's monitoring points at
 * either; the warning is the signal, not a change of behaviour.
 */
static void apply_licensed_settings(elpis_ctx_t *ctx)
{
    elpis_conf_t *c = &ctx->conf;

    if (elpis_strcasecmp_ascii(c->identity_name,
                               ELPIS_IDENTITY_NAME_DEFAULT) == 0)
        return;                         /* unchanged: nothing to gate */
    if (ctx->licence.valid)
        return;

    elpis_warn("identity-name is a licensed setting; '%s' ignored",
               c->identity_name);
    elpis_warn("using the default name '%s' -- 'identity: no' turns the probe "
               "off entirely, which needs no licence",
               ELPIS_IDENTITY_NAME_DEFAULT);
    elpis_strlcpy(c->identity_name, ELPIS_IDENTITY_NAME_DEFAULT,
                  sizeof c->identity_name);
}

static void check_licence(elpis_ctx_t *ctx)
{
    elpis_conf_t *c = &ctx->conf;
    char expires[32];

    if (c->licence[0] == '\0') {
        apply_licensed_settings(ctx);
        return;
    }

    elpis_licence_parse(c->licence, (int64_t)time(NULL), &ctx->licence);
    elpis_licence_date(ctx->licence.expires, expires, sizeof expires);

    if (!ctx->licence.valid) {
        elpis_warn("licence not accepted: %s", ctx->licence.why);
        elpis_warn("continuing with the self-declared edition '%s'", c->edition);
        apply_licensed_settings(ctx);
        return;
    }

    /* A verified licence outranks whatever edition: says.  Otherwise the
     * signature would be decoration -- anyone could hold a community licence
     * and still write commercial on the line below it. */
    elpis_strlcpy(c->edition, elpis_edition_name(ctx->licence.edition),
                  sizeof c->edition);

    if (ctx->licence.expired)
        elpis_warn("licence %lu for \"%s\" expired on %s; still %s, "
                   "nothing stops working",
                   (unsigned long)ctx->licence.serial, ctx->licence.org,
                   expires, elpis_edition_name(ctx->licence.edition));
    else
        elpis_info("licence %lu for \"%s\": %s, expires %s",
                   (unsigned long)ctx->licence.serial, ctx->licence.org,
                   elpis_edition_name(ctx->licence.edition), expires);

    apply_licensed_settings(ctx);
}

static int write_pidfile(const char *path)
{
    FILE *fp;
    if (path == NULL || *path == '\0')
        return ELPIS_OK;
    fp = fopen(path, "w");
    if (fp == NULL) {
        elpis_warn("cannot write pidfile '%s': %s", path, strerror(errno));
        return ELPIS_ERR;
    }
    fprintf(fp, "%ld\n", (long)getpid());
    fclose(fp);
    return ELPIS_OK;
}

int main(int argc, char **argv)
{
    static elpis_ctx_t ctx;
    const char *conf_path = NULL;
    int foreground = 0, testonly = 0, verbose = 0;
    unsigned nthreads, i;
    pthread_t axfr_th, probe_th;
    int axfr_started = 0, probe_started = 0;
    pthread_t web_th;
    int web_started = 0;

    for (i = 1; i < (unsigned)argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-c") && i + 1 < (unsigned)argc)      conf_path = argv[++i];
        else if (!strcmp(a, "-d"))                           foreground = 1;
        else if (!strcmp(a, "-t"))                           testonly = 1;
        else if (!strcmp(a, "-v"))                           verbose++;
        else if (!strcmp(a, "-V")) { printf("elpis %s\n", ELPIS_VERSION); return 0; }
        else if (!strcmp(a, "--hash-password")) return hash_password(argv[i + 1]);
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown option '%s'\n", a); usage(argv[0]); return 2; }
    }

    elpis_log_init(ELPIS_LOG_DST_STDERR, NULL, ELPIS_LOG_INFO);
    elpis_simd_init();
    elpis_clock_tick();
    elpis_random_init();

    if (elpis_ctx_init(&ctx, conf_path) != ELPIS_OK) {
        elpis_fatal("startup failed");
        return 1;
    }
    elpis_g = &ctx;

    if (verbose) {
        elpis_loglevel_t l = ctx.conf.log_level;
        while (verbose-- > 0 && l < ELPIS_LOG_TRACE)
            l = (elpis_loglevel_t)(l + 1);
        elpis_log_set_level(l);
        ctx.conf.log_level = l;
    }
    if (foreground) {
        ctx.conf.daemonize = 0;
        elpis_log_init(ELPIS_LOG_DST_STDERR, NULL, ctx.conf.log_level);
    }

    if (testonly) {
        elpis_info("configuration OK");
        elpis_ctx_fini(&ctx);
        return 0;
    }

    nthreads = ctx.conf.threads ? ctx.conf.threads : elpis_cpu_count();
    if (nthreads < 1)   nthreads = 1;
    if (nthreads > 256) nthreads = 256;

    g_workers = (wslot_t *)elpis_calloc(nthreads, sizeof(wslot_t));
    if (g_workers == NULL) {
        elpis_fatal("out of memory");
        return 1;
    }
    g_nworkers = nthreads;

    if (check_bind_privilege(&ctx.conf) != ELPIS_OK)
        return 1;
    if (resolve_port_conflicts(&ctx.conf) != ELPIS_OK)
        return 1;
    warn_redundant_listeners(&ctx.conf);

    /*
     * Running as root with nowhere to drop to is a choice, not a mistake, but
     * it is worth saying out loud once.
     */
    if (geteuid() == 0 && ctx.conf.user[0] == '\0')
        elpis_warn("running as root and no 'user:' is configured; "
                   "the resolver will keep full privileges");

    /* Sockets are bound before privileges are dropped. */
    for (i = 0; i < nthreads; i++) {
        if (elpis_worker_init(&g_workers[i].w, &ctx, i) != ELPIS_OK) {
            elpis_fatal("worker %u failed to start", i);
            return 1;
        }
    }

    if (drop_privilege(&ctx.conf) != ELPIS_OK)
        return 1;

    if (ctx.conf.daemonize && !foreground) {
        if (daemon(0, 0) != 0) {
            elpis_error("daemon() failed: %s", strerror(errno));
            return 1;
        }
    }
    elpis_tm_init(ctx.conf.web ? 1 : 0);
    if (ctx.conf.web)
        elpis_webui_prepare(&ctx);

    write_pidfile(ctx.conf.pidfile);
    install_signals();

    check_licence(&ctx);

    elpis_info("listening with %u worker%s", nthreads, nthreads == 1 ? "" : "s");

    if (ctx.conf.root_zone_transfer) {
        if (pthread_create(&axfr_th, NULL, axfr_main, &ctx) == 0)
            axfr_started = 1;
        else
            elpis_warn("could not start the root zone transfer thread");
    }
    if (ctx.conf.probe_roots) {
        if (pthread_create(&probe_th, NULL, probe_main, &ctx) == 0)
            probe_started = 1;
        else
            elpis_warn("could not start the root probe thread");
    }
    if (ctx.conf.web) {
        if (pthread_create(&web_th, NULL, elpis_webui_main, &ctx) == 0)
            web_started = 1;
        else
            elpis_warn("could not start the status page thread");
    }

    for (i = 1; i < nthreads; i++) {
        if (pthread_create(&g_workers[i].th, NULL, worker_main,
                           &g_workers[i]) != 0) {
            elpis_error("cannot create worker %u: %s", i, strerror(errno));
            break;
        }
        g_workers[i].started = 1;
    }

    /* Worker 0 runs on the main thread so signals land somewhere useful. */
    {
        elpis_worker_t *w0 = &g_workers[0].w;
        uint64_t last_stats = elpis_now_ms();

        elpis_clock_tick();
        elpis_prime_start(w0);
        elpis_tld_warm_start(w0);
        elpis_selfinfo_start(w0);

        while (!ctx.shutdown) {
            elpis_loop_once(w0->loop, 200);

            if (g_sig_quit) {
                elpis_info("shutting down");
                ctx.shutdown = 1;
                break;
            }
            if (g_sig_hup) {
                g_sig_hup = 0;
                elpis_log_reopen();
                elpis_cookie_rotate();
                elpis_random_reseed();
                elpis_info("reopened log, rotated the cookie secret and "
                           "reseeded the random pool");
            }
            if (g_sig_stats) {
                g_sig_stats = 0;
                elpis_stats_report(&ctx);
            }
            if (g_sig_flush) {
                g_sig_flush = 0;
                elpis_cache_flush(ctx.mcache);
                elpis_cache_flush(ctx.rcache);
                /*
                 * The delegation cache keeps the root hints: without them the
                 * resolver has nowhere to start after a flush.
                 */
                elpis_cache_flush(ctx.dcache);
                elpis_dcache_put(ctx.dcache, &ctx.root_hints,
                                 ctx.root_hints.ttl, 1);
                elpis_info("caches flushed on SIGUSR2");
            }
            if (ctx.conf.stats_interval &&
                elpis_now_ms() - last_stats >= ctx.conf.stats_interval * 1000ull) {
                last_stats = elpis_now_ms();
                elpis_stats_report(&ctx);
            }
        }
    }

    ctx.shutdown = 1;
    for (i = 1; i < nthreads; i++)
        if (g_workers[i].started)
            pthread_join(g_workers[i].th, NULL);
    if (axfr_started)
        pthread_join(axfr_th, NULL);
    if (probe_started)
        pthread_join(probe_th, NULL);
    if (web_started)
        pthread_join(web_th, NULL);

    elpis_stats_report(&ctx);

    for (i = 0; i < nthreads; i++)
        elpis_worker_fini(&g_workers[i].w);
    elpis_free(g_workers);

    if (ctx.conf.pidfile[0] != '\0')
        unlink(ctx.conf.pidfile);

    elpis_ctx_fini(&ctx);
    elpis_log_fini();
    return 0;
}
