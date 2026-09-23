/*
 * telemetry.c -- history, top-N tallies and the recent log.
 *
 * See elpis/telemetry.h for why the worker side takes no locks.
 */
#include "elpis/telemetry.h"
#include "elpis/ctx.h"
#include "elpis/log.h"
#include "elpis/simd.h"

#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Shared state                                                        */
/* ------------------------------------------------------------------ */

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static elpis_tmtab_t   g_tab[ELPIS_TOP__COUNT];

static elpis_tmsample_t g_hist[ELPIS_TM_HISTORY];
static unsigned         g_hist_n;      /* samples written, saturating  */
static unsigned         g_hist_head;   /* next slot to write           */

static char     g_log[ELPIS_TM_LOGRING][ELPIS_TM_LOGLEN];
static unsigned g_log_n, g_log_head;

/* Totals at the previous tick, so a sample is a delta. */
static struct {
    uint64_t queries, servfail, bogus, cache_hits, upstream;
    uint64_t rx_bytes, tx_bytes, rtt_sum_us, rtt_count;
    uint64_t rec_sum_us, rec_count;
    uint64_t verifies;
    uint64_t cpu_jiffies;
    uint64_t at_ms;
    int      have;
} g_prev;

static uint32_t g_cpu_milli;
static uint64_t g_rss_bytes;

/* Merged from every worker's counters, which only ever grow. */
static uint64_t g_rx_total, g_tx_total, g_rtt_sum_us, g_rtt_count;
static uint64_t g_verify_total;
static uint64_t g_rec_sum_us, g_rec_count;

int elpis_tm_enabled = 0;

void elpis_tm_init(int enabled)
{
    elpis_tm_enabled = enabled;
    pthread_mutex_lock(&g_lock);
    memset(g_tab, 0, sizeof g_tab);
    memset(g_hist, 0, sizeof g_hist);
    g_hist_n = g_hist_head = 0;
    g_log_n = g_log_head = 0;
    memset(&g_prev, 0, sizeof g_prev);
    pthread_mutex_unlock(&g_lock);
}

/* ------------------------------------------------------------------ */
/* Tables                                                              */
/* ------------------------------------------------------------------ */

static uint64_t key_hash(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ull;      /* FNV-1a */
    size_t i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ull;
    }
    return h ? h : 1u;
}

/*
 * Bump `key` in `t`.
 *
 * Open addressing with a short probe.  When the run is full the smallest
 * count in it is evicted, which is the usual approximate-heavy-hitters trade:
 * a key that really is busy comes straight back, and one that appeared once
 * does not deserve the slot it was holding.
 */
/*
 * Bump the entry for `key` (raw bytes), creating it if new.
 *
 * Returns the slot when its text still needs filling in -- that is, when this
 * key has just been seen for the first time -- and NULL when it was already
 * there.  Keeping the text out of the lookup is what makes counting every
 * single query affordable: the hash is over the wire form, so a busy name
 * costs one hash and one add no matter how often it is asked for.
 *
 * Open addressing with a short probe.  When the run is full the smallest count
 * in it is evicted, the usual approximate-heavy-hitters trade: something that
 * really is busy comes straight back, and something seen once does not deserve
 * the slot it was holding.
 */
static elpis_tmslot_t *tab_bump(elpis_tmtab_t *t, const void *key, size_t klen,
                                uint64_t by)
{
    uint64_t h = key_hash((const char *)key, klen);
    unsigned i, start, victim;
    uint64_t least;

    if (klen == 0)
        return NULL;

    start  = (unsigned)(h & (ELPIS_TM_SLOTS - 1u));
    victim = start;
    least  = (uint64_t)-1;

    for (i = 0; i < 8u; i++) {
        unsigned idx = (start + i) & (ELPIS_TM_SLOTS - 1u);
        elpis_tmslot_t *s = &t->slot[idx];

        if (s->hash == 0) {
            s->hash  = h;
            s->count = by;
            s->key[0] = '\0';
            return s;
        }
        if (s->hash == h) {
            s->count += by;
            return NULL;
        }
        if (s->count < least) {
            least  = s->count;
            victim = idx;
        }
    }
    {
        elpis_tmslot_t *s = &t->slot[victim];
        s->hash  = h;
        s->count = by;
        s->key[0] = '\0';
        return s;
    }
}

/* Merging an already-formatted row from a worker table into the shared one. */
static void tab_merge(elpis_tmtab_t *t, const char *text, uint64_t by)
{
    elpis_tmslot_t *s = tab_bump(t, text, strlen(text), by);
    if (s != NULL)
        elpis_strlcpy(s->key, text, sizeof s->key);
}

/* The address alone, without the port: one client is one row however many
 * ephemeral ports it happens to use. */
static void addr_only(const elpis_addr_t *a, char *out, size_t outsz)
{
    char full[80];
    size_t n;

    elpis_addr_str(a, full, sizeof full);
    if (full[0] == '[') {
        char *end = strchr(full, ']');
        if (end != NULL) {
            n = (size_t)(end - full) - 1u;
            if (n >= outsz) n = outsz - 1u;
            memcpy(out, full + 1, n);
            out[n] = '\0';
            return;
        }
    } else {
        char *colon = strrchr(full, ':');
        if (colon != NULL)
            *colon = '\0';
    }
    elpis_strlcpy(out, full, outsz);
}

/* ------------------------------------------------------------------ */
/* Worker side                                                         */
/* ------------------------------------------------------------------ */

void elpis_tm_verified(elpis_wtm_t *w, uint64_t n)
{
    if (!elpis_tm_enabled || w == NULL || n == 0)
        return;
    w->verifies += n;
    w->dirty = 1;
}

void elpis_tm_observe(elpis_wtm_t *w, uint64_t service_us, int recursed)
{
    if (!elpis_tm_enabled || w == NULL)
        return;
    /*
     * Answered from cache and answered by asking the internet differ by three
     * orders of magnitude, so one average over both says almost nothing.  The
     * two are kept apart and the page shows both -- which only works if each
     * query lands in exactly one of them.  Adding every query to the cache
     * figure and recursions to both made the "from cache" number the mean
     * over everything: at a 70% hit rate it read a hundred milliseconds for
     * answers that took none.
     */
    if (recursed) {
        w->rec_sum_us += service_us;
        w->rec_count++;
    } else {
        w->rtt_sum_us += service_us;
        w->rtt_count++;
    }
    w->dirty = 1;
}

/* Hash over the wire name, lowercased, so 0x20 randomisation does not split
 * one name across several rows. */
static void bump_name(elpis_tmtab_t *t, const elpis_name_t *n)
{
    uint8_t low[ELPIS_MAX_NAME];
    elpis_tmslot_t *s;

    if (n->len == 0)
        return;                       /* len is a uint8_t: it cannot exceed low[] */
    elpis_simd_lower(low, n->d, n->len);
    s = tab_bump(t, low, n->len, 1u);
    if (s != NULL) {
        elpis_name_t tmp = *n;
        elpis_name_lower(&tmp);
        elpis_name_str(&tmp, s->key, sizeof s->key);
    }
}

static void bump_addr(elpis_tmtab_t *t, const elpis_addr_t *a, int with_port)
{
    elpis_tmslot_t *s;
    const void *key;
    size_t klen;

    if (a->u.sa.sa_family == AF_INET) {
        key  = &a->u.v4.sin_addr;
        klen = sizeof a->u.v4.sin_addr;
    } else if (a->u.sa.sa_family == AF_INET6) {
        key  = &a->u.v6.sin6_addr;
        klen = sizeof a->u.v6.sin6_addr;
    } else {
        return;
    }
    s = tab_bump(t, key, klen, 1u);
    if (s != NULL) {
        if (with_port)
            elpis_addr_str(a, s->key, sizeof s->key);
        else
            addr_only(a, s->key, sizeof s->key);
    }
}

void elpis_tm_answer(elpis_wtm_t *w, const elpis_name_t *qname,
                     const elpis_addr_t *client, unsigned rcode, int bogus)
{
    int failed = (rcode == ELPIS_RC_SERVFAIL);

    if (!elpis_tm_enabled || w == NULL)
        return;
    w->dirty = 1;

    if (qname != NULL) {
        bump_name(&w->tab[ELPIS_TOP_QNAME], qname);
        if (failed) bump_name(&w->tab[ELPIS_TOP_SERVFAIL], qname);
        if (bogus)  bump_name(&w->tab[ELPIS_TOP_BOGUS], qname);
    }
    if (client != NULL) {
        bump_addr(&w->tab[ELPIS_TOP_CLIENT], client, 0);
        if (failed) bump_addr(&w->tab[ELPIS_TOP_CLIENT_FAIL], client, 0);
        if (bogus)  bump_addr(&w->tab[ELPIS_TOP_CLIENT_BOGUS], client, 0);
    }
}

void elpis_tm_timeout(elpis_wtm_t *w, const elpis_addr_t *server)
{
    if (!elpis_tm_enabled || w == NULL || server == NULL)
        return;
    /* The port is kept here: it identifies which instance went quiet. */
    bump_addr(&w->tab[ELPIS_TOP_TIMEOUT], server, 1);
    w->dirty = 1;
}

void elpis_tm_bytes(elpis_wtm_t *w, uint64_t rx, uint64_t tx)
{
    if (!elpis_tm_enabled || w == NULL)
        return;
    w->rx_bytes += rx;
    w->tx_bytes += tx;
}

void elpis_tm_publish(elpis_wtm_t *w)
{
    unsigned k, i;

    if (!elpis_tm_enabled || w == NULL)
        return;

    pthread_mutex_lock(&g_lock);
    g_rx_total   += w->rx_bytes;
    g_tx_total   += w->tx_bytes;
    g_verify_total += w->verifies;
    g_rtt_sum_us += w->rtt_sum_us;
    g_rtt_count  += w->rtt_count;
    g_rec_sum_us += w->rec_sum_us;
    g_rec_count  += w->rec_count;
    if (w->dirty) {
        for (k = 0; k < ELPIS_TOP__COUNT; k++) {
            for (i = 0; i < ELPIS_TM_SLOTS; i++) {
                elpis_tmslot_t *s = &w->tab[k].slot[i];
                if (s->hash != 0 && s->count != 0 && s->key[0] != '\0')
                    tab_merge(&g_tab[k], s->key, s->count);
            }
        }
    }
    pthread_mutex_unlock(&g_lock);

    memset(w->tab, 0, sizeof w->tab);
    w->rx_bytes = w->tx_bytes = 0;
    w->verifies = 0;
    w->rtt_sum_us = w->rtt_count = 0;
    w->rec_sum_us = w->rec_count = 0;
    w->dirty = 0;
}

/* ------------------------------------------------------------------ */
/* Process CPU and memory                                              */
/* ------------------------------------------------------------------ */

static uint64_t self_cpu_jiffies(void)
{
#if defined(__linux__)
    char buf[1024];
    int fd = open("/proc/self/stat", O_RDONLY);
    ssize_t n;
    char *p;
    unsigned f;
    uint64_t utime = 0, stime = 0;

    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';

    /* The command field may contain spaces; it is parenthesised, so skip past
     * the last ')' before counting fields. */
    p = strrchr(buf, ')');
    if (p == NULL)
        return 0;
    p++;
    /* Fields from here: state(3) ... utime(14) stime(15). */
    for (f = 3; f < 14 && *p; f++) {
        while (*p == ' ') p++;
        while (*p && *p != ' ') p++;
    }
    while (*p == ' ') p++;
    for (; *p >= '0' && *p <= '9'; p++) utime = utime * 10u + (uint64_t)(*p - '0');
    while (*p == ' ') p++;
    for (; *p >= '0' && *p <= '9'; p++) stime = stime * 10u + (uint64_t)(*p - '0');
    return utime + stime;
#else
    return 0;
#endif
}

static uint64_t self_rss_bytes(void)
{
#if defined(__linux__)
    char buf[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    ssize_t n;
    const char *p;
    uint64_t kb = 0;

    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    p = strstr(buf, "VmRSS:");
    if (p == NULL)
        return 0;
    p += 6;
    while (*p == ' ' || *p == '\t') p++;
    for (; *p >= '0' && *p <= '9'; p++) kb = kb * 10u + (uint64_t)(*p - '0');
    return kb * 1024u;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* Sampling                                                            */
/* ------------------------------------------------------------------ */

void elpis_tm_tick(const void *ctxv)
{
    const elpis_ctx_t *ctx = (const elpis_ctx_t *)ctxv;
    const elpis_stats_t *s;
    elpis_tmsample_t smp;
    uint64_t now_ms = elpis_now_ms();
    uint64_t jiff = self_cpu_jiffies();
    uint64_t rss  = self_rss_bytes();
    long hz;

    if (ctx == NULL)
        return;
    s = &ctx->stats;

    memset(&smp, 0, sizeof smp);

    pthread_mutex_lock(&g_lock);
    if (g_prev.have) {
        uint64_t dt_ms = now_ms > g_prev.at_ms ? now_ms - g_prev.at_ms : 1u;
        uint64_t dq  = s->queries    - g_prev.queries;
        uint64_t df  = s->servfail   - g_prev.servfail;
        uint64_t db  = s->dnssec_bogus - g_prev.bogus;
        uint64_t dh  = s->cache_hits - g_prev.cache_hits;
        uint64_t du  = s->upstream_queries - g_prev.upstream;
        uint64_t drx = g_rx_total - g_prev.rx_bytes;
        uint64_t dtx = g_tx_total - g_prev.tx_bytes;
        uint64_t dc  = g_rtt_count - g_prev.rtt_count;
        uint64_t dr  = g_rec_count - g_prev.rec_count;

        /* Scale to exactly one second, so a late tick does not read as a dip. */
        smp.queries    = dq * 1000u / dt_ms;
        smp.servfail   = df * 1000u / dt_ms;
        smp.bogus      = db * 1000u / dt_ms;
        smp.cache_hits = dh * 1000u / dt_ms;
        smp.upstream   = du * 1000u / dt_ms;
        smp.rx_bytes   = drx * 1000u / dt_ms;
        smp.tx_bytes   = dtx * 1000u / dt_ms;
        smp.rtt_us     = dc ? (uint32_t)((g_rtt_sum_us - g_prev.rtt_sum_us) / dc) : 0u;
        smp.rec_us     = dr ? (uint32_t)((g_rec_sum_us - g_prev.rec_sum_us) / dr) : 0u;
        smp.rtt_n      = dc;
        smp.verifies   = g_verify_total - g_prev.verifies;
        smp.rec_n      = dr;

        hz = sysconf(_SC_CLK_TCK);
        if (hz <= 0)
            hz = 100;
        if (jiff >= g_prev.cpu_jiffies) {
            uint64_t dj = jiff - g_prev.cpu_jiffies;
            smp.cpu_milli = (uint32_t)((dj * 1000u * 1000u) / ((uint64_t)hz * dt_ms));
        }
        smp.rss_bytes = rss;

        g_hist[g_hist_head] = smp;
        g_hist_head = (g_hist_head + 1u) % ELPIS_TM_HISTORY;
        if (g_hist_n < ELPIS_TM_HISTORY)
            g_hist_n++;

        g_cpu_milli = smp.cpu_milli;
        g_rss_bytes = rss;
    }

    g_prev.queries     = s->queries;
    g_prev.servfail    = s->servfail;
    g_prev.bogus       = s->dnssec_bogus;
    g_prev.cache_hits  = s->cache_hits;
    g_prev.upstream    = s->upstream_queries;
    g_prev.rx_bytes    = g_rx_total;
    g_prev.tx_bytes    = g_tx_total;
    g_prev.verifies    = g_verify_total;
    g_prev.rtt_sum_us  = g_rtt_sum_us;
    g_prev.rtt_count   = g_rtt_count;
    g_prev.rec_sum_us  = g_rec_sum_us;
    g_prev.rec_count   = g_rec_count;
    g_prev.cpu_jiffies = jiff;
    g_prev.at_ms       = now_ms;
    g_prev.have        = 1;
    pthread_mutex_unlock(&g_lock);
}

void elpis_tm_process(uint32_t *cpu_milli, uint64_t *rss_bytes)
{
    pthread_mutex_lock(&g_lock);
    if (cpu_milli) *cpu_milli = g_cpu_milli;
    if (rss_bytes) *rss_bytes = g_rss_bytes;
    pthread_mutex_unlock(&g_lock);
}

unsigned elpis_tm_history(elpis_tmsample_t *out, unsigned max)
{
    unsigned n, i, start;

    pthread_mutex_lock(&g_lock);
    n = g_hist_n < max ? g_hist_n : max;
    start = (g_hist_head + ELPIS_TM_HISTORY - n) % ELPIS_TM_HISTORY;
    for (i = 0; i < n; i++)
        out[i] = g_hist[(start + i) % ELPIS_TM_HISTORY];
    pthread_mutex_unlock(&g_lock);
    return n;
}

unsigned elpis_tm_top(elpis_top_t which, elpis_tmrow_t *out, unsigned max)
{
    unsigned n = 0, i, j;

    if (which >= ELPIS_TOP__COUNT)
        return 0;

    pthread_mutex_lock(&g_lock);
    for (i = 0; i < ELPIS_TM_SLOTS; i++) {
        const elpis_tmslot_t *s = &g_tab[which].slot[i];
        if (s->hash == 0 || s->count == 0)
            continue;
        /* Insertion sort into the output, which is tiny. */
        for (j = n; j > 0 && out[j - 1].count < s->count; j--) {
            if (j < max)
                out[j] = out[j - 1];
        }
        if (j < max) {
            elpis_strlcpy(out[j].key, s->key, sizeof out[j].key);
            out[j].count = s->count;
            if (n < max)
                n++;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return n;
}

/* ------------------------------------------------------------------ */
/* Log ring                                                            */
/* ------------------------------------------------------------------ */

void elpis_tm_log_add(const char *level, const char *msg)
{
    char line[ELPIS_TM_LOGLEN];

    snprintf(line, sizeof line, "%s\t%s", level ? level : "?", msg ? msg : "");

    pthread_mutex_lock(&g_lock);
    elpis_strlcpy(g_log[g_log_head], line, ELPIS_TM_LOGLEN);
    g_log_head = (g_log_head + 1u) % ELPIS_TM_LOGRING;
    if (g_log_n < ELPIS_TM_LOGRING)
        g_log_n++;
    pthread_mutex_unlock(&g_lock);
}

unsigned elpis_tm_log(char out[][ELPIS_TM_LOGLEN], unsigned max)
{
    unsigned n, i, start;

    pthread_mutex_lock(&g_lock);
    n = g_log_n < max ? g_log_n : max;
    start = (g_log_head + ELPIS_TM_LOGRING - n) % ELPIS_TM_LOGRING;
    for (i = 0; i < n; i++)
        elpis_strlcpy(out[i], g_log[(start + i) % ELPIS_TM_LOGRING],
                      ELPIS_TM_LOGLEN);
    pthread_mutex_unlock(&g_lock);
    return n;
}
