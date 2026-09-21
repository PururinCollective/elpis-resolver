/*
 * log.c -- logging and malformed-input accounting.
 *
 * Design notes
 *  - A single mutex guards the output stream only; counters use atomics so the
 *    packet path never blocks on the logger.
 *  - Every malformed datagram is counted.  Log lines for them are rate limited
 *    per drop reason, because a hostile peer can otherwise turn the log into
 *    an amplification target of its own.
 */
#include "elpis/log.h"
#include "elpis/util.h"
#include "elpis/atomic.h"

#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#if !defined(_WIN32)
#  include <syslog.h>
#endif

static pthread_mutex_t   g_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE             *g_fp;
static char              g_path[1024];
static elpis_logdst_t    g_dst = ELPIS_LOG_DST_STDERR;
static elpis_loglevel_t  g_level = ELPIS_LOG_INFO;
static int               g_syslog_open;

static const char *const k_level_name[] = {
    "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

int elpis_log_level_parse(const char *s, elpis_loglevel_t *out)
{
    size_t i;
    for (i = 0; i < ELPIS_ARRAY_LEN(k_level_name); i++) {
        if (!elpis_strcasecmp_ascii(s, k_level_name[i])) {
            *out = (elpis_loglevel_t)i;
            return 0;
        }
    }
    return -1;
}

int elpis_log_init(elpis_logdst_t dst, const char *path, elpis_loglevel_t lvl)
{
    pthread_mutex_lock(&g_lock);
    if (g_fp != NULL && g_fp != stderr) {
        fclose(g_fp);
        g_fp = NULL;
    }
    g_dst   = dst;
    g_level = lvl;
    g_path[0] = '\0';

    if (dst == ELPIS_LOG_DST_FILE && path != NULL && *path != '\0') {
        elpis_strlcpy(g_path, path, sizeof g_path);
        g_fp = fopen(g_path, "ae");
        if (g_fp == NULL)
            g_fp = fopen(g_path, "a");
        if (g_fp == NULL) {
            g_dst = ELPIS_LOG_DST_STDERR;
            g_fp  = stderr;
            pthread_mutex_unlock(&g_lock);
            elpis_error("cannot open log file '%s': %s", path, strerror(errno));
            return -1;
        }
        setvbuf(g_fp, NULL, _IOLBF, 8192);
    } else if (dst == ELPIS_LOG_DST_SYSLOG) {
#if !defined(_WIN32)
        if (!g_syslog_open) {
            openlog("elpis", LOG_PID | LOG_NDELAY, LOG_DAEMON);
            g_syslog_open = 1;
        }
#endif
    } else {
        g_fp = stderr;
    }
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void elpis_log_set_level(elpis_loglevel_t lvl) { g_level = lvl; }

void elpis_log_reopen(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_dst == ELPIS_LOG_DST_FILE && g_path[0] != '\0') {
        FILE *nf = fopen(g_path, "ae");
        if (nf == NULL)
            nf = fopen(g_path, "a");
        if (nf != NULL) {
            if (g_fp && g_fp != stderr)
                fclose(g_fp);
            g_fp = nf;
            setvbuf(g_fp, NULL, _IOLBF, 8192);
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void elpis_log_fini(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_fp && g_fp != stderr) {
        fflush(g_fp);
        fclose(g_fp);
    }
    g_fp = NULL;
#if !defined(_WIN32)
    if (g_syslog_open) {
        closelog();
        g_syslog_open = 0;
    }
#endif
    pthread_mutex_unlock(&g_lock);
}

static const char *basename_of(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

#if !defined(_WIN32)
static int syslog_prio(elpis_loglevel_t l)
{
    switch (l) {
    case ELPIS_LOG_FATAL: return LOG_CRIT;
    case ELPIS_LOG_ERROR: return LOG_ERR;
    case ELPIS_LOG_WARN:  return LOG_WARNING;
    case ELPIS_LOG_INFO:  return LOG_INFO;
    default:              return LOG_DEBUG;
    }
}
#endif

static void log_emit(elpis_loglevel_t lvl, const char *file, int line,
                     const char *fmt, va_list ap)
{
    char msg[2048];
    int n;

    n = vsnprintf(msg, sizeof msg, fmt, ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof msg)
        elpis_strlcpy(msg + sizeof msg - 5, "...", 5);

    if (g_dst == ELPIS_LOG_DST_NONE)
        return;

#if !defined(_WIN32)
    if (g_dst == ELPIS_LOG_DST_SYSLOG) {
        syslog(syslog_prio(lvl), "%s", msg);
        return;
    }
#endif
    {
        struct timespec ts;
        struct tm tmv;
        char stamp[64];
        FILE *fp;

        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            ts.tv_sec  = time(NULL);
            ts.tv_nsec = 0;
        }
#if defined(_POSIX_VERSION)
        if (gmtime_r(&ts.tv_sec, &tmv) == NULL)
            memset(&tmv, 0, sizeof tmv);
#else
        tmv = *gmtime(&ts.tv_sec);
#endif
        snprintf(stamp, sizeof stamp, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                 tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                 tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                 (long)((ts.tv_nsec / 1000000) % 1000));

        pthread_mutex_lock(&g_lock);
        fp = g_fp ? g_fp : stderr;
        if (lvl >= ELPIS_LOG_DEBUG)
            fprintf(fp, "%s %-5s [%s:%d] %s\n", stamp, k_level_name[lvl],
                    basename_of(file), line, msg);
        else
            fprintf(fp, "%s %-5s %s\n", stamp, k_level_name[lvl], msg);
        if (lvl <= ELPIS_LOG_ERROR)
            fflush(fp);
        pthread_mutex_unlock(&g_lock);
    }
}

void elpis_logf(elpis_loglevel_t lvl, const char *file, int line,
                const char *fmt, ...)
{
    va_list ap;
    if (lvl > g_level)
        return;
    va_start(ap, fmt);
    log_emit(lvl, file, line, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* Rate limiting                                                       */
/* ------------------------------------------------------------------ */

#define RL_WINDOW_MS 10000u
#define RL_BURST     5u

typedef struct {
    uint64_t window_start;
    uint32_t emitted;
    uint32_t suppressed;
} rl_slot_t;

static rl_slot_t g_rl[ELPIS_LOG_RL_SLOTS];
static pthread_mutex_t g_rl_lock = PTHREAD_MUTEX_INITIALIZER;

/* Returns 1 when the caller may log; fills `note` with a suppression tail. */
static int rl_allow(int slot, char *note, size_t notesz)
{
    uint64_t now = elpis_cached_now_ms();
    rl_slot_t *s;
    int allow;

    note[0] = '\0';
    if (slot < 0 || slot >= ELPIS_LOG_RL_SLOTS)
        return 1;
    s = &g_rl[slot];

    pthread_mutex_lock(&g_rl_lock);
    if (now - s->window_start >= RL_WINDOW_MS) {
        uint32_t sup = s->suppressed;
        s->window_start = now;
        s->emitted      = 0;
        s->suppressed   = 0;
        if (sup)
            snprintf(note, notesz, " (+%u suppressed in the last %us)",
                     (unsigned)sup, (unsigned)(RL_WINDOW_MS / 1000));
    }
    if (s->emitted < RL_BURST) {
        s->emitted++;
        allow = 1;
    } else {
        s->suppressed++;
        allow = 0;
    }
    pthread_mutex_unlock(&g_rl_lock);
    return allow;
}

void elpis_logf_rl(elpis_loglevel_t lvl, int slot, const char *file, int line,
                   const char *fmt, ...)
{
    va_list ap;
    char note[64];
    char buf[2048];
    int n;

    if (lvl > g_level)
        return;
    if (!rl_allow(slot, note, sizeof note))
        return;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (note[0] != '\0')
        elpis_strlcat(buf, note, sizeof buf);
    elpis_logf(lvl, file, line, "%s", buf);
}

/* ------------------------------------------------------------------ */
/* Malformed-input accounting                                          */
/* ------------------------------------------------------------------ */

static const char *const k_drop_name[ELPIS_DROP__MAX] = {
    "none", "short", "qr-set", "opcode", "qdcount", "name", "compress",
    "trailing", "rdlength", "rdata", "class", "edns", "tsig", "multi-opt",
    "spoof", "acl", "ratelimit", "oversize", "loop", "resource"
};

const char *elpis_drop_name(elpis_drop_t d)
{
    if ((unsigned)d >= ELPIS_DROP__MAX)
        return "?";
    return k_drop_name[d];
}

static uint64_t g_drop_count[ELPIS_DROP__MAX];

uint64_t elpis_drop_count(elpis_drop_t reason)
{
    if ((unsigned)reason >= ELPIS_DROP__MAX)
        return 0;
    return elpis_atomic_load64(&g_drop_count[reason]);
}

uint64_t elpis_drop_total(void)
{
    uint64_t t = 0;
    int i;
    for (i = 1; i < ELPIS_DROP__MAX; i++)
        t += elpis_atomic_load64(&g_drop_count[i]);
    return t;
}

/* Render the first bytes of the offending datagram; invaluable for triage. */
static void hexdump_head(const uint8_t *w, size_t len, char *out, size_t sz)
{
    static const char hx[] = "0123456789abcdef";
    size_t n = ELPIS_MIN(len, (size_t)24);
    size_t i, o = 0;

    if (w == NULL || len == 0 || sz < 4) {
        if (sz) out[0] = '\0';
        return;
    }
    for (i = 0; i < n && o + 3 < sz; i++) {
        out[o++] = hx[w[i] >> 4];
        out[o++] = hx[w[i] & 0x0F];
    }
    if (n < len && o + 3 < sz) {
        out[o++] = '.'; out[o++] = '.'; out[o++] = '.';
    }
    out[o] = '\0';
}

void elpis_drop_log_quiet(elpis_drop_t reason, const void *addr,
                          const uint8_t *wire, size_t len, const char *detail)
{
    char abuf[80];
    char hbuf[64];

    if ((unsigned)reason >= ELPIS_DROP__MAX)
        reason = ELPIS_DROP_NONE;
    elpis_atomic_add64(&g_drop_count[reason], 1);

    if (g_level < ELPIS_LOG_DEBUG)
        return;
    if (addr != NULL)
        elpis_addr_str((const elpis_addr_t *)addr, abuf, sizeof abuf);
    else
        elpis_strlcpy(abuf, "-", sizeof abuf);
    hexdump_head(wire, len, hbuf, sizeof hbuf);
    elpis_logf_rl(ELPIS_LOG_DEBUG, (int)reason, __FILE__, __LINE__,
                  "drop reason=%s from=%s len=%zu%s%s head=%s",
                  elpis_drop_name(reason), abuf, len,
                  detail ? " detail=" : "", detail ? detail : "", hbuf);
}

void elpis_drop_log(elpis_drop_t reason, const void *addr,
                    const uint8_t *wire, size_t len, const char *detail)
{
    char abuf[80];
    char hbuf[64];

    if ((unsigned)reason >= ELPIS_DROP__MAX)
        reason = ELPIS_DROP_NONE;
    elpis_atomic_add64(&g_drop_count[reason], 1);

    if (g_level < ELPIS_LOG_WARN)
        return;

    if (addr != NULL)
        elpis_addr_str((const elpis_addr_t *)addr, abuf, sizeof abuf);
    else
        elpis_strlcpy(abuf, "-", sizeof abuf);

    hexdump_head(wire, len, hbuf, sizeof hbuf);

    /* One rate-limit slot per drop reason. */
    elpis_logf_rl(ELPIS_LOG_WARN, (int)reason, __FILE__, __LINE__,
                  "drop reason=%s from=%s len=%zu%s%s head=%s",
                  elpis_drop_name(reason), abuf, len,
                  detail ? " detail=" : "", detail ? detail : "", hbuf);
}
