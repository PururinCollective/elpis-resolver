/*
 * elpis/log.h -- structured, lock-light logging with per-category rate limits.
 */
#ifndef ELPIS_LOG_H
#define ELPIS_LOG_H

#include "elpis/common.h"

typedef enum {
    ELPIS_LOG_FATAL = 0,
    ELPIS_LOG_ERROR = 1,
    ELPIS_LOG_WARN  = 2,
    ELPIS_LOG_INFO  = 3,
    ELPIS_LOG_DEBUG = 4,
    ELPIS_LOG_TRACE = 5
} elpis_loglevel_t;

typedef enum {
    ELPIS_LOG_DST_STDERR = 0,
    ELPIS_LOG_DST_FILE   = 1,
    ELPIS_LOG_DST_SYSLOG = 2,
    ELPIS_LOG_DST_NONE   = 3
} elpis_logdst_t;

int  elpis_log_init(elpis_logdst_t dst, const char *path, elpis_loglevel_t lvl);
void elpis_log_set_level(elpis_loglevel_t lvl);
void elpis_log_reopen(void);          /* SIGHUP / logrotate               */
void elpis_log_fini(void);
int  elpis_log_level_parse(const char *s, elpis_loglevel_t *out);

void elpis_logf(elpis_loglevel_t lvl, const char *file, int line,
                const char *fmt, ...) ELPIS_PRINTF(4, 5);

/*
 * Rate-limited variant.  `slot` must be a distinct small integer per call
 * site; at most `burst` messages are emitted per `window_ms`, then a single
 * "suppressed N" line is emitted when the window closes.
 */
void elpis_logf_rl(elpis_loglevel_t lvl, int slot, const char *file, int line,
                   const char *fmt, ...) ELPIS_PRINTF(5, 6);

#define ELPIS_LOG_RL_SLOTS 64

#define elpis_fatal(...) elpis_logf(ELPIS_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define elpis_error(...) elpis_logf(ELPIS_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define elpis_warn(...)  elpis_logf(ELPIS_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define elpis_info(...)  elpis_logf(ELPIS_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)

#ifdef ELPIS_DEBUG
#define elpis_debug(...) elpis_logf(ELPIS_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define elpis_trace(...) elpis_logf(ELPIS_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#else
/* Compiled out entirely in release builds, but still type-checked. */
#define elpis_debug(...) do { if (0) elpis_logf(ELPIS_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__); } while (0)
#define elpis_trace(...) do { if (0) elpis_logf(ELPIS_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__); } while (0)
#endif

/* ------------------------------------------------------------------ */
/* Malformed-input accounting                                          */
/* ------------------------------------------------------------------ */
typedef enum {
    ELPIS_DROP_NONE = 0,
    ELPIS_DROP_SHORT,            /* shorter than a DNS header            */
    ELPIS_DROP_QR_SET,           /* response arrived on the server port   */
    ELPIS_DROP_OPCODE,           /* unsupported opcode                    */
    ELPIS_DROP_QDCOUNT,          /* qdcount not 1                         */
    ELPIS_DROP_NAME,             /* bad label length / overlong name      */
    ELPIS_DROP_COMPRESS,         /* bad or looping compression pointer    */
    ELPIS_DROP_TRAILING,         /* junk after the last record            */
    ELPIS_DROP_RDLEN,            /* rdlength runs off the message         */
    ELPIS_DROP_RDATA,            /* rdata fails type-specific checks      */
    ELPIS_DROP_CLASS,            /* unsupported class                     */
    ELPIS_DROP_EDNS,             /* malformed OPT record                  */
    ELPIS_DROP_TSIG,             /* misplaced TSIG/SIG(0)                 */
    ELPIS_DROP_MULTI_OPT,        /* more than one OPT                     */
    ELPIS_DROP_SPOOF,            /* txid / 0x20 / port / cookie mismatch  */
    ELPIS_DROP_ACL,              /* not permitted by access control       */
    ELPIS_DROP_RATELIMIT,        /* client or response rate limit         */
    ELPIS_DROP_OVERSIZE,         /* larger than the declared TCP length   */
    ELPIS_DROP_LOOP,             /* query loop / recursion depth          */
    ELPIS_DROP_RESOURCE,         /* out of memory or descriptors          */
    ELPIS_DROP_SENDFAIL,         /* the answer could not be put on the wire */
    ELPIS_DROP__MAX
} elpis_drop_t;

const char *elpis_drop_name(elpis_drop_t d);

/* Record a dropped datagram: bumps a counter and rate-limits a log line. */
struct elpis_addr;
void elpis_drop_log(elpis_drop_t reason, const void *addr,
                    const uint8_t *wire, size_t len, const char *detail);
/* Counts the drop without a log line; for events a slow peer can trigger. */
void elpis_drop_log_quiet(elpis_drop_t reason, const void *addr,
                          const uint8_t *wire, size_t len, const char *detail);
uint64_t elpis_drop_count(elpis_drop_t reason);
uint64_t elpis_drop_total(void);

#endif /* ELPIS_LOG_H */
