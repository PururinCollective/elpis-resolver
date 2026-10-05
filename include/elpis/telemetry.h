/*
 * elpis/telemetry.h -- the numbers the status page is made of.
 *
 * Counters in elpis_stats_t answer "how many since start".  A person looking
 * at a resolver wants "what is it doing now" and "what is going wrong", which
 * needs three more things: a second-by-second history to draw, a running
 * tally of which names and which clients are responsible, and the recent log.
 *
 * The hot path must not pay for any of it.  Each worker keeps its own tables
 * and touches them without a lock, because only that worker ever does; once a
 * second the maintenance tick folds them into the shared copy under one mutex.
 * Nothing here is ever read from a worker thread.
 */
#ifndef ELPIS_TELEMETRY_H
#define ELPIS_TELEMETRY_H

#include "elpis/common.h"
#include "elpis/util.h"
#include "elpis/name.h"

#define ELPIS_TM_HISTORY  180u   /* seconds of 1 Hz history kept          */
#define ELPIS_TM_SLOTS    256u   /* tracked keys per table per worker     */
#define ELPIS_TM_KEYLEN   63u    /* key text kept, truncated for display  */
#define ELPIS_TM_LOGRING  256u   /* recent log lines kept for the page    */
#define ELPIS_TM_LOGLEN   200u

typedef enum {
    ELPIS_TOP_QNAME = 0,      /* busiest names                            */
    ELPIS_TOP_SERVFAIL,       /* names that ended in SERVFAIL             */
    ELPIS_TOP_BOGUS,          /* names that failed DNSSEC validation      */
    ELPIS_TOP_CLIENT,         /* busiest clients                          */
    ELPIS_TOP_CLIENT_FAIL,    /* clients being handed SERVFAIL            */
    ELPIS_TOP_CLIENT_BOGUS,   /* clients asking for bogus names           */
    ELPIS_TOP_TIMEOUT,        /* upstream servers that stopped answering  */
    ELPIS_TOP_HELD_ZONE,      /* zones answered SERVFAIL because held     */
    ELPIS_TOP__COUNT
} elpis_top_t;

typedef struct {
    uint64_t hash;
    uint64_t count;
    char     key[ELPIS_TM_KEYLEN + 1];
} elpis_tmslot_t;

typedef struct {
    elpis_tmslot_t slot[ELPIS_TM_SLOTS];
} elpis_tmtab_t;

/* Per-worker, lock-free: only the owning worker writes, and only in its own
 * thread.  `dirty` lets the merge skip tables nothing touched. */
typedef struct {
    elpis_tmtab_t tab[ELPIS_TOP__COUNT];
    uint64_t      rtt_sum_us;      /* client-visible service time, all    */
    uint64_t      rtt_count;
    uint64_t      rec_sum_us;      /* ... and for the ones that recursed  */
    uint64_t      rec_count;
    uint64_t      rx_bytes, tx_bytes;
    uint64_t      verifies;        /* signature verifications this second */
    unsigned      dirty : 1;
} elpis_wtm_t;

/* One second of history. */
typedef struct {
    uint64_t queries, servfail, bogus, cache_hits, upstream;
    uint64_t rx_bytes, tx_bytes;
    uint32_t rtt_us;               /* mean over the second, all answers   */
    uint32_t rec_us;               /* ... and over the ones that recursed */
    uint64_t rtt_n, rec_n;         /* how many each mean was taken over   */
    uint32_t cpu_milli;            /* 1000 = one core fully busy          */
    uint64_t rss_bytes;
    uint64_t verifies;             /* public-key verifications per second */
} elpis_tmsample_t;

typedef struct {
    char     key[ELPIS_TM_KEYLEN + 1];
    uint64_t count;
} elpis_tmrow_t;

/*
 * Servers held down (server-hold-down), and what set each one off.
 *
 * Kept apart from the top-N tables because a hold is an event with a story,
 * not a count: which zone was being asked, for which client, and when.  It is
 * also rare -- a held server is not asked again until its hold runs out -- so
 * the worker writes it under the lock directly instead of batching it.
 *
 * What the hold is doing now is not kept here.  The infra cache has that, and
 * the page reads it from there, so the two cannot disagree.
 */
#define ELPIS_TM_HELD     64u
#define ELPIS_TM_ADDRLEN  48u

typedef struct {
    char     client[ELPIS_TM_ADDRLEN];   /* address, or what asked instead */
    char     qname[ELPIS_TM_KEYLEN + 1]; /* the client's question          */
    uint16_t qtype;
    uint8_t  is_client;                  /* `client` is an address         */
    uint32_t at;                         /* monotonic seconds              */
} elpis_tmasker_t;

typedef struct {
    elpis_addr_t    server;
    char            zone[ELPIS_TM_KEYLEN + 1];  /* "" when not known       */
    uint32_t        streak;    /* the server's silent_since: one silence   */
    uint32_t        holds;     /* times held or held longer in it          */
    uint8_t         types;     /* ELPIS_QC_* held, at the latest hold      */
    elpis_tmasker_t first;     /* whose query first held it                */
    elpis_tmasker_t last;      /* ... and most recently                    */
} elpis_tmheld_t;

/*
 * Servers that speak DoT (authoritative-dot:), for the status page's DoT
 * window.  A row starts with a server's first finished handshake.  Rows are
 * written under the lock, but only on rare events -- a handshake, a failure
 * -- and with answers counted by the connection and handed over in batches,
 * so a DoT answer takes no lock.  Whether DoT stands for a server now is
 * read from the infra cache, as it is for held servers.
 */
#define ELPIS_TM_DOT      256u

typedef struct {
    elpis_addr_t server;
    char         zone[ELPIS_TM_KEYLEN + 1];   /* last asked over DoT        */
    uint64_t     answers;    /* DNS answers read over DoT                  */
    uint32_t     hs_ms;      /* the last full handshake                    */
    uint16_t     suite;
    uint32_t     last;       /* last handshake or answer, monotonic seconds */
    uint32_t     fails;      /* times DoT failed after it had worked       */
} elpis_tmdot_t;

/* What was waiting on the query whose timeout held a server. */
typedef struct {
    const elpis_addr_t *server;
    const elpis_name_t *zone;      /* the delegation being asked, or NULL  */
    const elpis_name_t *qname;     /* the client's question, or NULL       */
    uint16_t            qtype;
    const elpis_addr_t *client;    /* NULL when no client was waiting ...  */
    const char         *who;       /* ... and this says what asked instead */
    uint32_t            streak;
    uint8_t             types;
    uint32_t            now;
} elpis_tmhold_t;

/*
 * Counting every query exactly is worth about a tenth of peak throughput, so
 * nothing is counted at all until the status page is switched on.  The flag is
 * read on the hot path and never written after startup.
 */
extern int elpis_tm_enabled;
void elpis_tm_init(int enabled);

/* ---- hot path (worker-local, no locks) ---- */

/*
 * Every answer is counted, and counted exactly -- sampling was tried and it
 * is useless here: a resolver answering a few hundred queries a second gives
 * too few samples to rank anything, which is precisely when someone is
 * looking at the page.
 *
 * What makes that affordable is hashing the wire name and the raw address
 * rather than their text.  A name is turned into characters once, the first
 * time it is seen; every later query for it finds the slot by hash and adds
 * one, touching no formatting at all.
 */
void elpis_tm_observe(elpis_wtm_t *w, uint64_t service_us, int recursed);
/* Signature verifications the worker did since the last publish. */
void elpis_tm_verified(elpis_wtm_t *w, uint64_t n);
void elpis_tm_answer(elpis_wtm_t *w, const elpis_name_t *qname,
                     const elpis_addr_t *client, unsigned rcode, int bogus);
/* Record an upstream server that failed to answer. */
void elpis_tm_timeout(elpis_wtm_t *w, const elpis_addr_t *server);
/* A server was held, or held for longer.  Takes the lock; see above. */
void elpis_tm_held(const elpis_tmhold_t *h);
/* DoT to a server: a handshake finished, answers were read, or it failed
 * (`state` being what the server was left in, ELPIS_DOT_*).  Lock taken. */
void elpis_tm_dot_handshake(const elpis_addr_t *server, uint16_t suite,
                            uint32_t ms, uint32_t now);
void elpis_tm_dot_answers(const elpis_addr_t *server, const elpis_name_t *zone,
                          uint32_t n, uint32_t now);
void elpis_tm_dot_failed(const elpis_addr_t *server, int state, uint32_t now);
/* A resolution in `zone` ended at once because its servers were held. */
void elpis_tm_turned_away(elpis_wtm_t *w, const elpis_name_t *zone);
/* Bytes on the wire, counted where they are already being measured. */
void elpis_tm_bytes(elpis_wtm_t *w, uint64_t rx, uint64_t tx);

/* Fold a worker's tables into the shared copy and reset them. */
void elpis_tm_publish(elpis_wtm_t *w);

/* ---- reader side (the status page's thread) ---- */

/* Take one second's sample; call once a second from a single thread. */
void elpis_tm_tick(const void *ctx);

/* Copy the history newest-last.  Returns how many samples were written. */
unsigned elpis_tm_history(elpis_tmsample_t *out, unsigned max);

/* Copy the top `max` rows of one table, largest first. */
unsigned elpis_tm_top(elpis_top_t which, elpis_tmrow_t *out, unsigned max);

/* Copy the held-server rows, most recently held first. */
unsigned elpis_tm_held_rows(elpis_tmheld_t *out, unsigned max);

/* Copy the DoT rows, most answers first. */
unsigned elpis_tm_dot_rows(elpis_tmdot_t *out, unsigned max);

/* A zone name as the tables write it: lowercase, truncated to fit. */
void elpis_tm_name_text(const elpis_name_t *n, char *out, size_t outsz);

/* Recent log lines, oldest first. */
unsigned elpis_tm_log(char out[][ELPIS_TM_LOGLEN], unsigned max);

/* Called by log.c for anything worth showing on the page. */
void elpis_tm_log_add(const char *level, const char *msg);

/* Process CPU and resident size, sampled at the last tick. */
void elpis_tm_process(uint32_t *cpu_milli, uint64_t *rss_bytes);

#endif /* ELPIS_TELEMETRY_H */
