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
} elpis_tmsample_t;

typedef struct {
    char     key[ELPIS_TM_KEYLEN + 1];
    uint64_t count;
} elpis_tmrow_t;

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
void elpis_tm_answer(elpis_wtm_t *w, const elpis_name_t *qname,
                     const elpis_addr_t *client, unsigned rcode, int bogus);
/* Record an upstream server that failed to answer. */
void elpis_tm_timeout(elpis_wtm_t *w, const elpis_addr_t *server);
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

/* Recent log lines, oldest first. */
unsigned elpis_tm_log(char out[][ELPIS_TM_LOGLEN], unsigned max);

/* Called by log.c for anything worth showing on the page. */
void elpis_tm_log_add(const char *level, const char *msg);

/* Process CPU and resident size, sampled at the last tick. */
void elpis_tm_process(uint32_t *cpu_milli, uint64_t *rss_bytes);

#endif /* ELPIS_TELEMETRY_H */
