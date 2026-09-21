/*
 * elpis/cache.h -- sharded open-addressing cache.
 *
 * Layout follows the "Swiss table" idea: each group of 16 slots has 16
 * control bytes holding a 7-bit tag from the hash, so one SIMD compare tests
 * sixteen candidates at once and the entry array is touched only on a tag
 * hit.  For DNS workloads that means a lookup usually costs one cache line
 * of control bytes plus one entry line.
 *
 * Replacement is CLOCK rather than LRU.  That matters: LRU needs a list
 * splice on every hit, which forces an exclusive lock on the read path.  With
 * CLOCK a hit is a single relaxed byte store, so lookups hold only a shared
 * lock and many workers read the same shard concurrently.
 *
 * Concurrency contract: a looked-up entry is only valid while the shard lock
 * is held.  Callers copy what they need before releasing.  There is no
 * refcount and no deferred reclamation to get wrong.
 */
#ifndef ELPIS_CACHE_H
#define ELPIS_CACHE_H

#include "elpis/common.h"

/* Header every cached object starts with. */
typedef struct {
    uint64_t hash;
    uint32_t expiry;     /* monotonic seconds; 0 means "no expiry"       */
    uint32_t size;       /* bytes charged against the budget             */
    uint8_t  ref;        /* CLOCK reference bit                          */
    uint8_t  pinned;     /* exempt from eviction (root and TLD data)     */
    uint16_t pad;
} elpis_chdr_t;

typedef void (*elpis_cache_free_fn)(void *entry);
typedef int  (*elpis_cache_eq_fn)(const void *entry, const void *key);

typedef struct elpis_cache elpis_cache_t;

typedef struct {
    uint64_t hits, misses, inserts, evictions, expired, collisions;
    uint64_t entries, bytes, bytes_max, pinned_entries, pinned_bytes;
    uint64_t capacity;
} elpis_cache_stats_t;

elpis_cache_t *elpis_cache_new(const char *name, uint64_t bytes_max,
                               unsigned shards,
                               elpis_cache_free_fn freefn,
                               elpis_cache_eq_fn eqfn);
void elpis_cache_free(elpis_cache_t *c);

/*
 * Shared-lock lookup.  On a hit the shard index is returned through `shard`
 * and the caller MUST call elpis_cache_read_end(c, shard).  On a miss the
 * lock is already released and `shard` is untouched.
 */
void *elpis_cache_read_begin(elpis_cache_t *c, uint64_t hash, const void *key,
                             unsigned *shard);
void  elpis_cache_read_end(elpis_cache_t *c, unsigned shard);

/* Takes ownership of `entry` (whose header is already filled in).  Replaces
 * any existing entry with the same key. */
int   elpis_cache_insert(elpis_cache_t *c, void *entry, const void *key);
int   elpis_cache_remove(elpis_cache_t *c, uint64_t hash, const void *key);
void  elpis_cache_flush(elpis_cache_t *c);

/* Remove expired entries; `budget` bounds the work per call. */
uint64_t elpis_cache_expire(elpis_cache_t *c, uint32_t now, unsigned budget);

void elpis_cache_stats(const elpis_cache_t *c, elpis_cache_stats_t *out);
const char *elpis_cache_name(const elpis_cache_t *c);

/* ------------------------------------------------------------------ */
/* Automatic sizing                                                    */
/* ------------------------------------------------------------------ */
typedef struct {
    uint64_t ram_total;
    uint64_t budget_total;
    uint64_t msg_bytes;
    uint64_t rrset_bytes;
    uint64_t infra_bytes;
    uint64_t deleg_bytes;
    unsigned shards;
} elpis_cache_plan_t;

/*
 * Derive cache budgets from host memory.  `override_total` of 0 means
 * "decide automatically"; anything else is used verbatim as the total.
 */
void elpis_cache_plan(elpis_cache_plan_t *p, uint64_t override_total,
                      unsigned cpus);

#endif /* ELPIS_CACHE_H */
