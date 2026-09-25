/*
 * cache.c -- sharded open-addressing cache with SIMD group probing.
 */
#include "elpis/cache.h"
#include "elpis/simd.h"
#include "elpis/util.h"
#include "elpis/log.h"
#include "elpis/atomic.h"

#include <pthread.h>

#define CTRL_EMPTY   0x80u
#define CTRL_DELETED 0xFEu
#define IS_FULL(c)   (((c) & 0x80u) == 0u)

/* Grow when the table is 7/8 loaded (counting tombstones). */
#define LOAD_NUM 7
#define LOAD_DEN 8

#define MIN_CAP  64u

typedef struct {
    pthread_rwlock_t lock;
    uint8_t  *ctrl;       /* cap + ELPIS_GROUP bytes, mirrored tail */
    void    **slots;
    uint32_t  cap;        /* power of two                            */
    uint32_t  used;
    uint32_t  tomb;
    uint32_t  hand;       /* CLOCK sweep position                    */
    uint64_t  bytes;
    uint64_t  bytes_max;
    uint64_t  hits, misses, inserts, evictions, expired, collisions;
    uint32_t  pinned_entries;
    uint64_t  pinned_bytes;
} shard_t;

struct elpis_cache {
    char                 name[32];
    unsigned             nshards;
    unsigned             shard_shift;
    shard_t             *sh;
    elpis_cache_free_fn  freefn;
    elpis_cache_eq_fn    eqfn;
    elpis_cache_carry_fn carryfn;
    uint64_t             bytes_max;
};

ELPIS_INLINE elpis_chdr_t *hdr_of(void *e) { return (elpis_chdr_t *)e; }

/* Split the hash: low 7 bits are the tag, the rest picks the group. */
ELPIS_INLINE uint8_t h2(uint64_t h) { return (uint8_t)(h & 0x7Fu); }
ELPIS_INLINE uint64_t h1(uint64_t h) { return h >> 7; }

/* ------------------------------------------------------------------ */
/* Table primitives (caller holds the appropriate lock)                */
/* ------------------------------------------------------------------ */

static int shard_alloc(shard_t *s, uint32_t cap)
{
    uint8_t *ctrl = (uint8_t *)elpis_malloc((size_t)cap + ELPIS_GROUP);
    void   **slots = (void **)elpis_calloc(cap, sizeof(void *));

    if (ctrl == NULL || slots == NULL) {
        elpis_free(ctrl);
        elpis_free(slots);
        return ELPIS_ENOMEM;
    }
    memset(ctrl, CTRL_EMPTY, (size_t)cap + ELPIS_GROUP);
    s->ctrl  = ctrl;
    s->slots = slots;
    s->cap   = cap;
    s->used  = 0;
    s->tomb  = 0;
    s->hand  = 0;
    return ELPIS_OK;
}

/* Keep the mirrored tail in step so a group read never runs off the end. */
ELPIS_INLINE void ctrl_set(shard_t *s, uint32_t i, uint8_t v)
{
    s->ctrl[i] = v;
    if (i < ELPIS_GROUP)
        s->ctrl[s->cap + i] = v;
}

static void *find_slot(const elpis_cache_t *c, shard_t *s, uint64_t hash,
                       const void *key, uint32_t *idx_out)
{
    uint32_t mask = s->cap - 1u;
    uint32_t pos  = (uint32_t)(h1(hash) & mask);
    uint8_t  tag  = h2(hash);
    uint32_t step = 0;

    for (;;) {
        uint32_t g = pos & mask;
        uint32_t m = elpis_group_match(s->ctrl + g, tag);

        while (m) {
            unsigned b = elpis_ctz32(m);
            uint32_t i = (g + b) & mask;
            void *e = s->slots[i];
            if (e != NULL && hdr_of(e)->hash == hash && c->eqfn(e, key)) {
                if (idx_out) *idx_out = i;
                return e;
            }
            m &= m - 1u;
        }

        /* An empty control byte in the group ends the probe chain. */
        {
            uint32_t sp = elpis_group_special(s->ctrl + g);
            uint32_t emptyish = 0;
            while (sp) {
                unsigned b = elpis_ctz32(sp);
                if (s->ctrl[g + b] == CTRL_EMPTY)
                    emptyish |= 1u << b;
                sp &= sp - 1u;
            }
            if (emptyish)
                return NULL;
        }

        step += ELPIS_GROUP;
        if (step > s->cap)
            return NULL;
        pos = (g + ELPIS_GROUP) & mask;
    }
}

/* First free (empty or tombstone) slot on the probe path for `hash`. */
static int find_free(shard_t *s, uint64_t hash, uint32_t *out)
{
    uint32_t mask = s->cap - 1u;
    uint32_t pos  = (uint32_t)(h1(hash) & mask);
    uint32_t step = 0;

    for (;;) {
        uint32_t g = pos & mask;
        uint32_t sp = elpis_group_special(s->ctrl + g);
        if (sp) {
            *out = (g + elpis_ctz32(sp)) & mask;
            return ELPIS_OK;
        }
        step += ELPIS_GROUP;
        if (step > s->cap)
            return ELPIS_ERR;
        pos = (g + ELPIS_GROUP) & mask;
    }
}

static int shard_rehash(const elpis_cache_t *c, shard_t *s, uint32_t newcap)
{
    uint8_t *octrl = s->ctrl;
    void   **oslots = s->slots;
    uint32_t ocap = s->cap;
    uint32_t i;

    (void)c;
    if (shard_alloc(s, newcap) != ELPIS_OK) {
        s->ctrl = octrl;
        s->slots = oslots;
        s->cap = ocap;
        return ELPIS_ENOMEM;
    }
    for (i = 0; i < ocap; i++) {
        void *e;
        uint32_t slot;
        if (!IS_FULL(octrl[i]))
            continue;
        e = oslots[i];
        if (e == NULL)
            continue;
        if (find_free(s, hdr_of(e)->hash, &slot) != ELPIS_OK) {
            /* Cannot happen: the new table is strictly larger and empty. */
            elpis_error("%s: rehash lost an entry", c->name);
            continue;
        }
        s->slots[slot] = e;
        ctrl_set(s, slot, h2(hdr_of(e)->hash));
        s->used++;
    }
    elpis_free(octrl);
    elpis_free(oslots);
    return ELPIS_OK;
}

static void slot_drop(const elpis_cache_t *c, shard_t *s, uint32_t i)
{
    void *e = s->slots[i];
    if (e == NULL)
        return;
    s->bytes -= hdr_of(e)->size;
    if (hdr_of(e)->pinned) {
        s->pinned_entries--;
        s->pinned_bytes -= hdr_of(e)->size;
    }
    c->freefn(e);
    s->slots[i] = NULL;
    ctrl_set(s, i, CTRL_DELETED);
    s->used--;
    s->tomb++;
}

/*
 * CLOCK eviction: sweep forward, clearing reference bits, taking the first
 * unreferenced unpinned entry.  Expired entries are taken immediately.
 */
static int shard_evict_one(const elpis_cache_t *c, shard_t *s, uint32_t now)
{
    uint32_t scanned = 0;
    uint32_t limit = s->cap * 2u;

    while (scanned++ < limit) {
        uint32_t i = s->hand;
        s->hand = (s->hand + 1u) & (s->cap - 1u);

        if (!IS_FULL(s->ctrl[i]) || s->slots[i] == NULL)
            continue;
        {
            elpis_chdr_t *h = hdr_of(s->slots[i]);
            if (h->expiry != 0 && h->expiry <= now) {
                slot_drop(c, s, i);
                s->expired++;
                return ELPIS_OK;
            }
            if (h->pinned)
                continue;
            if (h->ref) {
                h->ref = 0;
                continue;
            }
            slot_drop(c, s, i);
            s->evictions++;
            return ELPIS_OK;
        }
    }
    return ELPIS_ERR;      /* everything is pinned or referenced */
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

static unsigned round_pow2(unsigned v)
{
    unsigned p = 1;
    while (p < v && p < (1u << 20))
        p <<= 1;
    return p;
}

elpis_cache_t *elpis_cache_new(const char *name, uint64_t bytes_max,
                               unsigned shards,
                               elpis_cache_free_fn freefn,
                               elpis_cache_eq_fn eqfn)
{
    elpis_cache_t *c;
    unsigned i;

    if (shards == 0)
        shards = 16;
    shards = round_pow2(shards);
    if (shards > 4096)
        shards = 4096;

    c = (elpis_cache_t *)elpis_calloc(1, sizeof *c);
    if (c == NULL)
        return NULL;
    elpis_strlcpy(c->name, name ? name : "cache", sizeof c->name);
    c->nshards   = shards;
    c->freefn    = freefn;
    c->eqfn      = eqfn;
    c->bytes_max = bytes_max;
    c->sh = (shard_t *)elpis_calloc(shards, sizeof(shard_t));
    if (c->sh == NULL) {
        elpis_free(c);
        return NULL;
    }
    for (i = 0; i < shards; i++) {
        if (pthread_rwlock_init(&c->sh[i].lock, NULL) != 0)
            goto fail;
        if (shard_alloc(&c->sh[i], MIN_CAP) != ELPIS_OK)
            goto fail;
        c->sh[i].bytes_max = bytes_max / shards;
        if (c->sh[i].bytes_max < 64u * 1024u)
            c->sh[i].bytes_max = 64u * 1024u;
    }
    elpis_info("%s: %u shards, budget %llu MiB", c->name, shards,
               (unsigned long long)(bytes_max / (1024 * 1024)));
    return c;

fail:
    elpis_cache_free(c);
    return NULL;
}

void elpis_cache_free(elpis_cache_t *c)
{
    unsigned i;
    if (c == NULL)
        return;
    if (c->sh != NULL) {
        for (i = 0; i < c->nshards; i++) {
            shard_t *s = &c->sh[i];
            uint32_t j;
            if (s->slots != NULL) {
                for (j = 0; j < s->cap; j++)
                    if (s->slots[j] != NULL)
                        c->freefn(s->slots[j]);
            }
            elpis_free(s->ctrl);
            elpis_free(s->slots);
            pthread_rwlock_destroy(&s->lock);
        }
        elpis_free(c->sh);
    }
    elpis_free(c);
}

ELPIS_INLINE unsigned shard_of(const elpis_cache_t *c, uint64_t hash)
{
    /* Use the high bits: the low bits already select the group. */
    return (unsigned)((hash >> 48) & (uint64_t)(c->nshards - 1u));
}

void *elpis_cache_read_begin(elpis_cache_t *c, uint64_t hash, const void *key,
                             unsigned *shard)
{
    unsigned si = shard_of(c, hash);
    shard_t *s = &c->sh[si];
    void *e;

    pthread_rwlock_rdlock(&s->lock);
    e = find_slot(c, s, hash, key, NULL);
    if (e == NULL) {
        pthread_rwlock_unlock(&s->lock);
        elpis_atomic_add64(&s->misses, 1);
        return NULL;
    }
    /*
     * Setting the CLOCK bit under a shared lock is a deliberate benign race:
     * concurrent readers may both store 1, and an evictor may clear it just
     * after.  The worst outcome is one extra sweep before the entry is taken.
     */
    hdr_of(e)->ref = 1;
    elpis_atomic_add64(&s->hits, 1);
    *shard = si;
    return e;
}

void elpis_cache_read_end(elpis_cache_t *c, unsigned shard)
{
    pthread_rwlock_unlock(&c->sh[shard].lock);
}

void *elpis_cache_peek_begin(elpis_cache_t *c, uint64_t hash, const void *key,
                             unsigned *shard)
{
    unsigned si = shard_of(c, hash);
    shard_t *s = &c->sh[si];
    void *e;

    pthread_rwlock_rdlock(&s->lock);
    e = find_slot(c, s, hash, key, NULL);
    if (e == NULL) {
        pthread_rwlock_unlock(&s->lock);
        return NULL;
    }
    *shard = si;
    return e;
}

void elpis_cache_set_carry(elpis_cache_t *c, elpis_cache_carry_fn fn)
{
    c->carryfn = fn;
}

int elpis_cache_insert(elpis_cache_t *c, void *entry, const void *key)
{
    elpis_chdr_t *h = hdr_of(entry);
    unsigned si = shard_of(c, h->hash);
    shard_t *s = &c->sh[si];
    uint32_t idx;
    void *old;
    uint32_t now = elpis_cached_now_s();

    pthread_rwlock_wrlock(&s->lock);

    old = find_slot(c, s, h->hash, key, &idx);
    if (old != NULL) {
        if (c->carryfn != NULL)
            c->carryfn(entry, old);
        s->bytes -= hdr_of(old)->size;
        if (hdr_of(old)->pinned) {
            s->pinned_entries--;
            s->pinned_bytes -= hdr_of(old)->size;
        }
        c->freefn(old);
        s->slots[idx] = entry;
        s->bytes += h->size;
        if (h->pinned) {
            s->pinned_entries++;
            s->pinned_bytes += h->size;
        }
        s->inserts++;
        pthread_rwlock_unlock(&s->lock);
        return ELPIS_OK;
    }

    /* Make room before growing: budget first, then load factor. */
    while (s->bytes + h->size > s->bytes_max) {
        if (shard_evict_one(c, s, now) != ELPIS_OK)
            break;
    }
    /*
     * Pinned entries (root and TLD delegations) are admitted unconditionally:
     * losing them is what we built the pin for.  Everything else is refused
     * when the shard cannot be brought back under budget.
     */
    if (s->bytes + h->size > s->bytes_max && !h->pinned) {
        pthread_rwlock_unlock(&s->lock);
        c->freefn(entry);
        return ELPIS_ENOMEM;
    }

    if ((uint64_t)(s->used + s->tomb + 1u) * LOAD_DEN >
        (uint64_t)s->cap * LOAD_NUM) {
        uint32_t newcap = (s->used + 1u) * 2u > s->cap ? s->cap * 2u : s->cap;
        if (newcap < MIN_CAP)
            newcap = MIN_CAP;
        if (shard_rehash(c, s, newcap) != ELPIS_OK) {
            pthread_rwlock_unlock(&s->lock);
            c->freefn(entry);
            return ELPIS_ENOMEM;
        }
    }

    if (find_free(s, h->hash, &idx) != ELPIS_OK) {
        pthread_rwlock_unlock(&s->lock);
        c->freefn(entry);
        return ELPIS_ENOMEM;
    }
    if (s->ctrl[idx] == CTRL_DELETED && s->tomb > 0)
        s->tomb--;
    s->slots[idx] = entry;
    ctrl_set(s, idx, h2(h->hash));
    s->used++;
    s->bytes += h->size;
    if (h->pinned) {
        s->pinned_entries++;
        s->pinned_bytes += h->size;
    }
    s->inserts++;
    pthread_rwlock_unlock(&s->lock);
    return ELPIS_OK;
}

int elpis_cache_remove(elpis_cache_t *c, uint64_t hash, const void *key)
{
    unsigned si = shard_of(c, hash);
    shard_t *s = &c->sh[si];
    uint32_t idx;
    void *e;
    int rc = ELPIS_ENOTFOUND;

    pthread_rwlock_wrlock(&s->lock);
    e = find_slot(c, s, hash, key, &idx);
    if (e != NULL) {
        slot_drop(c, s, idx);
        rc = ELPIS_OK;
    }
    pthread_rwlock_unlock(&s->lock);
    return rc;
}

void elpis_cache_flush(elpis_cache_t *c)
{
    unsigned i;
    for (i = 0; i < c->nshards; i++) {
        shard_t *s = &c->sh[i];
        uint32_t j;
        pthread_rwlock_wrlock(&s->lock);
        for (j = 0; j < s->cap; j++)
            if (IS_FULL(s->ctrl[j]) && s->slots[j] != NULL)
                slot_drop(c, s, j);
        s->tomb = 0;
        memset(s->ctrl, CTRL_EMPTY, (size_t)s->cap + ELPIS_GROUP);
        pthread_rwlock_unlock(&s->lock);
    }
}

uint64_t elpis_cache_expire(elpis_cache_t *c, uint32_t now, unsigned budget)
{
    unsigned i;
    uint64_t n = 0;
    unsigned per = budget / (c->nshards ? c->nshards : 1u);

    if (per == 0)
        per = 16;
    for (i = 0; i < c->nshards; i++) {
        shard_t *s = &c->sh[i];
        unsigned k;
        if (pthread_rwlock_trywrlock(&s->lock) != 0)
            continue;            /* busy; try again next tick */
        for (k = 0; k < per; k++) {
            uint32_t j = s->hand;
            s->hand = (s->hand + 1u) & (s->cap - 1u);
            if (!IS_FULL(s->ctrl[j]) || s->slots[j] == NULL)
                continue;
            {
                elpis_chdr_t *h = hdr_of(s->slots[j]);
                if (h->expiry != 0 && h->expiry <= now) {
                    slot_drop(c, s, j);
                    s->expired++;
                    n++;
                }
            }
        }
        pthread_rwlock_unlock(&s->lock);
    }
    return n;
}

void elpis_cache_walk(elpis_cache_t *c, elpis_cache_visit_fn fn, void *arg)
{
    unsigned i;

    for (i = 0; i < c->nshards; i++) {
        shard_t *s = &c->sh[i];
        uint32_t j;
        pthread_rwlock_rdlock(&s->lock);
        for (j = 0; j < s->cap; j++)
            if (IS_FULL(s->ctrl[j]) && s->slots[j] != NULL)
                fn(s->slots[j], arg);
        pthread_rwlock_unlock(&s->lock);
    }
}

void elpis_cache_stats(const elpis_cache_t *c, elpis_cache_stats_t *out)
{
    unsigned i;
    memset(out, 0, sizeof *out);
    for (i = 0; i < c->nshards; i++) {
        shard_t *s = &c->sh[i];
        out->hits       += s->hits;
        out->misses     += s->misses;
        out->inserts    += s->inserts;
        out->evictions  += s->evictions;
        out->expired    += s->expired;
        out->collisions += s->collisions;
        out->entries    += s->used;
        out->bytes      += s->bytes;
        out->bytes_max  += s->bytes_max;
        out->capacity   += s->cap;
        out->pinned_entries += s->pinned_entries;
        out->pinned_bytes   += s->pinned_bytes;
    }
}

const char *elpis_cache_name(const elpis_cache_t *c) { return c->name; }

/* ------------------------------------------------------------------ */
/* Automatic sizing                                                    */
/* ------------------------------------------------------------------ */

void elpis_cache_plan(elpis_cache_plan_t *p, uint64_t override_total,
                      unsigned cpus)
{
    const uint64_t MB = 1024ull * 1024ull;
    const uint64_t GB = 1024ull * MB;
    uint64_t ram, budget;

    memset(p, 0, sizeof *p);
    ram = elpis_physical_ram();
    p->ram_total = ram;

    if (override_total != 0) {
        budget = override_total;
    } else if (ram == 0) {
        budget = 64 * MB;                /* unknown host: stay modest */
    } else if (ram < 512 * MB) {
        budget = ram / 8;                /* 12.5% on tiny systems     */
        if (budget < 16 * MB)
            budget = 16 * MB;
    } else if (ram < 2 * GB) {
        budget = ram / 6;                /* ~17%                      */
    } else if (ram < 8 * GB) {
        budget = ram / 5;                /* 20%                       */
    } else if (ram < 64 * GB) {
        budget = ram / 4;                /* 25%                       */
    } else {
        budget = 16 * GB;                /* past this, more is waste  */
    }
    if (budget > 32 * GB)
        budget = 32 * GB;
    if (budget < 8 * MB)
        budget = 8 * MB;

    p->budget_total = budget;

    /*
     * The message cache answers the common case with one memcpy, so it gets
     * the largest share.  The RRset cache backs the resolver itself and the
     * delegation cache holds the root and TLD data we never want to lose.
     */
    p->msg_bytes   = budget / 2;                 /* 50% */
    p->rrset_bytes = budget / 100 * 32;          /* 32% */
    p->deleg_bytes = budget / 100 * 12;          /* 12% */
    p->infra_bytes = budget - p->msg_bytes - p->rrset_bytes - p->deleg_bytes;

    if (p->deleg_bytes < 8 * MB)
        p->deleg_bytes = 8 * MB;                 /* must hold every TLD */
    if (p->infra_bytes < 2 * MB)
        p->infra_bytes = 2 * MB;

    p->shards = round_pow2(cpus ? cpus * 8u : 16u);
    if (p->shards < 16)
        p->shards = 16;
    if (p->shards > 512)
        p->shards = 512;
}
