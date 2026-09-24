/*
 * rcache.c -- RRset cache.
 *
 * Entries hold the data records and their RRSIGs together.  Keeping them in
 * one object matters for the validator: a signature that arrives with its
 * RRset can never be separated from it by an eviction race.
 */
#include "elpis/store.h"
#include "elpis/util.h"
#include "elpis/simd.h"
#include "elpis/log.h"

typedef struct {
    elpis_chdr_t hdr;
    uint16_t type, klass;
    uint8_t  namelen;
    uint8_t  sec;
    uint8_t  count;
    uint8_t  sigcount;
    uint8_t  flags;
    uint8_t  zone_labels;       /* see elpis_rrset_buf_t */
    uint8_t  pad[2];
    uint32_t stored;
    uint32_t ttl;
    uint32_t datalen;
    /*
     * Trailing payload:
     *   uint8_t name[namelen]  (padded to a 4-byte boundary)
     *   (uint16_t len, uint8_t rd[len]) * (count + sigcount)
     */
} rent_t;

typedef struct {
    const elpis_name_t *name;
    uint16_t type, klass;
    uint64_t hash;
} rkey_t;

ELPIS_INLINE uint8_t *rent_name(rent_t *e) { return (uint8_t *)(e + 1); }
ELPIS_INLINE const uint8_t *rent_name_c(const rent_t *e) { return (const uint8_t *)(e + 1); }
ELPIS_INLINE uint8_t *rent_data(rent_t *e)
{
    return rent_name(e) + ((e->namelen + 3u) & ~3u);
}
ELPIS_INLINE const uint8_t *rent_data_c(const rent_t *e)
{
    return rent_name_c(e) + ((e->namelen + 3u) & ~3u);
}

static void rent_free(void *p) { elpis_free(p); }

static int rent_eq(const void *entry, const void *key)
{
    const rent_t *e = (const rent_t *)entry;
    const rkey_t *k = (const rkey_t *)key;

    return e->type == k->type && e->klass == k->klass &&
           e->namelen == k->name->len &&
           elpis_eq_ci(rent_name_c(e), k->name->d, e->namelen);
}

static void rkey_init(rkey_t *k, const elpis_name_t *name,
                      uint16_t type, uint16_t klass)
{
    uint64_t seed = 0x2545F4914F6CDD1Dull ^
                    ((uint64_t)type << 32) ^ ((uint64_t)klass << 16);
    k->name  = name;
    k->type  = type;
    k->klass = klass;
    k->hash  = elpis_simd_hash_ci(name->d, name->len, seed);
}

elpis_cache_t *elpis_rcache_new(uint64_t bytes, unsigned shards)
{
    return elpis_cache_new("rrset-cache", bytes, shards, rent_free, rent_eq);
}

/* ------------------------------------------------------------------ */
/* Buffer helpers                                                      */
/* ------------------------------------------------------------------ */

void elpis_rrset_buf_copy(elpis_rrset_buf_t *dst, const elpis_rrset_buf_t *src)
{
    unsigned n;
    uint32_t used;

    if (dst == src)
        return;

    dst->name.len    = src->name.len;
    dst->name.labels = src->name.labels;
    memcpy(dst->name.d, src->name.d, src->name.len);   /* len is a uint8_t */

    dst->type     = src->type;
    dst->klass    = src->klass;
    dst->ttl      = src->ttl;
    dst->orig_ttl = src->orig_ttl;
    dst->sec      = src->sec;
    dst->zone_labels = src->zone_labels;
    dst->count    = src->count;
    dst->sigcount = src->sigcount;
    dst->flags    = src->flags;

    n = (unsigned)src->count + (unsigned)src->sigcount;
    if (n > ELPIS_RRSET_MAX_RR)
        n = ELPIS_RRSET_MAX_RR;
    if (n != 0) {
        memcpy(dst->len, src->len, (size_t)n * sizeof src->len[0]);
        memcpy(dst->off, src->off, (size_t)n * sizeof src->off[0]);
    }

    used = src->used;
    if (used > ELPIS_RRSET_BUF)
        used = ELPIS_RRSET_BUF;
    dst->used = used;
    if (used != 0)
        memcpy(dst->data, src->data, used);
}

void elpis_rrset_buf_init(elpis_rrset_buf_t *b, const elpis_name_t *name,
                          uint16_t type, uint16_t klass, uint32_t ttl)
{
    b->name     = *name;
    b->type     = type;
    b->klass    = klass;
    b->ttl      = ttl;
    b->orig_ttl = ttl;
    b->sec      = ELPIS_SEC_UNCHECKED;
    b->zone_labels = 0;
    b->count    = 0;
    b->sigcount = 0;
    b->flags    = 0;
    b->used     = 0;
}

int elpis_rrset_buf_add(elpis_rrset_buf_t *b, const uint8_t *rd, uint16_t len)
{
    unsigned idx;
    /* Data records must stay ahead of the signatures in the index arrays. */
    if (b->sigcount != 0)
        return ELPIS_ERR;
    if (b->count >= ELPIS_RRSET_MAX_RR)
        return ELPIS_ETRUNC;
    if (b->used + len > ELPIS_RRSET_BUF)
        return ELPIS_ETRUNC;
    idx = b->count;
    b->off[idx] = b->used;
    b->len[idx] = len;
    memcpy(b->data + b->used, rd, len);
    b->used += len;
    b->count++;
    return ELPIS_OK;
}

int elpis_rrset_buf_add_sig(elpis_rrset_buf_t *b, const uint8_t *rd, uint16_t len)
{
    unsigned idx = (unsigned)b->count + b->sigcount;
    if (idx >= ELPIS_RRSET_MAX_RR)
        return ELPIS_ETRUNC;
    if (b->used + len > ELPIS_RRSET_BUF)
        return ELPIS_ETRUNC;
    b->off[idx] = b->used;
    b->len[idx] = len;
    memcpy(b->data + b->used, rd, len);
    b->used += len;
    b->sigcount++;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Lookup                                                              */
/* ------------------------------------------------------------------ */

int elpis_rcache_get(elpis_cache_t *c, const elpis_name_t *name,
                     uint16_t type, uint16_t klass, uint32_t now,
                     uint32_t serve_stale, elpis_rrset_buf_t *out)
{
    rkey_t k;
    unsigned shard;
    rent_t *e;
    const uint8_t *p;
    unsigned i, total;
    uint32_t elapsed;
    int rc = ELPIS_ENOTFOUND;

    rkey_init(&k, name, type, klass);
    e = (rent_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e == NULL)
        return ELPIS_ENOTFOUND;

    elapsed = now - e->stored;
    if (elapsed > e->ttl && elapsed > e->ttl + serve_stale)
        goto out;

    out->name     = *name;
    out->type     = e->type;
    out->klass    = e->klass;
    out->orig_ttl = e->ttl;
    out->ttl      = (elapsed >= e->ttl) ? 0u : (e->ttl - elapsed);
    out->sec      = e->sec;
    out->zone_labels = e->zone_labels;
    out->count    = e->count;
    out->sigcount = e->sigcount;
    out->flags    = e->flags;
    out->used     = 0;

    total = (unsigned)e->count + e->sigcount;
    p = rent_data_c(e);
    for (i = 0; i < total; i++) {
        uint16_t l = elpis_get16(p);
        p += 2;
        if (out->used + l > ELPIS_RRSET_BUF) {
            rc = ELPIS_ETRUNC;
            goto out;
        }
        out->off[i] = out->used;
        out->len[i] = l;
        memcpy(out->data + out->used, p, l);
        out->used += l;
        p += l;
    }
    rc = ELPIS_OK;

out:
    elpis_cache_read_end(c, shard);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

static int rcache_put(elpis_cache_t *c, const elpis_name_t *name,
                      uint16_t type, uint16_t klass, uint32_t ttl,
                      elpis_sec_t sec, uint8_t flags, uint8_t zone_labels,
                      const uint8_t *const *rd, const uint16_t *rdlen,
                      unsigned count,
                      const uint8_t *const *sig, const uint16_t *siglen,
                      unsigned sigcount, uint32_t max_stale, int pinned)
{
    rkey_t k;
    rent_t *e;
    size_t datalen = 0, sz;
    unsigned i;
    uint8_t *p;

    if (count > ELPIS_RRSET_MAX_RR)
        count = ELPIS_RRSET_MAX_RR;
    if (sigcount > ELPIS_RRSET_MAX_RR - count)
        sigcount = ELPIS_RRSET_MAX_RR - count;
    if (count == 0 && sigcount == 0)
        return ELPIS_ERR;
    if (ttl == 0 && !pinned)
        return ELPIS_OK;

    for (i = 0; i < count; i++)
        datalen += 2u + rdlen[i];
    for (i = 0; i < sigcount; i++)
        datalen += 2u + siglen[i];
    if (datalen > 512u * 1024u)
        return ELPIS_ERR;

    /* The name pad here must match rent_data() exactly. */
    sz = sizeof(rent_t) + (((size_t)name->len + 3u) & ~(size_t)3u) + datalen;

    e = (rent_t *)elpis_malloc(sz);
    if (e == NULL)
        return ELPIS_ENOMEM;
    memset(e, 0, sizeof *e);

    rkey_init(&k, name, type, klass);

    e->hdr.hash   = k.hash;
    e->hdr.size   = (uint32_t)(sz + 64u);
    e->hdr.ref    = 1;
    e->hdr.pinned = pinned ? 1u : 0u;
    e->hdr.expiry = pinned ? 0u : (elpis_cached_now_s() + ttl + max_stale);

    e->type     = type;
    e->klass    = klass;
    e->namelen  = name->len;
    e->sec      = (uint8_t)sec;
    e->count    = (uint8_t)count;
    e->sigcount = (uint8_t)sigcount;
    e->flags    = flags;
    e->zone_labels = zone_labels;
    e->stored   = elpis_cached_now_s();
    e->ttl      = ttl;
    e->datalen  = (uint32_t)datalen;

    memcpy(rent_name(e), name->d, name->len);
    /* Owner names are stored folded so lookups never have to fold twice. */
    elpis_simd_lower(rent_name(e), rent_name(e), name->len);

    p = rent_data(e);
    for (i = 0; i < count; i++) {
        elpis_put16(p, rdlen[i]);
        memcpy(p + 2, rd[i], rdlen[i]);
        p += 2u + rdlen[i];
    }
    for (i = 0; i < sigcount; i++) {
        elpis_put16(p, siglen[i]);
        memcpy(p + 2, sig[i], siglen[i]);
        p += 2u + siglen[i];
    }

    return elpis_cache_insert(c, e, &k);
}

int elpis_rcache_put(elpis_cache_t *c, const elpis_name_t *name,
                     uint16_t type, uint16_t klass, uint32_t ttl,
                     elpis_sec_t sec, uint8_t flags,
                     const uint8_t *const *rd, const uint16_t *rdlen,
                     unsigned count,
                     const uint8_t *const *sig, const uint16_t *siglen,
                     unsigned sigcount, uint32_t max_stale, int pinned)
{
    return rcache_put(c, name, type, klass, ttl, sec, flags, 0, rd, rdlen,
                      count, sig, siglen, sigcount, max_stale, pinned);
}

int elpis_rcache_put_buf(elpis_cache_t *c, const elpis_rrset_buf_t *b,
                         uint32_t max_stale, int pinned)
{
    const uint8_t *rd[ELPIS_RRSET_MAX_RR];
    const uint8_t *sg[ELPIS_RRSET_MAX_RR];
    uint16_t rl[ELPIS_RRSET_MAX_RR];
    uint16_t sl[ELPIS_RRSET_MAX_RR];
    unsigned i;

    for (i = 0; i < b->count; i++) {
        rd[i] = b->data + b->off[i];
        rl[i] = b->len[i];
    }
    for (i = 0; i < b->sigcount; i++) {
        sg[i] = b->data + b->off[b->count + i];
        sl[i] = b->len[b->count + i];
    }
    return rcache_put(c, &b->name, b->type, b->klass, b->ttl,
                      (elpis_sec_t)b->sec, b->flags, b->zone_labels,
                      rd, rl, b->count, sg, sl, b->sigcount,
                      max_stale, pinned);
}

int elpis_rcache_state(elpis_cache_t *c, const elpis_name_t *name,
                       uint16_t type, uint16_t klass, uint32_t now,
                       uint8_t *sec, uint8_t *flags)
{
    rkey_t k;
    unsigned shard;
    rent_t *e;
    int rc = ELPIS_ENOTFOUND;

    rkey_init(&k, name, type, klass);
    e = (rent_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e == NULL)
        return ELPIS_ENOTFOUND;
    if (now - e->stored < e->ttl) {
        *sec   = e->sec;
        *flags = e->flags;
        rc = ELPIS_OK;
    }
    elpis_cache_read_end(c, shard);
    return rc;
}

int elpis_rcache_del(elpis_cache_t *c, const elpis_name_t *name,
                     uint16_t type, uint16_t klass)
{
    rkey_t k;
    rkey_init(&k, name, type, klass);
    return elpis_cache_remove(c, k.hash, &k);
}
