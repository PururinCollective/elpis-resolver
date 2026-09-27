/*
 * mcache.c -- prebuilt response cache.
 */
#include "elpis/store.h"
#include "elpis/util.h"
#include "elpis/simd.h"
#include "elpis/log.h"

typedef struct {
    elpis_chdr_t hdr;
    uint16_t qtype, qclass;
    uint8_t  qnamelen;
    uint8_t  kflags;
    uint8_t  sec;
    /*
     * Background-refresh bookkeeping.  Low nibble: consecutive refreshes that
     * came back unusable, which sets how long to wait before trying again.
     * High nibble: consecutive refreshes that came back an authoritative
     * NXDOMAIN, which decides when to believe the name really is gone.
     */
    uint8_t  refresh;
    uint16_t rcode;
    uint16_t flags;        /* response flags worth replaying (AA, AD)     */
    uint16_t ancount, nscount, arcount;
    uint16_t nttl;
    uint32_t stored;       /* monotonic seconds at insert                 */
    uint32_t ttl;          /* smallest original TTL in the message        */
    uint32_t bloblen;
    uint32_t ns_off;       /* blob-relative start of the authority section */
    uint32_t ar_off;       /* blob-relative start of the additional section*/
    uint32_t prefetch_at;  /* last time a refresh was triggered, monotonic */
    /*
     * Trailing payload, in this order:
     *   uint8_t  qname[qnamelen]
     *   uint32_t ttl_off[nttl]      (blob-relative, ascending)
     *   uint32_t ttl_val[nttl]
     *   uint8_t  blob[bloblen]
     */
} ment_t;

ELPIS_INLINE uint8_t *ment_qname(ment_t *e) { return (uint8_t *)(e + 1); }
ELPIS_INLINE const uint8_t *ment_qname_c(const ment_t *e) { return (const uint8_t *)(e + 1); }
ELPIS_INLINE uint32_t *ment_ttloff(ment_t *e)
{
    return (uint32_t *)(void *)(ment_qname(e) + ((e->qnamelen + 3u) & ~3u));
}
ELPIS_INLINE uint32_t *ment_ttlval(ment_t *e) { return ment_ttloff(e) + e->nttl; }
ELPIS_INLINE uint8_t  *ment_blob(ment_t *e)
{
    return (uint8_t *)(void *)(ment_ttlval(e) + e->nttl);
}

static size_t ment_size(uint8_t qnamelen, unsigned nttl, size_t bloblen)
{
    return sizeof(ment_t) + ((qnamelen + 3u) & ~3u) +
           (size_t)nttl * 8u + bloblen;
}

static void ment_free(void *p) { elpis_free(p); }

static int ment_eq(const void *entry, const void *key)
{
    const ment_t *e = (const ment_t *)entry;
    const elpis_mkey_t *k = (const elpis_mkey_t *)key;

    return e->qtype == k->qtype && e->qclass == k->qclass &&
           e->kflags == k->kflags && e->qnamelen == k->qnamelen &&
           memcmp(ment_qname_c(e), k->qname, k->qnamelen) == 0;
}

void elpis_mkey_hash(elpis_mkey_t *k)
{
    uint64_t seed = 0x51ED270B9F1A7C15ull ^
                    ((uint64_t)k->qtype << 32) ^
                    ((uint64_t)k->qclass << 16) ^
                    (uint64_t)k->kflags;
    k->hash = elpis_simd_hash_ci(k->qname, k->qnamelen, seed);
}

elpis_cache_t *elpis_mcache_new(uint64_t bytes, unsigned shards)
{
    return elpis_cache_new("msg-cache", bytes, shards, ment_free, ment_eq);
}

/* ------------------------------------------------------------------ */
/* Serving                                                             */
/* ------------------------------------------------------------------ */

static uint32_t remaining_ttl(const ment_t *e, uint32_t now, uint32_t *elapsed_out)
{
    uint32_t elapsed = now - e->stored;       /* monotonic, cannot go back */
    *elapsed_out = elapsed;
    return (elapsed >= e->ttl) ? 0u : (e->ttl - elapsed);
}

int elpis_mcache_serve(elpis_cache_t *c, const elpis_mkey_t *k,
                       uint16_t id, const uint8_t *qname_wire,
                       uint16_t base_flags, size_t budget,
                       uint32_t serve_stale, uint32_t stale_ttl,
                       unsigned prefetch_pct,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       elpis_mserve_t *info)
{
    unsigned shard;
    ment_t *e;
    uint32_t now = elpis_cached_now_s();
    uint32_t elapsed, rem;
    size_t qoff, hdrlen, cut, total;
    uint16_t an, ns, ar;
    const uint32_t *toff, *tval;
    unsigned i, ncut;
    int rc = ELPIS_ENOTFOUND;

    e = (ment_t *)elpis_cache_read_begin(c, k->hash, k, &shard);
    if (e == NULL)
        return ELPIS_ENOTFOUND;

    rem = remaining_ttl(e, now, &elapsed);
    if (rem == 0 && elapsed > e->ttl + serve_stale)
        goto out;          /* too stale even for RFC 8767 */

    memset(info, 0, sizeof *info);
    info->rcode = e->rcode;
    info->sec   = (elpis_sec_t)e->sec;
    info->ttl   = rem;
    info->stale = (rem == 0) ? 1u : 0u;

    /*
     * Ask for a refresh when the entry is stale or nearly so.  The timestamp
     * lives in the entry and is stamped here under the shared lock, which
     * bounds refreshes to roughly one per second per key no matter how many
     * queries arrive -- at high query rates the alternative is a refresh
     * storm for every popular name.
     */
    if (prefetch_pct > 0 && e->ttl > 0) {
        /*
         * Percentage of the original TTL, multiplied before it is divided.
         * Dividing first truncated every TTL below 100 seconds to a threshold
         * of zero, so the shortest-lived entries -- the ones a refresh is
         * most worth doing for -- were never refreshed until they had already
         * gone stale.
         */
        uint32_t threshold =
            (uint32_t)(((uint64_t)e->ttl * prefetch_pct) / 100u);
        if (rem == 0 || rem <= threshold) {
            /*
             * One refresh per second per key is fine while they are working,
             * but a refresh that keeps failing must not keep asking at that
             * rate: the usual reason a refresh fails is that the far side is
             * rate limiting us, and hammering it once a second is how a brief
             * limit turns into a permanent one.  Back off to a minute.
             */
            unsigned fails = (unsigned)(e->refresh & 0x0Fu);
            uint32_t wait  = 1u << (fails > 6u ? 6u : fails);

            if (now - e->prefetch_at >= wait) {
                e->prefetch_at = now;
                info->want_prefetch = 1;
            }
        }
    }

    hdrlen = ELPIS_HDR_LEN + (size_t)e->qnamelen + 4u;
    if (outcap < hdrlen)
        goto out;

    an = e->ancount;
    ns = e->nscount;
    ar = e->arcount;
    cut = e->bloblen;

    /*
     * Trim from the tail when the message will not fit.  Compression pointers
     * only ever point backwards, so dropping a suffix can never orphan one.
     */
    if (hdrlen + cut > budget || hdrlen + cut > outcap) {
        cut = e->ar_off;
        ar  = 0;
        info->dropped_ar = 1;
        if (hdrlen + cut > budget || hdrlen + cut > outcap) {
            if (k->kflags & ELPIS_MK_DO) {
                /*
                 * The authority section carries the denial-of-existence proof
                 * for a DNSSEC-aware client; dropping it would turn a secure
                 * answer into an unprovable one.  Truncate instead.
                 */
                cut = 0;
                an = ns = 0;
                info->truncated = 1;
            } else {
                cut = e->ns_off;
                ns  = 0;
                info->dropped_ns = 1;
                if (hdrlen + cut > budget || hdrlen + cut > outcap) {
                    cut = 0;
                    an = 0;
                    info->truncated = 1;
                }
            }
        }
    }

    total = hdrlen + cut;
    if (total > outcap)
        goto out;

    /* Header. */
    elpis_put16(out, id);
    {
        uint16_t fl = (uint16_t)((base_flags & ~ELPIS_RCODE_MASK) |
                                 (e->rcode & ELPIS_RCODE_MASK));
        fl |= (uint16_t)(e->flags & ELPIS_FLAG_AD);
        if (info->truncated)
            fl |= ELPIS_FLAG_TC;
        elpis_put16(out + 2, fl);
    }
    elpis_put16(out + 4,  1);
    elpis_put16(out + 6,  an);
    elpis_put16(out + 8,  ns);
    elpis_put16(out + 10, ar);

    /* Question, echoed exactly as the client sent it (0x20 casing intact). */
    qoff = ELPIS_HDR_LEN;
    memcpy(out + qoff, qname_wire, e->qnamelen);
    qoff += e->qnamelen;
    elpis_put16(out + qoff, e->qtype);
    elpis_put16(out + qoff + 2, e->qclass);
    qoff += 4;

    if (cut > 0)
        memcpy(out + qoff, ment_blob(e), cut);

    /* Patch the TTLs that survived the cut. */
    toff = ment_ttloff(e);
    tval = ment_ttlval(e);
    ncut = e->nttl;
    for (i = 0; i < ncut; i++) {
        uint32_t o = toff[i];
        uint32_t v = tval[i];
        if (o + 4 > cut)
            break;                      /* offsets are ascending */
        /*
         * A stale answer goes out with a short TTL rather than zero
         * (RFC 8767 section 4): the client should come back soon, and a zero
         * TTL makes some stubs re-query immediately and hammer us.
         */
        v = (elapsed >= v) ? stale_ttl : (v - elapsed);
        elpis_put32(out + qoff + o, v);
    }

    *outlen = total;
    info->ancount = an;
    info->nscount = ns;
    info->arcount = ar;
    rc = ELPIS_OK;

out:
    elpis_cache_read_end(c, shard);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Storing                                                             */
/* ------------------------------------------------------------------ */

int elpis_mcache_store(elpis_cache_t *c, const elpis_mkey_t *k,
                       const uint8_t *wire, size_t len, size_t qend,
                       const uint32_t *ttl_off, const uint32_t *ttl_val,
                       unsigned nttl, size_t ns_off, size_t ar_off,
                       unsigned rcode, uint16_t flags, elpis_sec_t sec,
                       uint32_t ttl, uint32_t max_stale)
{
    ment_t *e;
    size_t bloblen, sz;
    unsigned i, kept = 0;
    uint32_t *toff, *tval;
    uint32_t prev = 0;

    if (len < qend || qend < ELPIS_HDR_LEN)
        return ELPIS_ERR;
    if (k->qnamelen == 0)
        return ELPIS_ERR;
    if (ttl == 0)
        return ELPIS_OK;                /* nothing worth keeping */

    bloblen = len - qend;
    if (bloblen > ELPIS_MAX_MSG)
        return ELPIS_ERR;

    /*
     * Count the usable TTL offsets first so the entry is allocated at exactly
     * the right size; the payload layout depends on nttl, so it has to be
     * final before anything is written into it.
     */
    for (i = 0; i < nttl; i++) {
        uint32_t rel;
        if (ttl_off[i] < qend)
            continue;
        rel = ttl_off[i] - (uint32_t)qend;
        if (rel + 4 > bloblen)
            continue;
        if (kept > 0 && rel < prev)
            continue;                   /* the builder emits these in order */
        prev = rel;
        kept++;
    }

    sz = ment_size(k->qnamelen, kept, bloblen);
    e = (ment_t *)elpis_malloc(sz);
    if (e == NULL)
        return ELPIS_ENOMEM;
    memset(e, 0, sizeof *e);

    e->hdr.hash   = k->hash;
    e->hdr.size   = (uint32_t)(sz + 64u);   /* allocator overhead estimate */
    e->hdr.ref    = 1;
    e->hdr.pinned = 0;
    e->hdr.expiry = elpis_cached_now_s() + ttl + max_stale;

    e->qtype    = k->qtype;
    e->qclass   = k->qclass;
    e->qnamelen = k->qnamelen;
    e->kflags   = k->kflags;
    e->sec      = (uint8_t)sec;
    e->rcode    = (uint16_t)rcode;
    e->flags    = flags;
    e->ancount  = elpis_get16(wire + 6);
    e->nscount  = elpis_get16(wire + 8);
    e->arcount  = elpis_get16(wire + 10);
    e->stored   = elpis_cached_now_s();
    e->ttl      = ttl;
    e->bloblen  = (uint32_t)bloblen;
    e->nttl     = (uint16_t)kept;
    e->ns_off   = (uint32_t)(ns_off >= qend ? ns_off - qend : bloblen);
    e->ar_off   = (uint32_t)(ar_off >= qend ? ar_off - qend : bloblen);
    if (e->ns_off > bloblen) e->ns_off = (uint32_t)bloblen;
    if (e->ar_off > bloblen) e->ar_off = (uint32_t)bloblen;
    if (e->ar_off < e->ns_off) e->ar_off = e->ns_off;

    memcpy(ment_qname(e), k->qname, k->qnamelen);

    toff = ment_ttloff(e);
    tval = ment_ttlval(e);
    prev = 0;
    kept = 0;
    for (i = 0; i < nttl; i++) {
        uint32_t rel;
        if (ttl_off[i] < qend)
            continue;
        rel = ttl_off[i] - (uint32_t)qend;
        if (rel + 4 > bloblen)
            continue;
        if (kept > 0 && rel < prev)
            continue;
        prev = rel;
        toff[kept] = rel;
        tval[kept] = ttl_val[i];
        kept++;
    }

    memcpy(ment_blob(e), wire + qend, bloblen);

    return elpis_cache_insert(c, e, k);
}

/*
 * Record how a background refresh turned out.
 *
 * Two different things can go wrong and they deserve opposite treatment.  An
 * unusable reply -- a timeout, SERVFAIL, REFUSED -- says nothing about the
 * name, so the entry stays and keeps being served while we wait longer and
 * longer before trying again.  An authoritative NXDOMAIN is real data, and
 * ignoring it forever would serve a deleted name for the whole serve-stale
 * window; but believing a single one would let one glitch from a rate-limited
 * server take out a name that is perfectly fine.  So it has to say so twice in
 * a row, after which the entry is dropped and the next query resolves for
 * real.
 */
int elpis_mcache_refresh_outcome(elpis_cache_t *c, const elpis_mkey_t *k,
                                 int outcome, unsigned nx_confirm)
{
    unsigned shard;
    ment_t *e;
    int drop = 0;

    e = (ment_t *)elpis_cache_read_begin(c, k->hash, k, &shard);
    if (e == NULL)
        return 0;

    {
        /*
         * Every unsuccessful refresh widens the gap before the next one,
         * whatever went wrong.  That matters for the NXDOMAIN count as much as
         * for the rest: the confirmations have to be spread over time to mean
         * anything, and at one a second three of them would say no more than
         * one does.  Backed off, the third lands some seconds after the first,
         * so a server having a brief bad moment gets to recover before its
         * answer is believed.
         */
        unsigned fails = (unsigned)(e->refresh & 0x0Fu);
        unsigned nx    = (unsigned)(e->refresh >> 4);

        if (fails < 15u)
            fails++;
        if (outcome == ELPIS_REFRESH_NXDOMAIN) {
            if (++nx >= nx_confirm)
                drop = 1;
        } else {
            nx = 0;             /* not a denial: start that count over */
        }
        if (nx > 15u)
            nx = 15u;
        e->refresh = (uint8_t)((nx << 4) | fails);
    }
    elpis_cache_read_end(c, shard);

    if (drop)
        elpis_cache_remove(c, k->hash, k);
    return drop;
}
