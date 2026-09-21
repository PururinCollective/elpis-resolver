/*
 * delegation.c -- delegation cache.
 */
#include "elpis/deleg.h"
#include "elpis/simd.h"
#include "elpis/log.h"

/*
 * Packed on-disk-ish layout, because the pinned TLD set lives here forever:
 *
 *   header
 *   uint8_t zone[zonelen]
 *   per nameserver:
 *       uint8_t namelen, name[namelen], n4, n6, flags
 *       uint8_t a4[n4][4]
 *       uint8_t a6[n6][16]
 *
 * Fixed-size elpis_nsrec_t would cost ~330 bytes per server; packed it is
 * closer to 60, which is the difference between the whole TLD set fitting in
 * a megabyte and needing eight.
 */
typedef struct {
    elpis_chdr_t hdr;
    uint8_t  zonelen;
    uint8_t  nns;
    uint8_t  sec;
    uint8_t  ds_state;
    uint32_t stored;
    uint32_t ttl;
    uint32_t datalen;
} dent_t;

typedef struct {
    const elpis_name_t *zone;
    uint64_t hash;
} dkey_t;

ELPIS_INLINE uint8_t *dent_zone(dent_t *e) { return (uint8_t *)(e + 1); }
ELPIS_INLINE const uint8_t *dent_zone_c(const dent_t *e) { return (const uint8_t *)(e + 1); }
ELPIS_INLINE uint8_t *dent_data(dent_t *e) { return dent_zone(e) + e->zonelen; }
ELPIS_INLINE const uint8_t *dent_data_c(const dent_t *e) { return dent_zone_c(e) + e->zonelen; }

static void dent_free(void *p) { elpis_free(p); }

static int dent_eq(const void *entry, const void *key)
{
    const dent_t *e = (const dent_t *)entry;
    const dkey_t *k = (const dkey_t *)key;
    return e->zonelen == k->zone->len &&
           elpis_eq_ci(dent_zone_c(e), k->zone->d, e->zonelen);
}

static void dkey_init(dkey_t *k, const elpis_name_t *zone)
{
    k->zone = zone;
    k->hash = elpis_simd_hash_ci(zone->d, zone->len, 0x7F4A7C15DEADBEEFull);
}

elpis_cache_t *elpis_dcache_new(uint64_t bytes, unsigned shards)
{
    return elpis_cache_new("deleg-cache", bytes, shards, dent_free, dent_eq);
}

/* ------------------------------------------------------------------ */
/* Working-set helpers                                                 */
/* ------------------------------------------------------------------ */

elpis_nsrec_t *elpis_deleg_find_ns(elpis_deleg_t *d, const elpis_name_t *ns)
{
    unsigned i;
    for (i = 0; i < d->nns; i++)
        if (elpis_name_eq(&d->ns[i].name, ns))
            return &d->ns[i];
    return NULL;
}

void elpis_deleg_add_ns(elpis_deleg_t *d, const elpis_name_t *ns)
{
    elpis_nsrec_t *r;
    if (elpis_deleg_find_ns(d, ns) != NULL)
        return;
    if (d->nns >= ELPIS_DELEG_MAX_NS)
        return;
    r = &d->ns[d->nns++];
    memset(r, 0, sizeof *r);
    r->name = *ns;
    r->port = 53;
    elpis_name_lower(&r->name);
}

void elpis_deleg_add_addr_port(elpis_deleg_t *d, const elpis_name_t *ns,
                               const uint8_t *ip, int family, uint8_t flags,
                               uint16_t port)
{
    elpis_nsrec_t *r;
    elpis_deleg_add_addr(d, ns, ip, family, flags);
    r = elpis_deleg_find_ns(d, ns);
    if (r != NULL)
        r->port = port;
}

void elpis_deleg_add_addr(elpis_deleg_t *d, const elpis_name_t *ns,
                          const uint8_t *ip, int family, uint8_t flags)
{
    elpis_nsrec_t *r = elpis_deleg_find_ns(d, ns);
    unsigned i;

    if (r == NULL) {
        elpis_deleg_add_ns(d, ns);
        r = elpis_deleg_find_ns(d, ns);
        if (r == NULL)
            return;
    }
    r->flags = (uint8_t)(r->flags | flags);
    r->flags = (uint8_t)(r->flags & ~ELPIS_NSF_NOADDR);

    if (family == AF_INET) {
        for (i = 0; i < r->n4; i++)
            if (memcmp(r->a4[i], ip, 4) == 0)
                return;
        if (r->n4 < ELPIS_NS_MAX_A4)
            memcpy(r->a4[r->n4++], ip, 4);
    } else if (family == AF_INET6) {
        for (i = 0; i < r->n6; i++)
            if (memcmp(r->a6[i], ip, 16) == 0)
                return;
        if (r->n6 < ELPIS_NS_MAX_A6)
            memcpy(r->a6[r->n6++], ip, 16);
    }
}

unsigned elpis_deleg_addr_count(const elpis_deleg_t *d)
{
    unsigned i, n = 0;
    for (i = 0; i < d->nns; i++)
        n += (unsigned)d->ns[i].n4 + d->ns[i].n6;
    return n;
}

/* ------------------------------------------------------------------ */
/* Pack / unpack                                                       */
/* ------------------------------------------------------------------ */

static size_t deleg_packed_len(const elpis_deleg_t *d)
{
    size_t n = 0;
    unsigned i;
    for (i = 0; i < d->nns; i++) {
        const elpis_nsrec_t *r = &d->ns[i];
        n += 1u + r->name.len + 5u;      /* len, name, n4, n6, flags, port */
        n += (size_t)r->n4 * 4u + (size_t)r->n6 * 16u;
    }
    return n;
}

static void deleg_pack(const elpis_deleg_t *d, uint8_t *p)
{
    unsigned i, j;
    for (i = 0; i < d->nns; i++) {
        const elpis_nsrec_t *r = &d->ns[i];
        *p++ = r->name.len;
        memcpy(p, r->name.d, r->name.len);
        p += r->name.len;
        *p++ = r->n4;
        *p++ = r->n6;
        *p++ = r->flags;
        *p++ = (uint8_t)(r->port >> 8);
        *p++ = (uint8_t)r->port;
        for (j = 0; j < r->n4; j++) { memcpy(p, r->a4[j], 4);  p += 4;  }
        for (j = 0; j < r->n6; j++) { memcpy(p, r->a6[j], 16); p += 16; }
    }
}

static int deleg_unpack(elpis_deleg_t *d, const uint8_t *p, size_t len,
                        unsigned nns)
{
    size_t off = 0;
    unsigned i, j;

    d->nns = 0;
    for (i = 0; i < nns && i < ELPIS_DELEG_MAX_NS; i++) {
        elpis_nsrec_t *r = &d->ns[i];
        unsigned nl;
        size_t used;

        if (off + 1 > len) return ELPIS_EFORMAT;
        nl = p[off++];
        if (off + nl + 5u > len) return ELPIS_EFORMAT;
        if (elpis_name_parse_nocomp(&r->name, p + off, nl, &used) != ELPIS_OK ||
            used != nl)
            return ELPIS_EFORMAT;
        off += nl;
        r->n4    = p[off++];
        r->n6    = p[off++];
        r->flags = p[off++];
        r->port  = (uint16_t)((p[off] << 8) | p[off + 1]);
        off += 2;
        if (r->port == 0)
            r->port = 53;
        if (r->n4 > ELPIS_NS_MAX_A4 || r->n6 > ELPIS_NS_MAX_A6)
            return ELPIS_EFORMAT;
        if (off + (size_t)r->n4 * 4u + (size_t)r->n6 * 16u > len)
            return ELPIS_EFORMAT;
        for (j = 0; j < r->n4; j++) { memcpy(r->a4[j], p + off, 4);  off += 4;  }
        for (j = 0; j < r->n6; j++) { memcpy(r->a6[j], p + off, 16); off += 16; }
        d->nns++;
    }
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Cache operations                                                    */
/* ------------------------------------------------------------------ */

int elpis_dcache_put(elpis_cache_t *c, const elpis_deleg_t *d,
                     uint32_t ttl, int pinned)
{
    dkey_t k;
    dent_t *e;
    size_t datalen, sz;

    if (d->nns == 0)
        return ELPIS_ERR;

    datalen = deleg_packed_len(d);
    sz = sizeof(dent_t) + d->zone.len + datalen;
    e = (dent_t *)elpis_malloc(sz);
    if (e == NULL)
        return ELPIS_ENOMEM;
    memset(e, 0, sizeof *e);

    dkey_init(&k, &d->zone);
    e->hdr.hash   = k.hash;
    e->hdr.size   = (uint32_t)(sz + 64u);
    e->hdr.ref    = 1;
    e->hdr.pinned = pinned ? 1u : 0u;
    /* Pinned delegations never expire out of the table; the refresh task
     * replaces them in place instead. */
    e->hdr.expiry = pinned ? 0u : (elpis_cached_now_s() + ttl);

    e->zonelen  = d->zone.len;
    e->nns      = d->nns;
    e->sec      = d->sec;
    e->ds_state = d->ds_state;
    e->stored   = elpis_cached_now_s();
    e->ttl      = ttl;
    e->datalen  = (uint32_t)datalen;

    memcpy(dent_zone(e), d->zone.d, d->zone.len);
    elpis_simd_lower(dent_zone(e), dent_zone(e), d->zone.len);
    deleg_pack(d, dent_data(e));

    return elpis_cache_insert(c, e, &k);
}

int elpis_dcache_get(elpis_cache_t *c, const elpis_name_t *zone,
                     uint32_t now, elpis_deleg_t *out)
{
    dkey_t k;
    unsigned shard;
    dent_t *e;
    uint32_t elapsed;
    int rc = ELPIS_ENOTFOUND;

    dkey_init(&k, zone);
    e = (dent_t *)elpis_cache_read_begin(c, k.hash, &k, &shard);
    if (e == NULL)
        return ELPIS_ENOTFOUND;

    elapsed = now - e->stored;
    if (!e->hdr.pinned && elapsed >= e->ttl)
        goto out;

    memset(out, 0, sizeof *out);
    out->zone     = *zone;
    out->sec      = e->sec;
    out->ds_state = e->ds_state;
    out->pinned   = e->hdr.pinned;
    out->ttl      = e->hdr.pinned ? e->ttl : (e->ttl - elapsed);
    if (deleg_unpack(out, dent_data_c(e), e->datalen, e->nns) != ELPIS_OK) {
        rc = ELPIS_EFORMAT;
        goto out;
    }
    rc = ELPIS_OK;

out:
    elpis_cache_read_end(c, shard);
    return rc;
}

int elpis_dcache_closest(elpis_cache_t *c, const elpis_name_t *name,
                         uint32_t now, elpis_deleg_t *out)
{
    elpis_name_t cur = *name;
    unsigned guard = 0;

    /*
     * Walk up one label at a time.  In practice this terminates on the first
     * or second probe once the TLD set is warm: "www.example.com" misses,
     * "example.com" often hits, "com" always does.
     */
    for (;;) {
        if (elpis_dcache_get(c, &cur, now, out) == ELPIS_OK &&
            elpis_deleg_addr_count(out) > 0)
            return ELPIS_OK;
        if (cur.len <= 1)
            break;
        if (elpis_name_parent(&cur, &cur) != 0)
            break;
        if (++guard > ELPIS_MAX_LABELS)
            break;
    }
    return ELPIS_ENOTFOUND;
}
