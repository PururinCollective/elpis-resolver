/*
 * nsec3.c -- NSEC3 denial-of-existence proofs (RFC 5155) and base32hex.
 *
 * NSEC3 replaces names with salted, iterated SHA-1 hashes.  The proof shape
 * is the same as NSEC -- cover the name, deny the wildcard -- but it has to be
 * expressed through the closest-encloser construction, and opt-out makes some
 * proofs legitimately weaker.
 *
 * Iteration counts above ELPIS_NSEC3_MAX_ITER are refused outright, per
 * RFC 9276: a zone can otherwise make every validator burn unbounded CPU on
 * a single query.
 */
#include "elpis/dnssec.h"
#include "elpis/crypto.h"
#include "elpis/rdata.h"
#include "elpis/log.h"

/* ------------------------------------------------------------------ */
/* base32hex (RFC 4648 section 7), lowercase, unpadded                 */
/* ------------------------------------------------------------------ */

static const char k_b32[] = "0123456789abcdefghijklmnopqrstuv";

int elpis_base32hex_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t i, o = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (i = 0; i < n; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (o + 1 >= cap)
                return ELPIS_ETRUNC;
            out[o++] = k_b32[(acc >> bits) & 0x1Fu];
        }
    }
    if (bits > 0) {
        if (o + 1 >= cap)
            return ELPIS_ETRUNC;
        out[o++] = k_b32[(acc << (5 - bits)) & 0x1Fu];
    }
    out[o] = '\0';
    return ELPIS_OK;
}

int elpis_base32hex_decode(const char *in, size_t n, uint8_t *out, size_t cap,
                           size_t *outlen)
{
    size_t i, o = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (i = 0; i < n; i++) {
        char c = in[i];
        int v;
        if (c >= '0' && c <= '9')      v = c - '0';
        else if (c >= 'a' && c <= 'v') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'V') v = c - 'A' + 10;
        else if (c == '=')             break;
        else return ELPIS_EFORMAT;
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap)
                return ELPIS_ETRUNC;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    *outlen = o;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

int elpis_nsec3_hash(const elpis_name_t *name, const uint8_t *salt,
                     uint8_t saltlen, uint16_t iterations, uint8_t alg,
                     uint8_t *out, size_t *outlen)
{
    elpis_name_t canon;
    uint8_t buf[20 + 255];
    unsigned i;

    if (alg != ELPIS_NSEC3_SHA1)
        return ELPIS_ERR;                /* SHA-1 is the only defined alg */
    if (iterations > ELPIS_NSEC3_MAX_ITER)
        return ELPIS_ERR;

    canon = *name;
    elpis_name_lower(&canon);

    /* IH(salt, x, 0) = H(x || salt) */
    {
        elpis_sha1_t c;
        elpis_sha1_init(&c);
        elpis_sha1_update(&c, canon.d, canon.len);
        if (saltlen)
            elpis_sha1_update(&c, salt, saltlen);
        elpis_sha1_final(&c, out);
    }
    for (i = 0; i < iterations; i++) {
        elpis_sha1_t c;
        memcpy(buf, out, 20);
        if (saltlen)
            memcpy(buf + 20, salt, saltlen);
        elpis_sha1_init(&c);
        elpis_sha1_update(&c, buf, 20u + saltlen);
        elpis_sha1_final(&c, out);
    }
    *outlen = 20;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Record accessors                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t        alg;
    uint8_t        flags;
    uint16_t       iterations;
    const uint8_t *salt;
    uint8_t        saltlen;
    const uint8_t *next;
    uint8_t        nextlen;
    const uint8_t *bitmap;
    size_t         bitmaplen;
    uint8_t        owner_hash[32];
    size_t         owner_hashlen;
} n3_t;

static int n3_parse(const elpis_denial_rr_t *r, const elpis_name_t *zone,
                    n3_t *o)
{
    size_t p = 0;
    char label[80];

    if (r->rdlen < 5)
        return 0;
    o->alg        = r->rd[0];
    o->flags      = r->rd[1];
    o->iterations = elpis_get16(r->rd + 2);
    o->saltlen    = r->rd[4];
    p = 5;
    if (p + o->saltlen + 1u > r->rdlen)
        return 0;
    o->salt = r->rd + p;
    p += o->saltlen;
    o->nextlen = r->rd[p++];
    if (o->nextlen == 0 || p + o->nextlen > r->rdlen)
        return 0;
    o->next = r->rd + p;
    p += o->nextlen;
    o->bitmap    = r->rd + p;
    o->bitmaplen = r->rdlen - p;

    /* The owner's first label is the base32hex of this record's own hash. */
    if (r->owner.len < 2 || r->owner.d[0] == 0 || r->owner.d[0] >= sizeof label)
        return 0;
    if (!elpis_name_is_subdomain(&r->owner, zone))
        return 0;
    memcpy(label, r->owner.d + 1, r->owner.d[0]);
    if (elpis_base32hex_decode(label, r->owner.d[0], o->owner_hash,
                               sizeof o->owner_hash, &o->owner_hashlen) != ELPIS_OK)
        return 0;
    if (o->owner_hashlen != o->nextlen)
        return 0;
    return 1;
}

static int hash_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    size_t n = alen < blen ? alen : blen;
    int c = memcmp(a, b, n);
    if (c != 0)
        return c;
    if (alen == blen)
        return 0;
    return alen < blen ? -1 : 1;
}

static int n3_covers(const n3_t *o, const uint8_t *h, size_t hlen)
{
    int c_owner = hash_cmp(o->owner_hash, o->owner_hashlen, h, hlen);
    int c_next  = hash_cmp(h, hlen, o->next, o->nextlen);

    if (hash_cmp(o->owner_hash, o->owner_hashlen, o->next, o->nextlen) < 0)
        return c_owner < 0 && c_next < 0;
    return c_owner < 0 || c_next < 0;    /* wraps at the end of the zone */
}

static int n3_matches(const n3_t *o, const uint8_t *h, size_t hlen)
{
    return hash_cmp(o->owner_hash, o->owner_hashlen, h, hlen) == 0;
}

/* ------------------------------------------------------------------ */
/* Proofs                                                              */
/* ------------------------------------------------------------------ */

/*
 * Find the closest provable ancestor of qname: walk up from qname until an
 * NSEC3 record matches that name's hash.  Returns its label count, or -1.
 */
static int find_closest_encloser(const elpis_denial_rr_t *rrs, unsigned n,
                                 const elpis_name_t *qname,
                                 const elpis_name_t *zone,
                                 const n3_t *params,
                                 elpis_name_t *ce_out)
{
    elpis_name_t cur = *qname;
    unsigned guard = 0;

    while (guard++ < ELPIS_MAX_LABELS) {
        uint8_t h[32];
        size_t hlen;
        unsigned i;

        if (cur.labels < zone->labels)
            return -1;

        if (elpis_nsec3_hash(&cur, params->salt, params->saltlen,
                             params->iterations, params->alg, h, &hlen) == ELPIS_OK) {
            for (i = 0; i < n; i++) {
                n3_t o;
                if (!n3_parse(&rrs[i], zone, &o))
                    continue;
                if (o.iterations != params->iterations ||
                    o.saltlen != params->saltlen ||
                    (o.saltlen && memcmp(o.salt, params->salt, o.saltlen) != 0))
                    continue;
                if (n3_matches(&o, h, hlen)) {
                    *ce_out = cur;
                    return (int)cur.labels;
                }
            }
        }
        if (cur.len <= 1 || elpis_name_eq(&cur, zone))
            return -1;
        if (elpis_name_parent(&cur, &cur) != 0)
            return -1;
    }
    return -1;
}

static int pick_params(const elpis_denial_rr_t *rrs, unsigned n,
                       const elpis_name_t *zone, n3_t *out)
{
    unsigned i;
    for (i = 0; i < n; i++) {
        if (n3_parse(&rrs[i], zone, out))
            return 1;
    }
    return 0;
}

static int covered_by_any(const elpis_denial_rr_t *rrs, unsigned n,
                          const elpis_name_t *zone, const n3_t *params,
                          const elpis_name_t *name, int *opt_out)
{
    uint8_t h[32];
    size_t hlen;
    unsigned i;

    if (elpis_nsec3_hash(name, params->salt, params->saltlen,
                         params->iterations, params->alg, h, &hlen) != ELPIS_OK)
        return 0;

    for (i = 0; i < n; i++) {
        n3_t o;
        if (!n3_parse(&rrs[i], zone, &o))
            continue;
        if (o.iterations != params->iterations || o.saltlen != params->saltlen)
            continue;
        if (o.saltlen && memcmp(o.salt, params->salt, o.saltlen) != 0)
            continue;
        if (n3_covers(&o, h, hlen)) {
            if (opt_out != NULL)
                *opt_out = (o.flags & ELPIS_NSEC3_OPTOUT) ? 1 : 0;
            return 1;
        }
    }
    return 0;
}

static int matched_by_any(const elpis_denial_rr_t *rrs, unsigned n,
                          const elpis_name_t *zone, const n3_t *params,
                          const elpis_name_t *name, n3_t *hit)
{
    uint8_t h[32];
    size_t hlen;
    unsigned i;

    if (elpis_nsec3_hash(name, params->salt, params->saltlen,
                         params->iterations, params->alg, h, &hlen) != ELPIS_OK)
        return 0;

    for (i = 0; i < n; i++) {
        n3_t o;
        if (!n3_parse(&rrs[i], zone, &o))
            continue;
        if (o.iterations != params->iterations || o.saltlen != params->saltlen)
            continue;
        if (o.saltlen && memcmp(o.salt, params->salt, o.saltlen) != 0)
            continue;
        if (n3_matches(&o, h, hlen)) {
            if (hit != NULL)
                *hit = o;
            return 1;
        }
    }
    return 0;
}

int elpis_nsec3_proves_nxdomain(const elpis_denial_rr_t *rrs, unsigned n,
                                const elpis_name_t *qname,
                                const elpis_name_t *zone)
{
    n3_t params;
    elpis_name_t ce, nc, wc;
    int ce_labels;

    if (n == 0 || !pick_params(rrs, n, zone, &params))
        return 0;
    if (params.iterations > ELPIS_NSEC3_MAX_ITER)
        return 0;

    ce_labels = find_closest_encloser(rrs, n, qname, zone, &params, &ce);
    if (ce_labels < 0)
        return 0;
    if ((unsigned)ce_labels >= qname->labels)
        return 0;                       /* the name itself exists */

    /* The "next closer" name is one label below the closest encloser. */
    if (elpis_name_suffix(qname, (unsigned)ce_labels + 1u, &nc) != 0)
        return 0;
    if (!covered_by_any(rrs, n, zone, &params, &nc, NULL))
        return 0;

    /* And the wildcard at the closest encloser must be denied too. */
    if (elpis_name_prepend(&wc, (const uint8_t *)"*", 1, &ce) != ELPIS_OK)
        return 0;
    if (matched_by_any(rrs, n, zone, &params, &wc, NULL))
        return 0;
    return covered_by_any(rrs, n, zone, &params, &wc, NULL);
}

int elpis_nsec3_proves_nodata(const elpis_denial_rr_t *rrs, unsigned n,
                              const elpis_name_t *qname, uint16_t qtype,
                              const elpis_name_t *zone)
{
    n3_t params, hit;

    if (n == 0 || !pick_params(rrs, n, zone, &params))
        return 0;
    if (params.iterations > ELPIS_NSEC3_MAX_ITER)
        return 0;

    if (matched_by_any(rrs, n, zone, &params, qname, &hit)) {
        if (elpis_bitmap_has(hit.bitmap, hit.bitmaplen, qtype))
            return 0;
        if (qtype != ELPIS_T_CNAME &&
            elpis_bitmap_has(hit.bitmap, hit.bitmaplen, ELPIS_T_CNAME))
            return 0;
        return 1;
    }

    /*
     * No direct match.  For a DS query this is still provable via opt-out;
     * for anything else it is not a proof.
     */
    if (qtype == ELPIS_T_DS)
        return elpis_nsec3_proves_no_ds(rrs, n, qname, zone);
    return 0;
}

int elpis_nsec3_proves_no_ds(const elpis_denial_rr_t *rrs, unsigned n,
                             const elpis_name_t *qname,
                             const elpis_name_t *zone)
{
    n3_t params, hit;
    int opt_out = 0;

    if (n == 0 || !pick_params(rrs, n, zone, &params))
        return 0;
    if (params.iterations > ELPIS_NSEC3_MAX_ITER)
        return 0;

    if (matched_by_any(rrs, n, zone, &params, qname, &hit)) {
        if (elpis_bitmap_has(hit.bitmap, hit.bitmaplen, ELPIS_T_DS))
            return 0;
        if (elpis_bitmap_has(hit.bitmap, hit.bitmaplen, ELPIS_T_SOA))
            return 0;                   /* that is the child's apex, not the cut */
        return 1;
    }

    /*
     * Opt-out (RFC 5155 section 6): an NSEC3 with the opt-out flag covering
     * the name proves only that there is no signed delegation there, which is
     * exactly what "no DS" means.
     */
    if (covered_by_any(rrs, n, zone, &params, qname, &opt_out) && opt_out)
        return 1;
    return 0;
}
