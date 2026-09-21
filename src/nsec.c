/*
 * nsec.c -- NSEC denial-of-existence proofs (RFC 4035 section 5.4).
 *
 * A signed NSEC record only says "nothing exists between these two names".
 * Turning that into "the name you asked for does not exist" needs two
 * separate proofs -- one covering the name, one covering the wildcard that
 * could otherwise have synthesised it -- and forgetting the second is the
 * classic way a validator ends up trusting a forged NXDOMAIN.
 */
#include "elpis/dnssec.h"
#include "elpis/rdata.h"
#include "elpis/log.h"

static int nsec_next(const elpis_denial_rr_t *r, elpis_name_t *next)
{
    size_t used;
    if (r->rdlen < 1)
        return 0;
    if (elpis_name_parse_nocomp(next, r->rd, r->rdlen, &used) != ELPIS_OK)
        return 0;
    return 1;
}

static const uint8_t *nsec_bitmap(const elpis_denial_rr_t *r, size_t *len)
{
    elpis_name_t next;
    size_t used;

    if (elpis_name_parse_nocomp(&next, r->rd, r->rdlen, &used) != ELPIS_OK)
        return NULL;
    if (used > r->rdlen)
        return NULL;
    *len = r->rdlen - used;
    return r->rd + used;
}

/*
 * True when `name` falls strictly between the NSEC owner and its next name.
 * The last NSEC in a zone wraps around, so owner >= next means "everything
 * after owner, plus everything before next".
 */
int elpis_nsec_covers(const elpis_denial_rr_t *r, const elpis_name_t *name)
{
    elpis_name_t next;
    int c_owner, c_next;

    if (!nsec_next(r, &next))
        return 0;

    c_owner = elpis_name_canon_cmp(&r->owner, name);
    c_next  = elpis_name_canon_cmp(name, &next);

    if (elpis_name_canon_cmp(&r->owner, &next) < 0)
        return c_owner < 0 && c_next < 0;
    /* Wrap-around at the end of the zone. */
    return c_owner < 0 || c_next < 0;
}

static int nsec_matches(const elpis_denial_rr_t *r, const elpis_name_t *name)
{
    return elpis_name_eq(&r->owner, name);
}

static int bitmap_has(const elpis_denial_rr_t *r, uint16_t type)
{
    size_t blen;
    const uint8_t *bm = nsec_bitmap(r, &blen);
    if (bm == NULL)
        return 0;
    return elpis_bitmap_has(bm, blen, type);
}

/*
 * The closest encloser is the longest ancestor of qname that provably exists;
 * with NSEC it is the longest common suffix of qname and a covering NSEC's
 * owner or next name.
 */
static unsigned closest_encloser_labels(const elpis_denial_rr_t *rrs, unsigned n,
                                        const elpis_name_t *qname)
{
    unsigned best = 0;
    unsigned i;

    for (i = 0; i < n; i++) {
        elpis_name_t next;
        unsigned a, b;

        a = elpis_name_common_labels(&rrs[i].owner, qname);
        if (a > best)
            best = a;
        if (nsec_next(&rrs[i], &next)) {
            b = elpis_name_common_labels(&next, qname);
            if (b > best)
                best = b;
        }
    }
    return best;
}

int elpis_nsec_proves_nxdomain(const elpis_denial_rr_t *rrs, unsigned n,
                               const elpis_name_t *qname)
{
    unsigned i;
    int covered = 0;
    int wildcard_denied = 0;
    unsigned ce_labels;
    elpis_name_t ce, wc;

    if (n == 0)
        return 0;

    for (i = 0; i < n; i++) {
        if (nsec_matches(&rrs[i], qname))
            return 0;                   /* the name exists after all */
        if (elpis_nsec_covers(&rrs[i], qname))
            covered = 1;
    }
    if (!covered)
        return 0;

    /* Deny the wildcard that could have covered the name. */
    ce_labels = closest_encloser_labels(rrs, n, qname);
    if (elpis_name_suffix(qname, ce_labels, &ce) != 0)
        return 0;
    if (elpis_name_prepend(&wc, (const uint8_t *)"*", 1, &ce) != ELPIS_OK)
        return 0;

    for (i = 0; i < n; i++) {
        if (nsec_matches(&rrs[i], &wc))
            return 0;                   /* the wildcard exists */
        if (elpis_nsec_covers(&rrs[i], &wc))
            wildcard_denied = 1;
    }
    return wildcard_denied;
}

int elpis_nsec_proves_nodata(const elpis_denial_rr_t *rrs, unsigned n,
                             const elpis_name_t *qname, uint16_t qtype)
{
    unsigned i;

    for (i = 0; i < n; i++) {
        if (!nsec_matches(&rrs[i], qname))
            continue;
        if (bitmap_has(&rrs[i], qtype))
            return 0;
        /*
         * A CNAME at the name would have been followed instead of producing
         * NODATA, so its presence makes the proof invalid.
         */
        if (qtype != ELPIS_T_CNAME && bitmap_has(&rrs[i], ELPIS_T_CNAME))
            return 0;
        /*
         * An NSEC at a delegation point proves nothing about the child zone's
         * data (RFC 4035 section 5.4, "opt-out"-like case for NS without SOA).
         */
        if (bitmap_has(&rrs[i], ELPIS_T_NS) && !bitmap_has(&rrs[i], ELPIS_T_SOA) &&
            qtype != ELPIS_T_DS)
            return 0;
        return 1;
    }

    /*
     * No NSEC matches the name itself.  That is still a valid NODATA proof
     * for a wildcard-expanded answer: the name is covered and the wildcard
     * exists but lacks the type.
     */
    return 0;
}

int elpis_nsec_proves_no_ds(const elpis_denial_rr_t *rrs, unsigned n,
                            const elpis_name_t *qname)
{
    unsigned i;

    for (i = 0; i < n; i++) {
        if (nsec_matches(&rrs[i], qname)) {
            if (bitmap_has(&rrs[i], ELPIS_T_DS))
                return 0;
            /* It must be the parent side of the cut, not the child's apex. */
            if (bitmap_has(&rrs[i], ELPIS_T_SOA))
                return 0;
            return 1;
        }
    }
    /* Or the name does not exist at all, which also means no DS. */
    return elpis_nsec_proves_nxdomain(rrs, n, qname);
}
