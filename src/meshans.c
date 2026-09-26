/*
 * meshans.c -- answers that travel with a name list (mesh-share-answers).
 *
 * A restarted instance asks a nearby peer for its most-asked names and, with
 * this on, for the answers it holds to them as well, and serves those at once
 * while its warm-up resolves the same names for itself.  This file is the
 * two ends of one answer: which of its own a peer may hand over, and what a
 * received one has to pass before it goes into the message cache.  mesh.c
 * moves them.
 *
 * Only answers DNSSEC could not have protected are handed over: an answer
 * this instance's own validator proved unsigned (INSECURE).  A signed name
 * gets no stand-in, so AD, and a validating client's view of it, is exactly
 * what it would have been without the mesh.  And only first-hand ones: an
 * answer a peer gave us, still unconfirmed, is never passed on.
 */
#include "elpis/mesh.h"
#include "elpis/store.h"
#include "elpis/msg.h"
#include "elpis/rdata.h"
#include "elpis/simd.h"
#include "elpis/util.h"

int elpis_mesh_answer_type(uint16_t qtype)
{
    return qtype == ELPIS_T_A || qtype == ELPIS_T_AAAA || qtype == ELPIS_T_HTTPS;
}

int elpis_mesh_answer_export(elpis_cache_t *mc, const elpis_mkey_t *k,
                             uint8_t *out, size_t cap, size_t *len)
{
    elpis_mserve_t info;

    if (k->qclass != ELPIS_CLASS_IN || (k->kflags & ELPIS_MK_CD) ||
        !elpis_mesh_answer_type(k->qtype))
        return ELPIS_ENOTFOUND;
    if (cap > ELPIS_MESH_ANSWER_MAX)
        cap = ELPIS_MESH_ANSWER_MAX;
    if (elpis_mcache_export(mc, k, out, cap, len, &info) != ELPIS_OK)
        return ELPIS_ENOTFOUND;
    if (info.src != ELPIS_MSRC_OWN || info.sec != ELPIS_SEC_INSECURE ||
        info.rcode != ELPIS_RC_NOERROR ||
        (info.ancount == 0 && info.nscount == 0) ||
        info.ttl < ELPIS_MESH_ANSWER_MIN_TTL)
        return ELPIS_ENOTFOUND;
    return ELPIS_OK;
}

/* What may sit in the answer section of an answer to `qtype`. */
static int answer_rr_ok(uint16_t type, uint16_t qtype, int dnssec)
{
    return type == qtype || type == ELPIS_T_CNAME || type == ELPIS_T_DNAME ||
           (dnssec && type == ELPIS_T_RRSIG);
}

/* Records a client that did not set DO never gets (resolver.c's rule). */
static int hidden(uint16_t type, uint16_t qtype, elpis_section_t sec,
                  int dnssec)
{
    if (dnssec)
        return 0;
    if (type != ELPIS_T_RRSIG && type != ELPIS_T_NSEC && type != ELPIS_T_NSEC3)
        return 0;
    return !(sec == ELPIS_SEC_ANSWER && type == qtype);
}

int elpis_mesh_answer_store(elpis_cache_t *mc, const elpis_conf_t *c,
                            const uint8_t *wire, size_t len, uint8_t kflags,
                            uint8_t src)
{
    static const elpis_section_t secs[3] = {
        ELPIS_SEC_ANSWER, ELPIS_SEC_AUTHORITY, ELPIS_SEC_ADDITIONAL
    };
    uint8_t out[2u * ELPIS_MESH_ANSWER_MAX], rd[4u * ELPIS_MESH_ANSWER_MAX];
    uint8_t folded[ELPIS_MAX_NAME];
    uint32_t toff[512], tval[512];
    elpis_cslot_t ctab[ELPIS_BLD_CTAB];
    elpis_mstate_t st;
    elpis_msg_t m;
    elpis_rr_iter_t it;
    elpis_rr_t rr;
    elpis_bld_t b;
    elpis_mkey_t k;
    elpis_name_t q;
    uint32_t minttl = 0xFFFFFFFFu, cap, ttl = 0xFFFFFFFFu;
    size_t qend, off[3];
    unsigned i, n;
    int rc, drop = 0, dnssec = (kflags & ELPIS_MK_DO) != 0, soa = 0;

    if (src == ELPIS_MSRC_OWN || len > ELPIS_MESH_ANSWER_MAX ||
        (kflags & ~ELPIS_MK_DO) != 0)
        return ELPIS_EFORMAT;
    if (elpis_msg_parse(&m, wire, len, ELPIS_PARSE_RESPONSE, &drop) != ELPIS_OK ||
        m.hdr.qdcount != 1 || m.qclass != ELPIS_CLASS_IN ||
        !elpis_mesh_answer_type(m.qtype) ||
        elpis_msg_rcode(&m) != ELPIS_RC_NOERROR ||
        (m.hdr.flags & ELPIS_FLAG_TC) ||
        (m.hdr.ancount == 0 && m.hdr.nscount == 0))
        return ELPIS_EFORMAT;

    q = m.qname;
    elpis_name_lower(&q);
    memcpy(folded, q.d, q.len);
    k.qname    = folded;
    k.qnamelen = q.len;
    k.qtype    = m.qtype;
    k.qclass   = ELPIS_CLASS_IN;
    k.kflags   = kflags;
    elpis_mkey_hash(&k);
    /* A live answer here already, of ours or another peer's: keep it. */
    if (elpis_mcache_seed_ex(mc, &k, 0, &st) && st.ttl_left > 0)
        return ELPIS_EREFUSED;

    /*
     * Every record checked before anything is built.  The answer section
     * answers this question, starting at its name; an answer with no records
     * says so with the zone's SOA (NODATA).  Nothing of another class.
     */
    for (i = 0; i < 3; i++) {
        n = 0;
        elpis_rr_iter(&it, &m, secs[i]);
        while ((rc = elpis_rr_next(&it, &rr, &drop)) == ELPIS_OK) {
            if (rr.type == ELPIS_T_OPT)
                continue;
            if (rr.klass != ELPIS_CLASS_IN || (rr.ttl & 0x80000000u) ||
                elpis_rdata_validate(rr.type, m.wire, m.len, rr.rdoff,
                                     rr.rdlen, &drop) != ELPIS_OK)
                return ELPIS_EFORMAT;
            if (secs[i] == ELPIS_SEC_ANSWER) {
                elpis_name_t owner = rr.name;
                elpis_name_lower(&owner);
                if (!answer_rr_ok(rr.type, m.qtype, dnssec) ||
                    (n == 0 && !elpis_name_eq(&owner, &q)))
                    return ELPIS_EFORMAT;
            }
            if (secs[i] == ELPIS_SEC_AUTHORITY && rr.type == ELPIS_T_SOA)
                soa = 1;
            if (rr.ttl < minttl)
                minttl = rr.ttl;
            n++;
        }
        if (rc != ELPIS_ENOTFOUND)
            return ELPIS_EFORMAT;
    }
    if (m.hdr.ancount == 0 && !soa)
        return ELPIS_EFORMAT;
    if (minttl < ELPIS_MESH_ANSWER_MIN_TTL_IN)
        return ELPIS_EFORMAT;

    /*
     * Rebuilt rather than stored as it came: names folded, compression our
     * own, and every TTL a second less for the trip and no longer than a
     * peer's answer is let stand in for ours.
     */
    cap = ELPIS_MESH_ANSWER_TTL_MAX;
    if (c->cache_max_ttl > 0 && c->cache_max_ttl < cap)
        cap = c->cache_max_ttl;
    elpis_bld_init(&b, out, sizeof out, ctab, 1);
    elpis_bld_track_ttl(&b, toff, tval, (unsigned)(sizeof toff / sizeof toff[0]));
    if (elpis_bld_header(&b, 0, (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA)) != ELPIS_OK ||
        elpis_bld_question_raw(&b, folded, q.len, m.qtype,
                               ELPIS_CLASS_IN) != ELPIS_OK)
        return ELPIS_EFORMAT;
    qend = b.len;
    for (i = 0; i < 3; i++) {
        off[i] = b.len;
        elpis_rr_iter(&it, &m, secs[i]);
        while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
            elpis_name_t owner = rr.name;
            uint32_t t = rr.ttl - 1u;
            size_t rdlen, rdpos;

            if (rr.type == ELPIS_T_OPT ||
                hidden(rr.type, m.qtype, secs[i], dnssec))
                continue;
            if (t > cap)
                t = cap;
            if (t < ttl)
                ttl = t;
            elpis_name_lower(&owner);
            if (elpis_rdata_canonical(rr.type, m.wire, m.len, rr.rdoff,
                                      rr.rdlen, rd, sizeof rd, &rdlen,
                                      1) != ELPIS_OK ||
                elpis_bld_rr_begin(&b, &owner, rr.type, ELPIS_CLASS_IN, t,
                                   &rdpos) != ELPIS_OK ||
                elpis_bld_bytes(&b, rd, rdlen) != ELPIS_OK ||
                elpis_bld_rr_end(&b, rdpos) != ELPIS_OK)
                return ELPIS_EFORMAT;
            elpis_bld_count(&b, secs[i], 1);
        }
    }
    elpis_bld_finish(&b);
    if (b.overflow || ttl == 0xFFFFFFFFu)
        return ELPIS_EFORMAT;

    /* No AD, never stale, and marked as the peer's until ours replaces it. */
    return elpis_mcache_store(mc, &k, out, b.len, qend, toff, tval, b.nttl,
                              off[1], off[2], ELPIS_RC_NOERROR, 0,
                              ELPIS_SEC_INSECURE, ttl, 0, 0, src);
}
