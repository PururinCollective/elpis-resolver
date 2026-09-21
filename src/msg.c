/*
 * msg.c -- DNS message parsing and construction.
 */
#include "elpis/msg.h"
#include "elpis/util.h"
#include "elpis/simd.h"

/* ================================================================== */
/* Header                                                              */
/* ================================================================== */

int elpis_hdr_parse(elpis_hdr_t *h, const uint8_t *wire, size_t len)
{
    if (len < ELPIS_HDR_LEN)
        return ELPIS_EFORMAT;
    h->id       = elpis_get16(wire);
    h->flags    = elpis_get16(wire + 2);
    h->qdcount  = elpis_get16(wire + 4);
    h->ancount  = elpis_get16(wire + 6);
    h->nscount  = elpis_get16(wire + 8);
    h->arcount  = elpis_get16(wire + 10);
    return ELPIS_OK;
}

/* ================================================================== */
/* Parsing                                                             */
/* ================================================================== */

/* Skip one name at `off`, validating it, without materialising it. */
static int skip_name(const uint8_t *w, size_t len, size_t off, size_t *end, int *drop)
{
    size_t total = 0;
    unsigned labels = 0;

    for (;;) {
        uint8_t c;
        if (off >= len) { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
        c = w[off];
        if ((c & 0xC0u) == 0xC0u) {
            if (off + 2 > len) { *drop = ELPIS_DROP_COMPRESS; return ELPIS_EFORMAT; }
            /*
             * We only need the in-message extent here.  The pointer target is
             * validated when the name is actually materialised; checking the
             * bound now keeps a malformed pointer from being cached later.
             */
            {
                size_t tgt = (size_t)((c & 0x3Fu) << 8) | w[off + 1];
                if (tgt >= off) { *drop = ELPIS_DROP_COMPRESS; return ELPIS_EFORMAT; }
            }
            *end = off + 2;
            return ELPIS_OK;
        }
        if ((c & 0xC0u) != 0) { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
        if (c == 0) {
            if (total + 1 > ELPIS_MAX_NAME) { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
            *end = off + 1;
            return ELPIS_OK;
        }
        if (c > ELPIS_MAX_LABEL)          { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
        if (off + 1 + c > len)            { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
        total += 1u + c;
        if (total + 1 > ELPIS_MAX_NAME)   { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
        if (++labels > ELPIS_MAX_LABELS)  { *drop = ELPIS_DROP_NAME; return ELPIS_EFORMAT; }
        off += 1u + c;
    }
}

/* Walk one record header, leaving `off` past the rdata. */
static int skip_rr(const uint8_t *w, size_t len, size_t off, size_t *end, int *drop)
{
    size_t p;
    uint16_t rdlen;

    if (skip_name(w, len, off, &p, drop) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (p + 10 > len) { *drop = ELPIS_DROP_RDLEN; return ELPIS_EFORMAT; }
    rdlen = elpis_get16(w + p + 8);
    p += 10;
    if (p + rdlen > len) { *drop = ELPIS_DROP_RDLEN; return ELPIS_EFORMAT; }
    *end = p + rdlen;
    return ELPIS_OK;
}

static int parse_opt(elpis_msg_t *m, const elpis_rr_t *rr, int *drop)
{
    size_t p = rr->rdoff;
    size_t stop = rr->rdoff + rr->rdlen;

    if (m->have_opt) { *drop = ELPIS_DROP_MULTI_OPT; return ELPIS_EFORMAT; }
    /* The OPT owner name must be the root (RFC 6891 section 6.1.2). */
    if (rr->name.len != 1) { *drop = ELPIS_DROP_EDNS; return ELPIS_EFORMAT; }

    m->have_opt      = 1;
    m->opt_off       = rr->rroff;
    m->opt_rdoff     = rr->rdoff;
    m->opt_rdlen     = rr->rdlen;
    m->edns_bufsize  = rr->klass;
    m->edns_rcode_hi = (uint8_t)(rr->ttl >> 24);
    m->edns_version  = (uint8_t)(rr->ttl >> 16);
    m->edns_flags    = (uint16_t)(rr->ttl & 0xFFFFu);
    m->do_bit        = (m->edns_flags & ELPIS_EDNS_DO) ? 1u : 0u;

    while (p < stop) {
        uint16_t ocode, olen;
        if (p + 4 > stop) { *drop = ELPIS_DROP_EDNS; return ELPIS_EFORMAT; }
        ocode = elpis_get16(m->wire + p);
        olen  = elpis_get16(m->wire + p + 2);
        p += 4;
        if (p + olen > stop) { *drop = ELPIS_DROP_EDNS; return ELPIS_EFORMAT; }
        switch (ocode) {
        case ELPIS_OPT_COOKIE:
            /* 8 bytes client, or 8 + 8..32 client+server (RFC 7873). */
            if (olen != 8 && (olen < 16 || olen > 40)) {
                *drop = ELPIS_DROP_EDNS;
                return ELPIS_EFORMAT;
            }
            memcpy(m->cookie, m->wire + p, olen);
            m->cookie_len  = (uint8_t)olen;
            m->have_cookie = 1;
            break;
        case ELPIS_OPT_ECS:
            if (olen < 4) { *drop = ELPIS_DROP_EDNS; return ELPIS_EFORMAT; }
            m->have_ecs = 1;
            break;
        default:
            break;
        }
        p += olen;
    }
    return ELPIS_OK;
}

int elpis_msg_parse(elpis_msg_t *m, const uint8_t *wire, size_t len,
                    unsigned flags, int *drop)
{
    size_t off;
    int d = ELPIS_DROP_NONE;
    unsigned s;

    memset(m, 0, sizeof *m);
    m->wire = wire;
    m->len  = len;
    m->edns_bufsize = ELPIS_MAX_UDP_LEGACY;

    if (elpis_hdr_parse(&m->hdr, wire, len) != ELPIS_OK) {
        *drop = ELPIS_DROP_SHORT;
        return ELPIS_EFORMAT;
    }

    {
        int is_resp = (m->hdr.flags & ELPIS_FLAG_QR) != 0;
        if (is_resp && !(flags & ELPIS_PARSE_RESPONSE)) {
            *drop = ELPIS_DROP_QR_SET;
            return ELPIS_EFORMAT;
        }
        if (!is_resp && !(flags & ELPIS_PARSE_QUERY)) {
            *drop = ELPIS_DROP_QR_SET;
            return ELPIS_EFORMAT;
        }
    }

    off = ELPIS_HDR_LEN;

    /*
     * qdcount != 1 is legal only for a few opcodes we do not serve.  Treating
     * it as malformed here keeps every downstream consumer simple.
     */
    if (m->hdr.qdcount == 1) {
        size_t qend;
        if (elpis_name_parse(&m->qname, wire, len, off, &qend, &d) != ELPIS_OK) {
            *drop = d;
            return ELPIS_EFORMAT;
        }
        if (qend + 4 > len) { *drop = ELPIS_DROP_SHORT; return ELPIS_EFORMAT; }
        m->qtype  = elpis_get16(wire + qend);
        m->qclass = elpis_get16(wire + qend + 2);
        m->qend   = qend + 4;
        off       = m->qend;
    } else if (m->hdr.qdcount == 0) {
        m->qend = off;
    } else {
        *drop = ELPIS_DROP_QDCOUNT;
        return ELPIS_EFORMAT;
    }

    m->sec_cnt[ELPIS_SEC_ANSWER]     = m->hdr.ancount;
    m->sec_cnt[ELPIS_SEC_AUTHORITY]  = m->hdr.nscount;
    m->sec_cnt[ELPIS_SEC_ADDITIONAL] = m->hdr.arcount;

    if (flags & ELPIS_PARSE_NO_WALK) {
        m->sec_off[0] = m->sec_off[1] = m->sec_off[2] = off;
        return ELPIS_OK;
    }

    /*
     * Walk every record.  This is the gate that keeps malformed data out of
     * the cache: a message that does not survive the walk is dropped whole.
     */
    for (s = 0; s < ELPIS_SEC__COUNT; s++) {
        unsigned i;
        m->sec_off[s] = off;
        for (i = 0; i < m->sec_cnt[s]; i++) {
            size_t next;
            if (skip_rr(wire, len, off, &next, &d) != ELPIS_OK) {
                *drop = d;
                return ELPIS_EFORMAT;
            }
            off = next;
        }
    }

    if (off != len) {
        /*
         * Trailing bytes mean either a count that lies or an appended payload.
         * Both are grounds to drop: accepting them invites cache poisoning via
         * records the counts do not cover.
         */
        *drop = ELPIS_DROP_TRAILING;
        return ELPIS_EFORMAT;
    }

    /* Locate and validate OPT; it must live in the additional section. */
    {
        elpis_rr_iter_t it;
        elpis_rr_t rr;
        int rc;

        elpis_rr_iter(&it, m, ELPIS_SEC_ADDITIONAL);
        while ((rc = elpis_rr_next(&it, &rr, &d)) == ELPIS_OK) {
            if (rr.type == ELPIS_T_OPT) {
                if (parse_opt(m, &rr, &d) != ELPIS_OK) {
                    *drop = d;
                    return ELPIS_EFORMAT;
                }
            }
        }
        if (rc == ELPIS_EFORMAT) {
            *drop = d;
            return ELPIS_EFORMAT;
        }
    }

    /* OPT must not appear in the answer or authority sections. */
    for (s = 0; s < 2; s++) {
        elpis_rr_iter_t it;
        elpis_rr_t rr;
        it.wire = wire; it.len = len; it.off = m->sec_off[s]; it.remain = m->sec_cnt[s];
        while (elpis_rr_next(&it, &rr, &d) == ELPIS_OK) {
            if (rr.type == ELPIS_T_OPT) {
                *drop = ELPIS_DROP_EDNS;
                return ELPIS_EFORMAT;
            }
        }
    }

    if (m->have_opt && m->edns_bufsize < 512)
        m->edns_bufsize = 512;      /* RFC 6891 section 6.2.3 floor */

    *drop = ELPIS_DROP_NONE;
    return ELPIS_OK;
}

void elpis_rr_iter(elpis_rr_iter_t *it, const elpis_msg_t *m, elpis_section_t s)
{
    it->wire   = m->wire;
    it->len    = m->len;
    it->off    = m->sec_off[s];
    it->remain = m->sec_cnt[s];
}

int elpis_rr_next(elpis_rr_iter_t *it, elpis_rr_t *rr, int *drop)
{
    size_t p;
    int d = ELPIS_DROP_NONE;

    if (it->remain == 0)
        return ELPIS_ENOTFOUND;

    rr->rroff = it->off;
    if (elpis_name_parse(&rr->name, it->wire, it->len, it->off, &p, &d) != ELPIS_OK) {
        *drop = d;
        return ELPIS_EFORMAT;
    }
    if (p + 10 > it->len) { *drop = ELPIS_DROP_RDLEN; return ELPIS_EFORMAT; }
    rr->type  = elpis_get16(it->wire + p);
    rr->klass = elpis_get16(it->wire + p + 2);
    rr->ttl   = elpis_get32(it->wire + p + 4);
    rr->rdlen = elpis_get16(it->wire + p + 8);
    rr->rdoff = p + 10;
    if (rr->rdoff + rr->rdlen > it->len) { *drop = ELPIS_DROP_RDLEN; return ELPIS_EFORMAT; }
    rr->next  = rr->rdoff + rr->rdlen;

    it->off = rr->next;
    it->remain--;
    *drop = ELPIS_DROP_NONE;
    return ELPIS_OK;
}

/* ================================================================== */
/* Building                                                            */
/* ================================================================== */

void elpis_bld_init(elpis_bld_t *b, uint8_t *buf, size_t cap,
                    elpis_cslot_t *ctab, int compress)
{
    memset(b, 0, sizeof *b);
    b->buf      = buf;
    b->cap      = cap;
    b->ctab     = ctab;
    b->compress = (compress && ctab != NULL) ? 1u : 0u;
}

void elpis_bld_track_ttl(elpis_bld_t *b, uint32_t *off, uint32_t *val, unsigned cap)
{
    b->ttl_off   = off;
    b->ttl_val   = val;
    b->ttl_cap   = cap;
    b->nttl      = 0;
    b->track_ttl = (off != NULL && val != NULL && cap > 0) ? 1u : 0u;
}

void elpis_bld_mark(const elpis_bld_t *b, elpis_bld_mark_t *m)
{
    m->len   = b->len;
    m->nctab = b->nctab;
    m->nttl  = b->nttl;
    memcpy(m->counts, b->counts, sizeof m->counts);
}

void elpis_bld_rollback(elpis_bld_t *b, const elpis_bld_mark_t *m)
{
    b->len   = m->len;
    b->nctab = m->nctab;
    b->nttl  = m->nttl;
    memcpy(b->counts, m->counts, sizeof b->counts);
    b->overflow = 0;
}

int elpis_bld_bytes(elpis_bld_t *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) { b->overflow = 1; return ELPIS_ETRUNC; }
    memcpy(b->buf + b->len, p, n);
    b->len += n;
    return ELPIS_OK;
}

int elpis_bld_u16(elpis_bld_t *b, uint16_t v)
{
    if (b->len + 2 > b->cap) { b->overflow = 1; return ELPIS_ETRUNC; }
    elpis_put16(b->buf + b->len, v);
    b->len += 2;
    return ELPIS_OK;
}

int elpis_bld_u32(elpis_bld_t *b, uint32_t v)
{
    if (b->len + 4 > b->cap) { b->overflow = 1; return ELPIS_ETRUNC; }
    elpis_put32(b->buf + b->len, v);
    b->len += 4;
    return ELPIS_OK;
}

int elpis_bld_header(elpis_bld_t *b, uint16_t id, uint16_t flags)
{
    uint8_t h[ELPIS_HDR_LEN];
    memset(h, 0, sizeof h);
    elpis_put16(h, id);
    elpis_put16(h + 2, flags);
    b->len = 0;
    memset(b->counts, 0, sizeof b->counts);
    return elpis_bld_bytes(b, h, sizeof h);
}

/* Register `n` (and the offsets of its suffixes) as a compression target. */
static void ctab_add(elpis_bld_t *b, const elpis_name_t *n, size_t off)
{
    elpis_name_t cur = *n;
    size_t o = off;

    if (!b->compress)
        return;
    while (cur.len > 1) {
        if (b->nctab >= ELPIS_BLD_CTAB)
            return;
        if (o >= 0x4000u)               /* pointers only reach 14 bits */
            return;
        b->ctab[b->nctab].off  = (uint16_t)o;
        b->ctab[b->nctab].name = cur;
        b->nctab++;
        o += 1u + (size_t)cur.d[0];
        if (elpis_name_parent(&cur, &cur) != 0)
            return;
    }
}

static int ctab_find(const elpis_bld_t *b, const elpis_name_t *n, uint16_t *off)
{
    unsigned i;
    for (i = 0; i < b->nctab; i++) {
        if (b->ctab[i].name.len == n->len &&
            elpis_eq_ci(b->ctab[i].name.d, n->d, n->len)) {
            *off = b->ctab[i].off;
            return 1;
        }
    }
    return 0;
}

int elpis_bld_name(elpis_bld_t *b, const elpis_name_t *n)
{
    elpis_name_t suffix;
    size_t start = b->len;
    uint16_t target;

    if (!b->compress)
        return elpis_bld_name_raw(b, n);

    suffix = *n;
    /*
     * Walk suffixes longest-first; the first hit gives the shortest encoding.
     * Labels skipped along the way are emitted literally.
     */
    for (;;) {
        if (suffix.len <= 1)
            break;
        if (ctab_find(b, &suffix, &target)) {
            size_t lit = (size_t)n->len - suffix.len;
            if (b->len + lit + 2 > b->cap) { b->overflow = 1; return ELPIS_ETRUNC; }
            memcpy(b->buf + b->len, n->d, lit);
            b->len += lit;
            b->buf[b->len++] = (uint8_t)(0xC0u | (target >> 8));
            b->buf[b->len++] = (uint8_t)(target & 0xFFu);
            /* Register the literal prefix suffixes we just materialised. */
            if (lit > 0) {
                elpis_name_t pre = *n;
                size_t o = start;
                while (pre.len > suffix.len) {
                    if (b->nctab >= ELPIS_BLD_CTAB || o >= 0x4000u)
                        break;
                    b->ctab[b->nctab].off  = (uint16_t)o;
                    b->ctab[b->nctab].name = pre;
                    b->nctab++;
                    o += 1u + (size_t)pre.d[0];
                    if (elpis_name_parent(&pre, &pre) != 0)
                        break;
                }
            }
            return ELPIS_OK;
        }
        if (elpis_name_parent(&suffix, &suffix) != 0)
            break;
    }

    if (elpis_bld_name_raw(b, n) != ELPIS_OK)
        return ELPIS_ETRUNC;
    ctab_add(b, n, start);
    return ELPIS_OK;
}

int elpis_bld_name_raw(elpis_bld_t *b, const elpis_name_t *n)
{
    return elpis_bld_bytes(b, n->d, n->len);
}

int elpis_bld_question(elpis_bld_t *b, const elpis_name_t *n,
                       uint16_t type, uint16_t klass)
{
    size_t start = b->len;
    if (elpis_bld_name_raw(b, n) != ELPIS_OK) return ELPIS_ETRUNC;
    if (elpis_bld_u16(b, type) != ELPIS_OK)   return ELPIS_ETRUNC;
    if (elpis_bld_u16(b, klass) != ELPIS_OK)  return ELPIS_ETRUNC;
    ctab_add(b, n, start);
    b->counts[0]++;
    return ELPIS_OK;
}

int elpis_bld_question_raw(elpis_bld_t *b, const uint8_t *qname, size_t qlen,
                           uint16_t type, uint16_t klass)
{
    size_t start = b->len;
    elpis_name_t n;

    if (qlen == 0 || qlen > ELPIS_MAX_NAME)
        return ELPIS_EFORMAT;
    if (elpis_bld_bytes(b, qname, qlen) != ELPIS_OK) return ELPIS_ETRUNC;
    if (elpis_bld_u16(b, type) != ELPIS_OK)          return ELPIS_ETRUNC;
    if (elpis_bld_u16(b, klass) != ELPIS_OK)         return ELPIS_ETRUNC;
    if (b->compress) {
        size_t used;
        if (elpis_name_parse_nocomp(&n, qname, qlen, &used) == ELPIS_OK && used == qlen)
            ctab_add(b, &n, start);
    }
    b->counts[0]++;
    return ELPIS_OK;
}

int elpis_bld_rr_begin(elpis_bld_t *b, const elpis_name_t *owner,
                       uint16_t type, uint16_t klass, uint32_t ttl,
                       size_t *rdlen_pos)
{
    if (elpis_bld_name(b, owner) != ELPIS_OK) return ELPIS_ETRUNC;
    if (elpis_bld_u16(b, type) != ELPIS_OK)   return ELPIS_ETRUNC;
    if (elpis_bld_u16(b, klass) != ELPIS_OK)  return ELPIS_ETRUNC;
    if (b->track_ttl && b->nttl < b->ttl_cap) {
        b->ttl_off[b->nttl] = (uint32_t)b->len;
        b->ttl_val[b->nttl] = ttl;
        b->nttl++;
    }
    if (elpis_bld_u32(b, ttl) != ELPIS_OK)    return ELPIS_ETRUNC;
    *rdlen_pos = b->len;
    if (elpis_bld_u16(b, 0) != ELPIS_OK)      return ELPIS_ETRUNC;
    return ELPIS_OK;
}

int elpis_bld_rr_end(elpis_bld_t *b, size_t rdlen_pos)
{
    size_t rdlen;
    if (b->overflow)
        return ELPIS_ETRUNC;
    if (rdlen_pos + 2 > b->len)
        return ELPIS_ERR;
    rdlen = b->len - (rdlen_pos + 2);
    if (rdlen > 0xFFFFu)
        return ELPIS_ETRUNC;
    elpis_put16(b->buf + rdlen_pos, (uint16_t)rdlen);
    return ELPIS_OK;
}

int elpis_bld_count(elpis_bld_t *b, elpis_section_t s, int delta)
{
    unsigned idx = (unsigned)s + 1u;
    int v;
    if (idx > 3)
        return ELPIS_ERR;
    v = (int)b->counts[idx] + delta;
    if (v < 0 || v > 0xFFFF)
        return ELPIS_ERR;
    b->counts[idx] = (uint16_t)v;
    return ELPIS_OK;
}

void elpis_bld_finish(elpis_bld_t *b)
{
    if (b->len < ELPIS_HDR_LEN)
        return;
    elpis_put16(b->buf + 4,  b->counts[0]);
    elpis_put16(b->buf + 6,  b->counts[1]);
    elpis_put16(b->buf + 8,  b->counts[2]);
    elpis_put16(b->buf + 10, b->counts[3]);
}
