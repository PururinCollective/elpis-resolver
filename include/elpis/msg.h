/*
 * elpis/msg.h -- DNS message parsing and construction.
 *
 * The parser is zero-copy: records are described by offsets into the caller's
 * buffer.  It is also total -- every structural rule in RFC 1035 section 4 is
 * checked before any consumer sees the message, and a failure names the drop
 * reason for the log.
 */
#ifndef ELPIS_MSG_H
#define ELPIS_MSG_H

#include "elpis/name.h"
#include "elpis/log.h"

/* ------------------------------------------------------------------ */
/* Parsing                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount, ancount, nscount, arcount;
} elpis_hdr_t;

typedef struct {
    elpis_name_t name;
    uint16_t     type;
    uint16_t     klass;
    uint32_t     ttl;
    uint16_t     rdlen;
    size_t       rdoff;    /* offset of rdata within the message   */
    size_t       rroff;    /* offset of the owner name             */
    size_t       next;     /* offset just past this record         */
} elpis_rr_t;

typedef enum {
    ELPIS_SEC_ANSWER = 0,
    ELPIS_SEC_AUTHORITY = 1,
    ELPIS_SEC_ADDITIONAL = 2,
    ELPIS_SEC__COUNT = 3
} elpis_section_t;

typedef struct {
    const uint8_t *wire;
    size_t         len;
    elpis_hdr_t    hdr;

    elpis_name_t   qname;
    uint16_t       qtype;
    uint16_t       qclass;
    size_t         qend;              /* offset past the question       */

    size_t         sec_off[ELPIS_SEC__COUNT];
    uint16_t       sec_cnt[ELPIS_SEC__COUNT];

    /* EDNS(0) -- populated when an OPT record is present. */
    unsigned       have_opt : 1;
    unsigned       do_bit   : 1;
    unsigned       have_cookie : 1;
    unsigned       have_ecs : 1;
    uint16_t       edns_bufsize;
    uint8_t        edns_version;
    uint8_t        edns_rcode_hi;      /* upper 8 bits of the ext. rcode */
    uint16_t       edns_flags;
    size_t         opt_off;            /* start of the OPT RR            */
    size_t         opt_rdoff;
    uint16_t       opt_rdlen;
    uint8_t        cookie[40];
    uint8_t        cookie_len;
} elpis_msg_t;

ELPIS_INLINE unsigned elpis_msg_rcode(const elpis_msg_t *m)
{
    return (unsigned)(m->hdr.flags & ELPIS_RCODE_MASK) |
           ((unsigned)m->edns_rcode_hi << 4);
}
ELPIS_INLINE unsigned elpis_msg_opcode(const elpis_msg_t *m)
{
    return (unsigned)((m->hdr.flags & ELPIS_OPCODE_MASK) >> ELPIS_OPCODE_SHIFT);
}

/* Parse just the 12-byte header.  Returns ELPIS_EFORMAT when len < 12. */
int elpis_hdr_parse(elpis_hdr_t *h, const uint8_t *wire, size_t len);

/*
 * Full structural validation.  `flags` selects how strict to be:
 *  ELPIS_PARSE_QUERY     -- expect a client query (QR clear, qdcount 1)
 *  ELPIS_PARSE_RESPONSE  -- expect a response (QR set)
 *  ELPIS_PARSE_ANY       -- accept either
 * On failure *drop carries an elpis_drop_t.
 */
#define ELPIS_PARSE_QUERY     0x01u
#define ELPIS_PARSE_RESPONSE  0x02u
#define ELPIS_PARSE_ANY       0x03u
#define ELPIS_PARSE_NO_WALK   0x04u   /* skip the full record walk        */

int elpis_msg_parse(elpis_msg_t *m, const uint8_t *wire, size_t len,
                    unsigned flags, int *drop);

/* Record iteration. */
typedef struct {
    const uint8_t *wire;
    size_t         len;
    size_t         off;
    uint16_t       remain;
} elpis_rr_iter_t;

void elpis_rr_iter(elpis_rr_iter_t *it, const elpis_msg_t *m, elpis_section_t s);
/* Returns ELPIS_OK, ELPIS_ENOTFOUND at the end, or ELPIS_EFORMAT. */
int  elpis_rr_next(elpis_rr_iter_t *it, elpis_rr_t *rr, int *drop);

/* ------------------------------------------------------------------ */
/* Building                                                            */
/* ------------------------------------------------------------------ */

#define ELPIS_BLD_CTAB 64

typedef struct {
    uint16_t     off;
    elpis_name_t name;
} elpis_cslot_t;

typedef struct {
    uint8_t  *buf;
    size_t    cap;
    size_t    len;
    unsigned  compress : 1;
    unsigned  overflow : 1;     /* a write did not fit; message is partial */
    unsigned  track_ttl : 1;
    uint16_t  counts[4];        /* qd, an, ns, ar                          */
    size_t    rrstart;          /* offset of the record currently open     */

    /* Offsets of TTL fields, for the message cache's in-place TTL patch. */
    uint32_t *ttl_off;
    uint32_t *ttl_val;
    unsigned  nttl;
    unsigned  ttl_cap;

    elpis_cslot_t *ctab;        /* compression targets                     */
    unsigned  nctab;
} elpis_bld_t;

/* `ctab` may be NULL to disable compression entirely. */
void elpis_bld_init(elpis_bld_t *b, uint8_t *buf, size_t cap,
                    elpis_cslot_t *ctab, int compress);
/* Enable TTL offset recording into caller-owned arrays. */
void elpis_bld_track_ttl(elpis_bld_t *b, uint32_t *off, uint32_t *val, unsigned cap);

int  elpis_bld_header(elpis_bld_t *b, uint16_t id, uint16_t flags);
int  elpis_bld_question(elpis_bld_t *b, const elpis_name_t *n,
                        uint16_t type, uint16_t klass);
/* Raw question bytes (echoes the client's 0x20 casing verbatim). */
int  elpis_bld_question_raw(elpis_bld_t *b, const uint8_t *qname, size_t qlen,
                            uint16_t type, uint16_t klass);
int  elpis_bld_name(elpis_bld_t *b, const elpis_name_t *n);
int  elpis_bld_name_raw(elpis_bld_t *b, const elpis_name_t *n);   /* no pointers */
int  elpis_bld_bytes(elpis_bld_t *b, const void *p, size_t n);
int  elpis_bld_u16(elpis_bld_t *b, uint16_t v);
int  elpis_bld_u32(elpis_bld_t *b, uint32_t v);

/* Open a record; returns the offset of its rdlength field via *rdlen_pos. */
int  elpis_bld_rr_begin(elpis_bld_t *b, const elpis_name_t *owner,
                        uint16_t type, uint16_t klass, uint32_t ttl,
                        size_t *rdlen_pos);
int  elpis_bld_rr_end(elpis_bld_t *b, size_t rdlen_pos);
/* Copy an already-encoded record, rewriting embedded names is NOT attempted. */
int  elpis_bld_count(elpis_bld_t *b, elpis_section_t s, int delta);
void elpis_bld_finish(elpis_bld_t *b);

/* Mark a rollback point and rewind to it (used when a section overflows). */
typedef struct { size_t len; uint16_t counts[4]; unsigned nctab, nttl; } elpis_bld_mark_t;
void elpis_bld_mark(const elpis_bld_t *b, elpis_bld_mark_t *m);
void elpis_bld_rollback(elpis_bld_t *b, const elpis_bld_mark_t *m);

#endif /* ELPIS_MSG_H */
