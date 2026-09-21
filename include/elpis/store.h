/*
 * elpis/store.h -- the two data caches.
 *
 * mcache  Whole prebuilt responses, keyed by (qname, qtype, qclass, DO|CD).
 *         A hit is answered by writing a 12-byte header, echoing the client's
 *         question verbatim and memcpy'ing one blob, then patching TTLs in
 *         place.  No record is re-encoded and no name is re-compressed.
 *
 *         The trick that makes this safe is that the key fixes the question
 *         length, so every compression pointer inside the blob still aims at
 *         the same offset it did when the blob was built.
 *
 * rcache  Individual RRsets with their RRSIGs.  This is what the resolver and
 *         the validator work on: delegations, DNSKEY/DS chains, CNAME chains.
 */
#ifndef ELPIS_STORE_H
#define ELPIS_STORE_H

#include "elpis/cache.h"
#include "elpis/name.h"
#include "elpis/msg.h"

/* ================================================================== */
/* Message cache                                                       */
/* ================================================================== */

#define ELPIS_MK_DO  0x01u      /* DNSSEC OK was set on the query  */
#define ELPIS_MK_CD  0x02u      /* checking disabled               */

typedef struct {
    const uint8_t *qname;       /* case-folded wire form           */
    uint8_t        qnamelen;
    uint8_t        kflags;
    uint16_t       qtype;
    uint16_t       qclass;
    uint64_t       hash;        /* filled by elpis_mkey_hash()     */
} elpis_mkey_t;

void elpis_mkey_hash(elpis_mkey_t *k);

typedef struct {
    unsigned rcode;
    elpis_sec_t sec;
    uint32_t ttl;               /* seconds remaining               */
    unsigned stale     : 1;     /* served past expiry (RFC 8767)   */
    unsigned truncated : 1;
    unsigned dropped_ar: 1;
    unsigned dropped_ns: 1;
    unsigned want_prefetch : 1; /* nearly expired; refresh it      */
    uint16_t ancount, nscount, arcount;
} elpis_mserve_t;

elpis_cache_t *elpis_mcache_new(uint64_t bytes, unsigned shards);

/*
 * Assemble a response for `k` into `out`.
 *  id          transaction id to stamp
 *  qname_wire  the client's question name, echoed byte for byte so 0x20
 *              case encoding survives
 *  base_flags  QR/RD/RA and friends; the rcode and AD bit are added here
 *  budget      largest message we may produce (UDP payload size, or 65535)
 *  serve_stale seconds past expiry we are willing to serve
 * Returns ELPIS_OK on a hit, ELPIS_ENOTFOUND on a miss.
 */
int elpis_mcache_serve(elpis_cache_t *c, const elpis_mkey_t *k,
                       uint16_t id, const uint8_t *qname_wire,
                       uint16_t base_flags, size_t budget,
                       uint32_t serve_stale, uint32_t stale_ttl,
                       unsigned prefetch_pct,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       elpis_mserve_t *info);

/*
 * Store a response.  `wire`/`len` is a complete message whose question
 * matches `k`; `qend` is the offset just past the question.  Any OPT record
 * must already have been excluded from the message and from arcount.
 * `ttl_off`/`ttl_val` are the message-relative TTL field offsets recorded by
 * the builder.
 */
/*
 * How a background refresh ended, for elpis_mcache_refresh_outcome().  An
 * NXDOMAIN has to repeat `nx_confirm` times in a row before the cached answer
 * is given up, so one bad reply cannot take a live name down.
 */
#define ELPIS_REFRESH_FAILED    0
#define ELPIS_REFRESH_NXDOMAIN  1
/* Returns 1 when the cached answer was given up and should be re-resolved. */
int elpis_mcache_refresh_outcome(elpis_cache_t *c, const elpis_mkey_t *k,
                                 int outcome, unsigned nx_confirm);

int elpis_mcache_store(elpis_cache_t *c, const elpis_mkey_t *k,
                       const uint8_t *wire, size_t len, size_t qend,
                       const uint32_t *ttl_off, const uint32_t *ttl_val,
                       unsigned nttl, size_t ns_off, size_t ar_off,
                       unsigned rcode, uint16_t flags, elpis_sec_t sec,
                       uint32_t ttl, uint32_t max_stale);

/* ================================================================== */
/* RRset cache                                                         */
/* ================================================================== */

#define ELPIS_RRSET_MAX_RR  96
#define ELPIS_RRSET_BUF     20480

/* A negative marker: "this name does not exist" (RFC 8020 NXDOMAIN cut). */
#define ELPIS_T_NXNAME      0    /* type 0 is reserved, so it is free here */

typedef struct {
    elpis_name_t name;
    uint16_t     type;
    uint16_t     klass;
    uint32_t     ttl;          /* seconds remaining at lookup time */
    uint32_t     orig_ttl;
    uint8_t      sec;          /* elpis_sec_t                      */
    uint8_t      count;        /* data records                     */
    uint8_t      sigcount;     /* RRSIGs following the data        */
    uint8_t      flags;
    uint16_t     len[ELPIS_RRSET_MAX_RR];
    uint32_t     off[ELPIS_RRSET_MAX_RR];
    uint32_t     used;
    uint8_t      data[ELPIS_RRSET_BUF];
} elpis_rrset_buf_t;

#define ELPIS_RRF_WILDCARD 0x01u   /* answer was synthesised from a wildcard */
#define ELPIS_RRF_GLUE     0x02u   /* learned from a delegation's additional */
#define ELPIS_RRF_AUTH     0x04u   /* came from an authoritative answer      */
/*
 * Negative entries.  The single stored "record" is the proving SOA, encoded
 * as: uint8_t owner_len, owner wire, then the SOA rdata.  Keeping the SOA
 * with the marker means a cached NXDOMAIN can be replayed with its own
 * authority section instead of an empty one.
 */
#define ELPIS_RRF_NXDOMAIN 0x08u
#define ELPIS_RRF_NODATA   0x10u

elpis_cache_t *elpis_rcache_new(uint64_t bytes, unsigned shards);

int elpis_rcache_get(elpis_cache_t *c, const elpis_name_t *name,
                     uint16_t type, uint16_t klass, uint32_t now,
                     uint32_t serve_stale, elpis_rrset_buf_t *out);

int elpis_rcache_put(elpis_cache_t *c, const elpis_name_t *name,
                     uint16_t type, uint16_t klass, uint32_t ttl,
                     elpis_sec_t sec, uint8_t flags,
                     const uint8_t *const *rd, const uint16_t *rdlen,
                     unsigned count,
                     const uint8_t *const *sig, const uint16_t *siglen,
                     unsigned sigcount, uint32_t max_stale, int pinned);

/* Convenience: store straight from an elpis_rrset_buf_t. */
int elpis_rcache_put_buf(elpis_cache_t *c, const elpis_rrset_buf_t *b,
                         uint32_t max_stale, int pinned);

int elpis_rcache_del(elpis_cache_t *c, const elpis_name_t *name,
                     uint16_t type, uint16_t klass);

/* Helpers for assembling an elpis_rrset_buf_t. */
void elpis_rrset_buf_init(elpis_rrset_buf_t *b, const elpis_name_t *name,
                          uint16_t type, uint16_t klass, uint32_t ttl);
int  elpis_rrset_buf_add(elpis_rrset_buf_t *b, const uint8_t *rd, uint16_t len);

/*
 * Copy only the part of the buffer that holds anything.
 *
 * The struct carries a 20 KiB data area so that the largest RRset that can
 * exist fits, and plain assignment copies all of it however little is in use.
 * A DS is about a hundred bytes; copying twenty thousand to move it was the
 * single largest consumer of CPU in the validator, which does this for every
 * zone of every chain walk.
 */
void elpis_rrset_buf_copy(elpis_rrset_buf_t *dst, const elpis_rrset_buf_t *src);
int  elpis_rrset_buf_add_sig(elpis_rrset_buf_t *b, const uint8_t *rd, uint16_t len);
ELPIS_INLINE const uint8_t *elpis_rrset_rd(const elpis_rrset_buf_t *b, unsigned i)
{
    return b->data + b->off[i];
}

#endif /* ELPIS_STORE_H */
