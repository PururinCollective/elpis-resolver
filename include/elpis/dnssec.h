/*
 * elpis/dnssec.h -- validation.
 */
#ifndef ELPIS_DNSSEC_H
#define ELPIS_DNSSEC_H

#include "elpis/name.h"
#include "elpis/store.h"
#include "elpis/conf.h"

/* ---- trust anchors ------------------------------------------------ */
typedef struct {
    elpis_name_t name;
    uint16_t     keytag;
    uint8_t      alg;
    uint8_t      digest_type;
    uint8_t      digest[64];
    uint8_t      digest_len;
} elpis_ta_t;

struct elpis_ta_store {
    elpis_ta_t *ta;
    unsigned    n, cap;
};

/* C99 forbids repeating a typedef; both headers need this name. */
#ifndef ELPIS_TA_STORE_TYPEDEF
#define ELPIS_TA_STORE_TYPEDEF
typedef struct elpis_ta_store elpis_ta_store_t;
#endif

elpis_ta_store_t *elpis_ta_new(void);
void elpis_ta_free(elpis_ta_store_t *s);
/* Load the built-in IANA root anchors. */
int  elpis_ta_add_builtin(elpis_ta_store_t *s);
/* Parse a file of "name IN DS tag alg digest-type hex" / DNSKEY lines. */
int  elpis_ta_load_file(elpis_ta_store_t *s, const char *path);
/* Deepest anchor at or above `name`; NULL when there is none. */
const elpis_name_t *elpis_ta_closest(const elpis_ta_store_t *s,
                                     const elpis_name_t *name);
unsigned elpis_ta_for(const elpis_ta_store_t *s, const elpis_name_t *zone,
                      const elpis_ta_t **out, unsigned max);

/* ---- primitives --------------------------------------------------- */
/* RFC 4034 appendix B. */
uint16_t elpis_dnskey_tag(const uint8_t *rdata, size_t len);
/* Map a DNSSEC algorithm number to the hash it signs with. */
int  elpis_alg_hash(const elpis_conf_t *c, uint8_t alg);
int  elpis_alg_supported(const elpis_conf_t *c, uint8_t alg);
int  elpis_digest_supported(uint8_t digest_type);

/* DS(child DNSKEY) == ds rdata? */
int  elpis_ds_matches(const elpis_name_t *owner,
                      const uint8_t *dnskey, size_t keylen,
                      const uint8_t *ds, size_t dslen);

/*
 * Verify one RRset against one RRSIG and one DNSKEY.  `rd`/`rdlen` are the
 * canonical (decompressed) rdata of each record, already owned by the caller.
 * Returns ELPIS_OK, ELPIS_EBOGUS, or ELPIS_ENOTFOUND when the signature does
 * not apply to this key at all.
 */
int elpis_rrsig_verify(const elpis_conf_t *conf,
                       const elpis_name_t *owner, uint16_t type, uint16_t klass,
                       const uint8_t *const *rd, const uint16_t *rdlen,
                       unsigned count,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *key, size_t keylen,
                       int64_t now, int *ede);

/* Verify an RRset against every key in a DNSKEY RRset. */
int elpis_rrset_validate(const elpis_conf_t *conf,
                         const elpis_rrset_buf_t *set,
                         const elpis_rrset_buf_t *keys,
                         int64_t now, elpis_name_t *wildcard_out, int *ede);

/* Validate a DNSKEY RRset against a DS RRset (or trust anchors). */
int elpis_dnskey_validate_ds(const elpis_conf_t *conf,
                             const elpis_rrset_buf_t *keys,
                             const elpis_rrset_buf_t *ds,
                             int64_t now, int *ede);
int elpis_dnskey_validate_ta(const elpis_conf_t *conf,
                             const elpis_ta_store_t *store,
                             const elpis_rrset_buf_t *keys,
                             int64_t now, int *ede);

/* ---- denial of existence ------------------------------------------ */
/*
 * The proof records, already decompressed.  Passing a flat array keeps the
 * NSEC and NSEC3 logic independent of how the caller stores records.
 */
typedef struct {
    elpis_name_t   owner;
    const uint8_t *rd;
    uint16_t       rdlen;
} elpis_denial_rr_t;

/* NSEC (nsec.c) */
int elpis_nsec_covers(const elpis_denial_rr_t *r, const elpis_name_t *name);
int elpis_nsec_proves_nxdomain(const elpis_denial_rr_t *rrs, unsigned n,
                               const elpis_name_t *qname);
int elpis_nsec_proves_nodata(const elpis_denial_rr_t *rrs, unsigned n,
                             const elpis_name_t *qname, uint16_t qtype);
int elpis_nsec_proves_no_ds(const elpis_denial_rr_t *rrs, unsigned n,
                            const elpis_name_t *qname);

/* NSEC3 (nsec3.c) */
int elpis_nsec3_hash(const elpis_name_t *name, const uint8_t *salt,
                     uint8_t saltlen, uint16_t iterations, uint8_t alg,
                     uint8_t *out, size_t *outlen);
int elpis_nsec3_proves_nxdomain(const elpis_denial_rr_t *rrs, unsigned n,
                                const elpis_name_t *qname,
                                const elpis_name_t *zone);
int elpis_nsec3_proves_nodata(const elpis_denial_rr_t *rrs, unsigned n,
                              const elpis_name_t *qname, uint16_t qtype,
                              const elpis_name_t *zone);
int elpis_nsec3_proves_no_ds(const elpis_denial_rr_t *rrs, unsigned n,
                             const elpis_name_t *qname,
                             const elpis_name_t *zone);
/* Largest iteration count we are willing to compute (RFC 9276). */
#define ELPIS_NSEC3_MAX_ITER 100

/* Base32hex, as NSEC3 owner names use it. */
int elpis_base32hex_encode(const uint8_t *in, size_t n, char *out, size_t cap);
int elpis_base32hex_decode(const char *in, size_t n, uint8_t *out, size_t cap,
                           size_t *outlen);

#endif /* ELPIS_DNSSEC_H */
