/*
 * elpis/rdata.h -- per-type RDATA layout, validation and canonicalisation.
 *
 * Every type Elpis understands has a field descriptor.  One table drives
 * three jobs:
 *
 *   - validation      (reject malformed rdata before anything caches it)
 *   - decompression   (rdata copied into the cache must outlive its message)
 *   - canonicalisation(RFC 4034 section 6.2 form for signature verification)
 *
 * Types without a descriptor are handled as opaque per RFC 3597: any length
 * is accepted and the bytes are copied verbatim.
 */
#ifndef ELPIS_RDATA_H
#define ELPIS_RDATA_H

#include "elpis/name.h"

/* Field codes used by the descriptor table. */
enum {
    RDF_END = 0,
    RDF_U8,          /* one octet                                      */
    RDF_U16,
    RDF_U32,
    RDF_U48,         /* EUI-48                                         */
    RDF_U64,         /* EUI-64, L64, NID                               */
    RDF_A,           /* 4-octet IPv4 address                           */
    RDF_AAAA,        /* 16-octet IPv6 address                          */
    RDF_NAME,        /* domain name, compression permitted             */
    RDF_NAME_UNC,    /* domain name, compression forbidden             */
    RDF_STR,         /* <character-string>                             */
    RDF_STRS,        /* one or more <character-string> to end of rdata  */
    RDF_BLOB,        /* remaining octets, possibly zero                 */
    RDF_BLOB1,       /* remaining octets, at least one                  */
    RDF_BITMAP,      /* NSEC-style type bitmap to end of rdata          */
    RDF_NSEC3_SALT,  /* length-prefixed salt                            */
    RDF_NSEC3_HASH,  /* length-prefixed next hashed owner               */
    RDF_SVCPARAMS,   /* SVCB/HTTPS parameter list                       */
    RDF_IPSECKEY,    /* gateway type dependent                          */
    RDF_HIP,         /* HIT/public-key/rendezvous servers               */
    RDF_APL,         /* address prefix list                             */
    RDF_LOC,         /* fixed 16-octet LOC (version 0)                  */
    RDF_WKS,         /* IPv4 + protocol + bitmap                        */
    RDF_AMTRELAY     /* precedence/D/type + relay                       */
};

/*
 * Whether names inside `type`'s rdata are case-folded for the DNSSEC
 * canonical form.  RFC 4034 section 6.2 as corrected by RFC 6840 section 5.1:
 * the list is closed, and types defined afterwards are never folded.
 */
int elpis_rdata_downcase(uint16_t type);

/*
 * Validate rdata in place.  `wire`/`len` are the enclosing message so that
 * compression pointers can be followed.  Returns ELPIS_OK or ELPIS_EFORMAT
 * with *drop set.
 */
int elpis_rdata_validate(uint16_t type, const uint8_t *wire, size_t len,
                         size_t rdoff, uint16_t rdlen, int *drop);

/*
 * Copy rdata into `out`, expanding any compression pointers.  When
 * `downcase` is non-zero the names are folded per elpis_rdata_downcase().
 * Returns ELPIS_OK and sets *outlen, or ELPIS_ETRUNC / ELPIS_EFORMAT.
 */
int elpis_rdata_canonical(uint16_t type, const uint8_t *wire, size_t len,
                          size_t rdoff, uint16_t rdlen,
                          uint8_t *out, size_t outsz, size_t *outlen,
                          int downcase);

/* Extract the single target name of NS/CNAME/DNAME/PTR/MX/SOA-mname rdata. */
int elpis_rdata_target(uint16_t type, const uint8_t *rd, size_t rdlen,
                       elpis_name_t *out);

/* Presentation form, mostly for logs and the debug dump. */
int elpis_rdata_to_text(uint16_t type, const uint8_t *rd, size_t rdlen,
                        char *buf, size_t sz);

/* NSEC/NSEC3 type-bitmap membership test. */
int elpis_bitmap_has(const uint8_t *bm, size_t bmlen, uint16_t type);
int elpis_bitmap_validate(const uint8_t *bm, size_t bmlen);

#endif /* ELPIS_RDATA_H */
