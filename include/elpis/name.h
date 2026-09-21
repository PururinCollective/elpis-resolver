/*
 * elpis/name.h -- DNS owner names.
 *
 * Names are held in uncompressed wire form and, inside the cache and the
 * resolver, always case-folded.  The trailing pad exists so the SIMD
 * lowercase kernel can write in 16-byte blocks without a scalar tail and
 * without ever touching memory it does not own.
 */
#ifndef ELPIS_NAME_H
#define ELPIS_NAME_H

#include "elpis/dns.h"

#define ELPIS_NAME_PAD 16

typedef struct {
    uint8_t  len;      /* wire length including the root label (1..255) */
    uint8_t  labels;   /* label count, root excluded                    */
    uint8_t  d[ELPIS_MAX_NAME + ELPIS_NAME_PAD];
} elpis_name_t;

/* The root, ".", as a ready-made constant. */
extern const elpis_name_t elpis_name_root;

void elpis_name_init_root(elpis_name_t *n);

/*
 * Parse a (possibly compressed) name at `off` in `msg`.
 * `*end` receives the offset just past the name as it appears in the message
 * -- i.e. past the first pointer, not past the target.  Returns ELPIS_OK or
 * ELPIS_EFORMAT with `*drop` describing why.
 */
int elpis_name_parse(elpis_name_t *n, const uint8_t *msg, size_t msglen,
                     size_t off, size_t *end, int *drop);

/* Parse without compression support (rdata of RFC 3597-opaque types). */
int elpis_name_parse_nocomp(elpis_name_t *n, const uint8_t *p, size_t len,
                            size_t *used);

/* Presentation format, with \DDD and \. escapes per RFC 1035 section 5.1. */
int elpis_name_from_text(elpis_name_t *n, const char *s);
int elpis_name_to_text(const elpis_name_t *n, char *buf, size_t sz);

/* Case-fold in place.  Idempotent. */
void elpis_name_lower(elpis_name_t *n);
/* Case-folded 64-bit hash. */
uint64_t elpis_name_hash(const elpis_name_t *n);

int elpis_name_eq(const elpis_name_t *a, const elpis_name_t *b);
ELPIS_INLINE int elpis_name_is_root(const elpis_name_t *n) { return n->len == 1; }

/* Strip the leftmost label.  Returns -1 when `n` is already the root. */
int elpis_name_parent(const elpis_name_t *n, elpis_name_t *out);
/* Keep only the rightmost `keep` labels (keep == 0 yields the root). */
int elpis_name_suffix(const elpis_name_t *n, unsigned keep, elpis_name_t *out);
/* 1 when `sub` is equal to or below `parent`. */
int elpis_name_is_subdomain(const elpis_name_t *sub, const elpis_name_t *parent);
/* Number of trailing labels `a` and `b` share. */
unsigned elpis_name_common_labels(const elpis_name_t *a, const elpis_name_t *b);
/* Prepend one label to `parent`; used for NSEC3 and QNAME minimisation. */
int elpis_name_prepend(elpis_name_t *out, const uint8_t *label, size_t llen,
                       const elpis_name_t *parent);
/* Replace the `owner` suffix of `n` with `target` (DNAME, RFC 6672). */
int elpis_name_substitute(const elpis_name_t *n, const elpis_name_t *owner,
                          const elpis_name_t *target, elpis_name_t *out);

/* DNSSEC canonical ordering, RFC 4034 section 6.1.  <0, 0, >0. */
int elpis_name_canon_cmp(const elpis_name_t *a, const elpis_name_t *b);

/* 1 when any label is a wildcard "*" in the leftmost position. */
int elpis_name_is_wildcard(const elpis_name_t *n);

/* Scratch helper: a short printable form for log lines. */
const char *elpis_name_str(const elpis_name_t *n, char *buf, size_t sz);

#endif /* ELPIS_NAME_H */
