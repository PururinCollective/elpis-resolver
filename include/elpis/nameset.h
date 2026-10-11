/*
 * elpis/nameset.h -- a fixed set of names, each standing for itself and
 * everything below it.
 *
 * Built once from a list in text, then asked whether a name is in it or under
 * it.  The question's suffixes are looked up in a hash table, one per label,
 * so asking costs the same few lookups however long the list grows.  The
 * built-in blocklist (blocklist.c) and forward list (forwardlist.c) are each
 * one of these.
 */
#ifndef ELPIS_NAMESET_H
#define ELPIS_NAMESET_H

#include "elpis/name.h"

typedef struct {
    uint64_t       hash;
    const uint8_t *name;            /* wire form, lower case; NULL: empty */
    uint8_t        len;
} elpis_nameset_slot_t;

typedef struct {
    elpis_nameset_slot_t *slot;
    size_t                mask;
    uint8_t              *wire;     /* every name, back to back */
    unsigned              count;
    /* Suffixes with more or fewer labels than any entry are not looked up. */
    unsigned              min_labels, max_labels;
} elpis_nameset_t;

/*
 * Fill `s` from `n` names in text.  A name that does not parse, or the root,
 * is skipped with a warning that starts with `what`.  Out of memory, the set
 * is left empty and matches nothing.  Never freed: a set lives as long as the
 * process.
 */
void elpis_nameset_build(elpis_nameset_t *s, const char *const *names,
                         size_t n, const char *what);

/*
 * Labels in the deepest name of `s` that `qname` is, or is below, in any
 * case; 0 when there is none.  No set holds the root, so 0 is never a match.
 */
unsigned elpis_nameset_match(const elpis_nameset_t *s,
                             const elpis_name_t *qname);

#endif /* ELPIS_NAMESET_H */
