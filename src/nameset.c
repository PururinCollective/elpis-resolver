/*
 * nameset.c -- a fixed set of names, looked up one label suffix at a time.
 *
 * Moved out of blocklist.c when the forward list needed the same table.  A
 * linear walk like the quirk list's would put the length of a list on every
 * query that asks it; a hash per suffix costs the same whatever the length.
 */
#include "elpis/nameset.h"
#include "elpis/log.h"
#include "elpis/simd.h"
#include "elpis/util.h"

#include <string.h>

#define SEED 0xB10C4B10C4B10C4Bull

static elpis_nameset_slot_t *find(const elpis_nameset_t *s, const uint8_t *d,
                                  size_t len, uint64_t h)
{
    size_t j;

    for (j = (size_t)h & s->mask; s->slot[j].name != NULL;
         j = (j + 1) & s->mask)
        if (s->slot[j].hash == h && s->slot[j].len == len &&
            elpis_eq_ci(d, s->slot[j].name, len))
            return &s->slot[j];
    return &s->slot[j];             /* the empty slot it would go in */
}

void elpis_nameset_build(elpis_nameset_t *s, const char *const *names,
                         size_t n, const char *what)
{
    size_t i, slots = 4, total = 0, used = 0;

    memset(s, 0, sizeof *s);
    for (i = 0; i < n; i++)
        total += strlen(names[i]) + 2;      /* wire form is never longer */
    /* At most half full, so a miss finds an empty slot in a probe or two. */
    while (slots < 2 * n)
        slots <<= 1;
    s->wire = (uint8_t *)elpis_malloc(total);
    s->slot = (elpis_nameset_slot_t *)elpis_calloc(slots, sizeof *s->slot);
    if (s->wire == NULL || s->slot == NULL) {
        elpis_free(s->wire);
        elpis_free(s->slot);
        memset(s, 0, sizeof *s);
        elpis_warn("%s: out of memory; the list is empty", what);
        return;
    }
    s->mask = slots - 1;
    s->min_labels = ELPIS_MAX_LABELS;

    for (i = 0; i < n; i++) {
        elpis_name_t nm;
        elpis_nameset_slot_t *sl;
        uint64_t h;

        /* The root would match everything: refused like a bad name. */
        if (elpis_name_from_text(&nm, names[i]) != ELPIS_OK || nm.labels == 0) {
            elpis_warn("%s: \"%s\" is not a name; skipped", what, names[i]);
            continue;
        }
        elpis_name_lower(&nm);
        h = elpis_simd_hash_ci(nm.d, nm.len, SEED);
        sl = find(s, nm.d, nm.len, h);
        if (sl->name != NULL)
            continue;               /* listed twice */
        memcpy(s->wire + used, nm.d, nm.len);
        sl->hash = h;
        sl->name = s->wire + used;
        sl->len  = nm.len;
        used += nm.len;
        s->count++;
        if (nm.labels < s->min_labels) s->min_labels = nm.labels;
        if (nm.labels > s->max_labels) s->max_labels = nm.labels;
    }
}

unsigned elpis_nameset_match(const elpis_nameset_t *s,
                             const elpis_name_t *qname)
{
    size_t off = 0;
    unsigned labels;

    if (s->count == 0)
        return 0;

    /*
     * From the whole name up, one label off the left each time; the suffix
     * at `off` has `labels` labels, so the first match is the deepest.  A
     * random-label flood under a listed name usually has more labels than
     * any entry, so most of its suffixes are skipped without being hashed.
     */
    for (labels = qname->labels; labels >= s->min_labels; labels--) {
        if (off >= qname->len || qname->d[off] == 0)
            break;
        if (labels <= s->max_labels) {
            size_t len = (size_t)qname->len - off;
            uint64_t h = elpis_simd_hash_ci(qname->d + off, len, SEED);
            if (find(s, qname->d + off, len, h)->name != NULL)
                return labels;
        }
        off += 1u + (size_t)qname->d[off];
    }
    return 0;
}
