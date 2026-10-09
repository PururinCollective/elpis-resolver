/*
 * blocklist.c -- names answered REFUSED before anything else is done.
 *
 * What a match does, and why, is in elpis/blocklist.h.  This is the list.
 *
 * It is gathered by the ElpisDNS honeypot, a resolver that serves no one, so
 * every name it is asked was chosen by whoever is scanning, flooding or
 * tunnelling through open resolvers.  The published copy is
 *
 *   https://raw.githubusercontent.com/Anime4000/ElpisDNS/refs/heads/main/bogus.txt
 *
 * in filter syntax, "||name^": the name and everything below it, which is
 * what an entry here means too.  These are the names it held on 2026-10-09.
 * To bring the list up to date, put what this prints in place of the entries
 * below:
 *
 *   curl -s <the URL above> | sed -n 's/^||\(.*\)\^$/    "\1",/p'
 *
 * An entry is a name, not a pattern.  The question's suffixes are looked up
 * in a hash table, one per label, so a query costs the same few lookups
 * however long the list grows; a linear walk like the quirk list's would put
 * the length of this list on every query the resolver answers.
 */
#include "elpis/blocklist.h"
#include "elpis/log.h"
#include "elpis/simd.h"
#include "elpis/util.h"

#include <pthread.h>
#include <string.h>

static const char *const k_names[] = {
    "ruck-fi.com",
    "darkorb.net",
    "fusu.cc",
    "hmdns.top",
    "cfpro.ru",
    "z6r8.com",
    "vtb.com",
    "heimaoip.com",
    "sikelocci.com",
    "v2z.ru",
    "vpnv.shop",
};

#define NNAMES ELPIS_ARRAY_LEN(k_names)
#define SEED   0xB10C4B10C4B10C4Bull

typedef struct {
    uint64_t       hash;
    const uint8_t *name;            /* wire form, lower case; NULL: empty */
    uint8_t        len;
} slot_t;

static slot_t        *g_slot;
static size_t         g_mask;
static uint8_t       *g_wire;       /* every name, back to back */
static unsigned       g_count;
/* Suffixes with more or fewer labels than any entry are not looked up. */
static unsigned       g_min_labels, g_max_labels;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static slot_t *find(const uint8_t *d, size_t len, uint64_t h)
{
    size_t j;

    for (j = (size_t)h & g_mask; g_slot[j].name != NULL; j = (j + 1) & g_mask)
        if (g_slot[j].hash == h && g_slot[j].len == len &&
            elpis_eq_ci(d, g_slot[j].name, len))
            return &g_slot[j];
    return &g_slot[j];              /* the empty slot it would go in */
}

static void build(void)
{
    size_t i, slots = 4, total = 0, used = 0;

    for (i = 0; i < NNAMES; i++)
        total += strlen(k_names[i]) + 2;    /* wire form is never longer */
    /* At most half full, so a miss finds an empty slot in a probe or two. */
    while (slots < 2 * NNAMES)
        slots <<= 1;
    g_wire = (uint8_t *)elpis_malloc(total);
    g_slot = (slot_t *)elpis_calloc(slots, sizeof *g_slot);
    if (g_wire == NULL || g_slot == NULL) {
        elpis_free(g_wire);
        elpis_free(g_slot);
        g_wire = NULL;
        g_slot = NULL;
        elpis_warn("blocklist: out of memory; nothing will be blocked");
        return;
    }
    g_mask = slots - 1;
    g_min_labels = ELPIS_MAX_LABELS;

    for (i = 0; i < NNAMES; i++) {
        elpis_name_t n;
        slot_t *s;
        uint64_t h;

        /* The root would block everything: refused like a bad name. */
        if (elpis_name_from_text(&n, k_names[i]) != ELPIS_OK || n.labels == 0) {
            elpis_warn("blocklist: \"%s\" is not a name; skipped", k_names[i]);
            continue;
        }
        elpis_name_lower(&n);
        h = elpis_simd_hash_ci(n.d, n.len, SEED);
        s = find(n.d, n.len, h);
        if (s->name != NULL)
            continue;               /* listed twice */
        memcpy(g_wire + used, n.d, n.len);
        s->hash = h;
        s->name = g_wire + used;
        s->len  = n.len;
        used += n.len;
        g_count++;
        if (n.labels < g_min_labels) g_min_labels = n.labels;
        if (n.labels > g_max_labels) g_max_labels = n.labels;
    }
}

int elpis_blocklist_match(const elpis_name_t *qname)
{
    size_t off = 0;
    unsigned labels;

    pthread_once(&g_once, build);
    if (g_count == 0)
        return 0;

    /*
     * From the whole name up, one label off the left each time; the suffix
     * at `off` has `labels` labels.  A random-label flood under a listed
     * name usually has more labels than any entry, so most of its suffixes
     * are skipped without being hashed.
     */
    for (labels = qname->labels; labels >= g_min_labels; labels--) {
        if (off >= qname->len || qname->d[off] == 0)
            break;
        if (labels <= g_max_labels) {
            size_t len = (size_t)qname->len - off;
            uint64_t h = elpis_simd_hash_ci(qname->d + off, len, SEED);
            if (find(qname->d + off, len, h)->name != NULL)
                return 1;
        }
        off += 1u + (size_t)qname->d[off];
    }
    return 0;
}

unsigned elpis_blocklist_count(void)
{
    pthread_once(&g_once, build);
    return g_count;
}
