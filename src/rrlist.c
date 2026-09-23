/*
 * rrlist.c -- record accumulator.
 */
#include "elpis/rrlist.h"
#include "elpis/util.h"
#include "elpis/simd.h"

#define RRLIST_RR_MIN   16
#define RRLIST_POOL_MIN 512
#define RRLIST_RR_MAX   512
#define RRLIST_POOL_MAX (256u * 1024u)

void elpis_rrlist_init(elpis_rrlist_t *l)
{
    memset(l, 0, sizeof *l);
}

void elpis_rrlist_clear(elpis_rrlist_t *l)
{
    l->n = 0;
    l->plen = 0;
    l->zone_labels = 0;
}

void elpis_rrlist_free(elpis_rrlist_t *l)
{
    elpis_free(l->rr);
    elpis_free(l->pool);
    memset(l, 0, sizeof *l);
}

static int pool_reserve(elpis_rrlist_t *l, uint32_t need)
{
    uint32_t want;
    uint8_t *p;

    if (l->plen + need <= l->pcap)
        return ELPIS_OK;
    want = l->pcap ? l->pcap : RRLIST_POOL_MIN;
    while (want < l->plen + need) {
        if (want >= RRLIST_POOL_MAX)
            return ELPIS_ENOMEM;
        want *= 2u;
    }
    p = (uint8_t *)elpis_realloc(l->pool, want);
    if (p == NULL)
        return ELPIS_ENOMEM;
    l->pool = p;
    l->pcap = want;
    return ELPIS_OK;
}

int elpis_rrlist_add(elpis_rrlist_t *l, elpis_section_t sec,
                     const elpis_name_t *name, uint16_t type, uint16_t klass,
                     uint32_t ttl, const uint8_t *rd, uint16_t rdlen)
{
    elpis_trr_t *e;

    if (l->n >= RRLIST_RR_MAX)
        return ELPIS_ENOMEM;
    if (l->n == l->cap) {
        unsigned want = l->cap ? l->cap * 2u : RRLIST_RR_MIN;
        elpis_trr_t *nr = (elpis_trr_t *)elpis_realloc(l->rr, want * sizeof *nr);
        if (nr == NULL)
            return ELPIS_ENOMEM;
        l->rr = nr;
        l->cap = want;
    }
    if (pool_reserve(l, (uint32_t)name->len + rdlen) != ELPIS_OK)
        return ELPIS_ENOMEM;

    e = &l->rr[l->n];
    e->nameoff = l->plen;
    e->namelen = name->len;
    memcpy(l->pool + l->plen, name->d, name->len);
    l->plen += name->len;

    e->rdoff = l->plen;
    e->rdlen = rdlen;
    if (rdlen) {
        memcpy(l->pool + l->plen, rd, rdlen);
        l->plen += rdlen;
    }

    e->type    = type;
    e->klass   = klass;
    e->ttl     = ttl;
    e->section = (uint8_t)sec;
    /*
     * The stamp applies to exactly one record and then clears itself.  Only
     * the caller that knows which zone served the record -- the one taking it
     * off the wire, or a cache replay carrying the stamp recorded then -- may
     * set it; DNS64 synthesis and local data must leave the record marked
     * unknown rather than silently inherit whatever the previous hop set.
     * Consuming it here makes that the default.
     */
    e->zone_labels = l->zone_labels;
    l->zone_labels = 0;
    l->n++;
    return ELPIS_OK;
}

int elpis_rrlist_has(const elpis_rrlist_t *l, const elpis_name_t *name,
                     uint16_t type, const uint8_t *rd, uint16_t rdlen)
{
    unsigned i;
    for (i = 0; i < l->n; i++) {
        if (l->rr[i].type != type || l->rr[i].rdlen != rdlen)
            continue;
        if (l->rr[i].namelen != name->len)
            continue;
        if (!elpis_eq_ci(l->pool + l->rr[i].nameoff, name->d, name->len))
            continue;
        if (memcmp(l->pool + l->rr[i].rdoff, rd, rdlen) == 0)
            return 1;
    }
    return 0;
}

uint32_t elpis_rrlist_min_ttl(const elpis_rrlist_t *l, uint32_t dflt)
{
    uint32_t m = 0xFFFFFFFFu;
    unsigned i;
    if (l->n == 0)
        return dflt;
    for (i = 0; i < l->n; i++)
        if (l->rr[i].ttl < m)
            m = l->rr[i].ttl;
    return m;
}

int elpis_trr_get_name(const elpis_rrlist_t *l, unsigned i, elpis_name_t *out)
{
    size_t used;
    if (i >= l->n)
        return ELPIS_ERR;
    return elpis_name_parse_nocomp(out, l->pool + l->rr[i].nameoff,
                                   l->rr[i].namelen, &used);
}
