/*
 * elpis/rrlist.h -- a compact accumulator for records under construction.
 *
 * A resolution may gather records from several servers (a CNAME chain can
 * cross zones), so the answer is assembled here and only encoded once at the
 * end.  Names and rdata live in one growable byte pool; the index entries are
 * 24 bytes each, which keeps a task's footprint small enough to have tens of
 * thousands of them in flight.
 */
#ifndef ELPIS_RRLIST_H
#define ELPIS_RRLIST_H

#include "elpis/name.h"
#include "elpis/msg.h"

typedef struct {
    uint32_t nameoff;
    uint32_t rdoff;
    uint32_t ttl;
    uint16_t type;
    uint16_t klass;
    uint16_t rdlen;
    uint8_t  namelen;
    uint8_t  section;     /* elpis_section_t */
    /*
     * How many labels of this record's owner name make up the zone that
     * served it, plus one -- so the root is 1 -- or 0 when that is not known.
     * An answer assembled across a CNAME chain spans several zones, and an
     * RRset that arrives with no signature can only be judged against the one
     * that actually produced it.  ELPIS_ZONE_STAMP() makes one.
     */
    uint8_t  zone_labels;
} elpis_trr_t;

/*
 * The stamp for a record served by `zone`.  Plain label counts made the root
 * 0, which is also "unknown", and a record the validator cannot place is one
 * it declines to judge: everything under "forward-zone: ." -- where the
 * forwarder is asked for the whole tree and "." is the zone we queried --
 * went out as insecure without a look, signatures stripped or not.
 */
#define ELPIS_ZONE_STAMP(zone) ((uint8_t)((zone)->labels + 1u))

typedef struct {
    elpis_trr_t *rr;
    unsigned     n, cap;
    uint8_t     *pool;
    uint32_t     plen, pcap;
    /* Stamped onto the next record added, then cleared: set it immediately
     * before each add, or the record is marked as unknown provenance. */
    uint8_t      zone_labels;
} elpis_rrlist_t;

void elpis_rrlist_init(elpis_rrlist_t *l);
void elpis_rrlist_clear(elpis_rrlist_t *l);
void elpis_rrlist_free(elpis_rrlist_t *l);

int  elpis_rrlist_add(elpis_rrlist_t *l, elpis_section_t sec,
                      const elpis_name_t *name, uint16_t type, uint16_t klass,
                      uint32_t ttl, const uint8_t *rd, uint16_t rdlen);

/* 1 when an identical (name,type,class,rdata) record is already present. */
int  elpis_rrlist_has(const elpis_rrlist_t *l, const elpis_name_t *name,
                      uint16_t type, const uint8_t *rd, uint16_t rdlen);

/* Smallest TTL across all records, or `dflt` when the list is empty. */
uint32_t elpis_rrlist_min_ttl(const elpis_rrlist_t *l, uint32_t dflt);

ELPIS_INLINE const uint8_t *elpis_trr_name(const elpis_rrlist_t *l, unsigned i)
{
    return l->pool + l->rr[i].nameoff;
}
ELPIS_INLINE const uint8_t *elpis_trr_rd(const elpis_rrlist_t *l, unsigned i)
{
    return l->pool + l->rr[i].rdoff;
}
int elpis_trr_get_name(const elpis_rrlist_t *l, unsigned i, elpis_name_t *out);

#endif /* ELPIS_RRLIST_H */
