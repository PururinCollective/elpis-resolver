/*
 * elpis/deleg.h -- delegation cache, root priming and TLD warming.
 *
 * A delegation is everything needed to talk to a zone's authoritative
 * servers: the NS names, their addresses, and whether the child is signed.
 * Keeping that as one object (instead of re-joining an NS RRset with A/AAAA
 * RRsets on every query) is what turns "resolve anything under .com" into a
 * single hash lookup plus a send.
 *
 * Root and TLD delegations are pinned, so they survive any amount of cache
 * pressure and the resolver effectively never has to walk back to the root.
 */
#ifndef ELPIS_DELEG_H
#define ELPIS_DELEG_H

#include "elpis/store.h"
#include "elpis/util.h"

#define ELPIS_DELEG_MAX_NS    16
#define ELPIS_NS_MAX_A4        4
#define ELPIS_NS_MAX_A6        2

#define ELPIS_NSF_GLUE        0x01u   /* address came from the parent       */
#define ELPIS_NSF_RESOLVED    0x02u   /* address came from a real lookup    */
#define ELPIS_NSF_LAME        0x04u   /* answered but not authoritative     */
#define ELPIS_NSF_NOADDR      0x08u   /* lookup produced no address         */

typedef struct {
    elpis_name_t name;
    uint8_t  n4, n6;
    uint8_t  flags;
    uint8_t  pad;
    /*
     * Authorities always answer on 53, but a configured forwarder or stub
     * often does not -- running next to AdGuard Home usually means something
     * is on a different port.  Carrying it here is what makes
     * "stub-zone: corp.example 10.0.0.1@5335" actually work.
     */
    uint16_t port;
    uint8_t  a4[ELPIS_NS_MAX_A4][4];
    uint8_t  a6[ELPIS_NS_MAX_A6][16];
} elpis_nsrec_t;

typedef struct {
    elpis_name_t  zone;
    uint8_t       nns;
    uint8_t       sec;        /* elpis_sec_t of the delegation itself */
    uint8_t       ds_state;   /* ELPIS_DS_*                            */
    uint8_t       pinned;
    uint32_t      ttl;        /* seconds remaining                     */
    elpis_nsrec_t ns[ELPIS_DELEG_MAX_NS];
} elpis_deleg_t;

#define ELPIS_DS_UNKNOWN  0   /* not looked up yet                     */
#define ELPIS_DS_PRESENT  1   /* DS exists: the child zone is signed   */
#define ELPIS_DS_ABSENT   2   /* proven absent: the child is insecure  */
#define ELPIS_DS_BOGUS    3

elpis_cache_t *elpis_dcache_new(uint64_t bytes, unsigned shards);

int  elpis_dcache_get(elpis_cache_t *c, const elpis_name_t *zone,
                      uint32_t now, elpis_deleg_t *out);
int  elpis_dcache_put(elpis_cache_t *c, const elpis_deleg_t *d,
                      uint32_t ttl, int pinned);

/*
 * Deepest cached delegation at or above `name`.  This is the hot path for
 * every recursion: a hit on "com." means the query goes straight to a .com
 * server instead of starting at the root.
 */
int  elpis_dcache_closest(elpis_cache_t *c, const elpis_name_t *name,
                          uint32_t now, elpis_deleg_t *out);

/* Merge freshly learned addresses into an existing delegation. */
void elpis_deleg_add_ns(elpis_deleg_t *d, const elpis_name_t *ns);
void elpis_deleg_add_addr(elpis_deleg_t *d, const elpis_name_t *ns,
                          const uint8_t *ip, int family, uint8_t flags);
/* Same, but for a server that does not listen on port 53. */
void elpis_deleg_add_addr_port(elpis_deleg_t *d, const elpis_name_t *ns,
                               const uint8_t *ip, int family, uint8_t flags,
                               uint16_t port);
elpis_nsrec_t *elpis_deleg_find_ns(elpis_deleg_t *d, const elpis_name_t *ns);
unsigned elpis_deleg_addr_count(const elpis_deleg_t *d);

/* ------------------------------------------------------------------ */
/* Root hints                                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;
    const char *v4;
    const char *v6;
} elpis_roothint_t;

const elpis_roothint_t *elpis_root_hints(unsigned *count);
/* Build the built-in root delegation. */
void elpis_root_delegation(elpis_deleg_t *d);
/* Replace the built-ins from a BIND-style root hints file. */
int  elpis_root_hints_load(const char *path, elpis_deleg_t *out);

#endif /* ELPIS_DELEG_H */
