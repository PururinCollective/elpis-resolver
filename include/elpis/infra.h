/*
 * elpis/infra.h -- per-nameserver state: round-trip time, EDNS capability,
 * lameness and learned server cookies.
 *
 * Server selection is only as good as this data.  Picking the fastest known
 * authority rather than a random one is the single biggest latency win a
 * recursive resolver has, and remembering that a server chokes on large EDNS
 * buffers avoids a whole retry round trip.
 */
#ifndef ELPIS_INFRA_H
#define ELPIS_INFRA_H

#include "elpis/cache.h"
#include "elpis/util.h"
#include "elpis/name.h"

#define ELPIS_EDNS_UNKNOWN   0
#define ELPIS_EDNS_YES       1
#define ELPIS_EDNS_NO        2
#define ELPIS_EDNS_FALLBACK  3   /* works, but only at a smaller buffer */

#define ELPIS_INF_LAME       0x01u
#define ELPIS_INF_COOKIE_OK  0x02u
#define ELPIS_INF_TCP_ONLY   0x04u
#define ELPIS_INF_DNSSEC_NO  0x08u   /* strips DO or drops signed answers */
/*
 * Case randomisation (0x20).  Some authorities silently drop any query whose
 * name is not all lowercase -- intel.com's four did, from here, for a while --
 * so a server that has timed out without ever answering a randomised name is
 * asked once as-is.
 * An answer to that marks it NO_0X20; an answer to a randomised one, 0X20_OK.
 */
#define ELPIS_INF_0X20_OK    0x10u
#define ELPIS_INF_NO_0X20    0x20u
/*
 * Rejected a server cookie it had handed out itself.  An anycast address is
 * many machines, each with its own secret: g-root and the .uk servers answer
 * BADCOOKIE to their own cookie from a query ago about half the time, and the
 * retry can land on a third.  Such a server is sent the client half only,
 * which RFC 7873 section 5.2.3 has it answer normally.
 */
#define ELPIS_INF_COOKIE_ROAM 0x40u

/* Starting estimate for a server we have never talked to. */
#define ELPIS_RTT_INITIAL    376u
#define ELPIS_RTT_MAX        12000u
#define ELPIS_RTT_BAN        120000u  /* effectively "do not pick"  */

typedef struct {
    uint32_t srtt;        /* smoothed round-trip time, milliseconds */
    uint32_t rttvar;
    uint32_t timeouts;    /* consecutive timeouts                   */
    uint32_t queries;
    uint16_t edns_max;    /* largest advertised buffer that worked  */
    uint8_t  edns_state;
    uint8_t  flags;
    uint8_t  cookie[32];  /* server cookie half, learned from peer  */
    uint8_t  cookie_len;
    uint32_t last_used;
} elpis_infra_info_t;

elpis_cache_t *elpis_infra_new(uint64_t bytes, unsigned shards);

/* Fills `out` with either the stored state or sane defaults. */
void elpis_infra_get(elpis_cache_t *c, const elpis_addr_t *a,
                     elpis_infra_info_t *out);

/* Jacobson/Karels style update; also clears the timeout counter. */
void elpis_infra_rtt_ok(elpis_cache_t *c, const elpis_addr_t *a, uint32_t rtt_ms);
void elpis_infra_timeout(elpis_cache_t *c, const elpis_addr_t *a);
void elpis_infra_set_edns(elpis_cache_t *c, const elpis_addr_t *a,
                          uint8_t state, uint16_t maxsize);
void elpis_infra_set_flag(elpis_cache_t *c, const elpis_addr_t *a,
                          uint8_t flag, int on);
void elpis_infra_set_cookie(elpis_cache_t *c, const elpis_addr_t *a,
                            const uint8_t *cookie, size_t len);

/* Effective selection cost: srtt plus a penalty for recent timeouts. */
uint32_t elpis_infra_cost(const elpis_infra_info_t *i);

#endif /* ELPIS_INFRA_H */
