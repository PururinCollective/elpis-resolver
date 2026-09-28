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

/*
 * Holding down a server that has stopped answering.
 *
 * A ban above only reorders the list: when every server a zone has is banned,
 * they are all asked anyway, round after round.  ns1-ns4.charter.com drop
 * every query from some networks, and each new name under spectrum.com cost
 * sixteen queries and the whole 20 s query-total-timeout before its SERVFAIL:
 * a third of all upstream traffic, at 475 names a minute.
 *
 * So a server that has been silent for HOLD_SILENT_S seconds and
 * HOLD_AFTER timeouts, while others were answering, is held: not asked the
 * kinds of question it went quiet on for server-hold-down seconds.  When every
 * address a zone has is held, the query fails at once.  When the hold runs
 * out, the next query to reach it is let through as a probe; one answer
 * clears the lot.
 *
 * The kind of question matters because a server can drop one type and answer
 * the rest.  Plenty drop HTTPS; some once dropped AAAA.  Holding such a server
 * for every type would turn its unanswered HTTPS into SERVFAIL for A.  So
 * each timeout is recorded against its type's class, and a hold covers only
 * the classes that timed out.  DNSKEY, DS, NS and the rest share a class.
 */
#define ELPIS_QC_A           0x01u
#define ELPIS_QC_AAAA        0x02u
#define ELPIS_QC_SVCB        0x04u   /* HTTPS and SVCB */
#define ELPIS_QC_OTHER       0x08u

#define ELPIS_HOLD_AFTER     3u      /* timeouts in a row, as for the ban */
#define ELPIS_HOLD_SILENT_S  10u     /* and silent for at least this long */

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
    uint8_t  silent_types; /* ELPIS_QC_* that timed out since the last answer */
    uint32_t silent_since; /* first of those timeouts, seconds; 0 = none     */
    uint32_t hold_until;   /* held types are not asked before this; 0 = none */
    uint32_t last_used;
} elpis_infra_info_t;

elpis_cache_t *elpis_infra_new(uint64_t bytes, unsigned shards);

/* Fills `out` with either the stored state or sane defaults. */
void elpis_infra_get(elpis_cache_t *c, const elpis_addr_t *a,
                     elpis_infra_info_t *out);

/* Jacobson/Karels style update; also clears the timeout counter and any
 * hold. */
void elpis_infra_rtt_ok(elpis_cache_t *c, const elpis_addr_t *a, uint32_t rtt_ms);
/*
 * A question of type `qtype` went unanswered at `now`.  `hold_s` is how long
 * to hold the server if this makes it due, and 0 when it must not be held:
 * holds are off, or nobody else answered either, so the silence may well be
 * this host's own network.
 */
void elpis_infra_timeout(elpis_cache_t *c, const elpis_addr_t *a,
                         uint16_t qtype, uint32_t now, uint32_t hold_s);
/* The ELPIS_QC_* class a question type is held under. */
unsigned elpis_infra_qclass(uint16_t qtype);
/* Is the server held for this type of question at `now`? */
int  elpis_infra_held(const elpis_infra_info_t *i, uint16_t qtype, uint32_t now);
/* Has its hold for this type run out, so that this query is the probe? */
int  elpis_infra_probe_due(const elpis_infra_info_t *i, uint16_t qtype,
                           uint32_t now);
/* Move the hold on to `until`, while the server is still silent: taken by the
 * probe, so that the queries behind it do not all go the same way. */
void elpis_infra_hold(elpis_cache_t *c, const elpis_addr_t *a, uint32_t until);
void elpis_infra_set_edns(elpis_cache_t *c, const elpis_addr_t *a,
                          uint8_t state, uint16_t maxsize);
void elpis_infra_set_flag(elpis_cache_t *c, const elpis_addr_t *a,
                          uint8_t flag, int on);
void elpis_infra_set_cookie(elpis_cache_t *c, const elpis_addr_t *a,
                            const uint8_t *cookie, size_t len);

/* Effective selection cost: srtt plus a penalty for recent timeouts. */
uint32_t elpis_infra_cost(const elpis_infra_info_t *i);

#endif /* ELPIS_INFRA_H */
