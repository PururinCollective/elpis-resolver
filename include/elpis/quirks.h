/*
 * elpis/quirks.h -- zones whose authorities misbehave in known ways.
 *
 * Most of the DNS answers every question it is asked, one way or another.
 * Some zones do not: a firewall in front of the servers drops query types it
 * was never taught, or a load balancer answers the types it balances and
 * shrugs at the rest.  Resolving such a zone by the book ends in SERVFAIL,
 * seconds later, for a question that has a perfectly good answer -- "there is
 * nothing of that type here".  A quirk says how a zone misbehaves, so the
 * answer it cannot give properly is given anyway.
 *
 * Every entry is matched against the zone actually being asked -- the
 * delegation, not the question -- so it covers the zone and everything below
 * it that the same servers serve.  An answer made up from a quirk goes
 * through the validator like any other, so for a zone that is signed it is
 * refused rather than believed.  The built-in list is in src/quirks.c; the
 * quirk: directive adds to it, or overrides an entry with "none".
 */
#ifndef ELPIS_QUIRKS_H
#define ELPIS_QUIRKS_H

#include "elpis/name.h"

/*
 * The servers never answer HTTPS or SVCB queries -- a firewall drops the
 * types it does not know -- though every older type works.  Those two are
 * answered "no data" without asking, rather than after every server has timed
 * out.  Browsers ask HTTPS for every page.
 */
#define ELPIS_QUIRK_DROPS_SVCB    0x01u
/*
 * For a type it does not serve, a server answers NOERROR with nothing at all
 * in the message: no record, no SOA, not authoritative.  Taken as "no data" at
 * the first such reply.
 */
#define ELPIS_QUIRK_EMPTY_NODATA  0x02u
/*
 * For a type it does not serve, a server refers us back to the very zone we
 * asked -- its own NS records, not authoritative.  Taken as "no data" at the
 * first such reply.
 */
#define ELPIS_QUIRK_SELFREF_NODATA 0x04u

#define ELPIS_QUIRK_ALL (ELPIS_QUIRK_DROPS_SVCB | ELPIS_QUIRK_EMPTY_NODATA | \
                         ELPIS_QUIRK_SELFREF_NODATA)

/* How long a made-up "no data" is kept, in the message cache only. */
#define ELPIS_QUIRK_NODATA_TTL 60u

/* One zone and what is wrong with it: a built-in entry or a quirk: line. */
typedef struct {
    elpis_name_t zone;              /* wire form, lower case */
    unsigned     flags;             /* ELPIS_QUIRK_*; 0 cancels a built-in */
} elpis_quirk_t;

#define ELPIS_MAX_QUIRKS 64

/*
 * The quirks of the deepest zone at or above `zone`: configured entries
 * first, then the built-in ones.  0 when nothing is known about it.
 */
unsigned elpis_quirks_for(const elpis_quirk_t *conf_list, unsigned nconf,
                          const elpis_name_t *zone);

/* "drops-svcb" and friends, or "none".  Returns 0 and ORs into *flags. */
int elpis_quirk_flag_parse(const char *word, unsigned *flags);
/* The flags as the words that set them, for logs and the config dump. */
void elpis_quirk_flags_str(unsigned flags, char *buf, size_t sz);

/* The built-in list, for the startup dump and the tests. */
unsigned elpis_quirks_builtin(const char **zones, unsigned *flags, unsigned max);

#endif /* ELPIS_QUIRKS_H */
