/*
 * elpis/forwardlist.h -- zones asked through public resolvers rather than
 * their own servers.
 *
 * A few zones' servers will not answer a resolver like this one: they drop
 * queries from addresses they don't know, or rate-limit a busy source until
 * it gets nothing at all.  Asked directly, such a zone is a timeout and then
 * a SERVFAIL, while the big public resolvers, which those servers do answer,
 * have the name.  A name on the built-in list, and every name below it, is
 * asked of Cloudflare's and Google's public resolvers instead (1.1.1.1,
 * 1.0.0.1, 8.8.8.8, 8.8.4.4 and their IPv6 addresses), with RD set, as a
 * forward-zone would be: the cheapest first, and the next when one fails or
 * answers SERVFAIL, so one provider having trouble with a zone is not the
 * end of it.  What comes back is still validated.
 *
 * These queries never carry EDNS Client Subnet, whatever ecs: says: a
 * client's subnet would tell two more companies who was asking.
 *
 * A name under a forward-zone: or stub-zone: in the config goes where that
 * line says; the list only changes names that would have been resolved from
 * the root.  The list is in src/forwardlist.c, compiled in.  "forwardlist:
 * no" in the config switches it off.
 */
#ifndef ELPIS_FORWARDLIST_H
#define ELPIS_FORWARDLIST_H

#include "elpis/name.h"
#include "elpis/util.h"

/*
 * Labels in the deepest listed name that `qname` is, or is below, in any
 * case: the zone the question is forwarded under.  0 when there is none.
 */
unsigned elpis_forwardlist_match(const elpis_name_t *qname);

/* How many names the built-in list holds, for the startup dump and tests. */
unsigned elpis_forwardlist_count(void);

/* The public resolvers a listed name is asked of; `*n` is set to how many. */
const elpis_addr_t *elpis_forwardlist_servers(unsigned *n);

#endif /* ELPIS_FORWARDLIST_H */
