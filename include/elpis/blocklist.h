/*
 * elpis/blocklist.h -- names refused outright, before the cache or a task.
 *
 * Some names are asked only to make a resolver work: random labels under a
 * domain, each one a cache miss and a resolution of its own, or a name whose
 * signed answer is kilobytes, asked from a spoofed address so the answer
 * lands on someone else.  A resolver that answers a whole ISP on plain port
 * 53 is asked them too, and pays for each one.  A name on the built-in list,
 * and every name below it, is answered REFUSED with EDE 15 (Blocked) as soon
 * as the question is read: no cache lookup, no task, nothing sent upstream,
 * and a reply with no records in it, a few bytes over the query.
 *
 * The list is in src/blocklist.c, compiled in.  "blocklist: no" in the
 * config switches it off.
 */
#ifndef ELPIS_BLOCKLIST_H
#define ELPIS_BLOCKLIST_H

#include "elpis/name.h"

/* 1 when `qname` is a listed name or below one, in any case. */
int elpis_blocklist_match(const elpis_name_t *qname);

/* How many names the built-in list holds, for the startup dump and tests. */
unsigned elpis_blocklist_count(void);

#endif /* ELPIS_BLOCKLIST_H */
