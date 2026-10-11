/*
 * blocklist.c -- names answered REFUSED before anything else is done.
 *
 * What a match does, and why, is in elpis/blocklist.h.  This is the list.
 *
 * It is gathered by the ElpisDNS honeypot, a resolver that serves no one, so
 * every name it is asked was chosen by whoever is scanning, flooding or
 * tunnelling through open resolvers.  The published copy is
 *
 *   https://github.com/PururinCollective/ElpisDNS/blob/main/bogus.txt
 *
 * in filter syntax, "||name^": the name and everything below it, which is
 * what an entry here means too.  These are the names it held on 2026-10-09.
 * To bring the list up to date, put what this prints in place of the entries
 * below:
 *
 *   curl -s <the URL above> | sed -n 's/^||\(.*\)\^$/    "\1",/p'
 *
 * An entry is a name, not a pattern.  The question's suffixes are looked up
 * in a hash table, one per label (nameset.c), so a query costs the same few
 * lookups however long the list grows.
 */
#include "elpis/blocklist.h"
#include "elpis/nameset.h"
#include "elpis/util.h"

#include <pthread.h>

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

static elpis_nameset_t g_set;
static pthread_once_t  g_once = PTHREAD_ONCE_INIT;

static void build(void)
{
    elpis_nameset_build(&g_set, k_names, ELPIS_ARRAY_LEN(k_names), "blocklist");
}

int elpis_blocklist_match(const elpis_name_t *qname)
{
    pthread_once(&g_once, build);
    return elpis_nameset_match(&g_set, qname) != 0;
}

unsigned elpis_blocklist_count(void)
{
    pthread_once(&g_once, build);
    return g_set.count;
}
