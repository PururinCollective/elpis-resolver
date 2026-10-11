/*
 * forwardlist.c -- names asked through public resolvers, and which ones.
 *
 * What a match does, and why, is in elpis/forwardlist.h.  This is the list.
 *
 * Each entry is a zone whose own servers were seen not to answer Elpis while
 * the public resolvers had the name.  Say what was seen when adding one.
 *
 *   charter.com  ns1-4.charter.com (24.216.90.1, 24.216.90.2, 24.240.146.1,
 *                24.240.146.2) time out from Elpis in Malaysia, and answer
 *                1.1.1.1, 8.8.8.8 and 9.9.9.9 (2026-10-11).  Later that day
 *                Cloudflare's IPv6 addresses answered it SERVFAIL while
 *                1.1.1.1 and Google's answered.
 *   usda.gov     rate-limits: no answer through the maintainer's resolver,
 *                answers through Cloudflare.  ns1/ns2.usda.gov answered a
 *                quiet test box directly, and 1.1.1.1 itself was SERVFAIL
 *                with EDE 22 while 8.8.8.8 answered (2026-10-11), which is
 *                why the list has two providers in it.
 *
 * An entry is a name, not a pattern, and covers everything below it.  A
 * zone comes off the list once its servers answer again.
 */
#include "elpis/forwardlist.h"
#include "elpis/log.h"
#include "elpis/nameset.h"

#include <pthread.h>

static const char *const k_names[] = {
    "charter.com",
    "usda.gov",
};

/*
 * Two providers, two addresses each in each family, Cloudflare first.  Order
 * matters little: each is measured and the fastest asked, as with any
 * forward-zone, with IPv4 a little ahead unless prefer-ipv6 says otherwise.
 * The IPv6 ones keep the list working on a host with do-ipv4: no.
 */
static const char *const k_servers[] = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
};

static elpis_nameset_t g_set;
static elpis_addr_t    g_addr[ELPIS_ARRAY_LEN(k_servers)];
static unsigned        g_naddr;
static pthread_once_t  g_once = PTHREAD_ONCE_INIT;

static void build(void)
{
    size_t i;

    elpis_nameset_build(&g_set, k_names, ELPIS_ARRAY_LEN(k_names),
                        "forwardlist");
    for (i = 0; i < ELPIS_ARRAY_LEN(k_servers); i++) {
        if (elpis_addr_parse(&g_addr[g_naddr], k_servers[i], 53) != 0) {
            elpis_warn("forwardlist: \"%s\" is not an address; skipped",
                       k_servers[i]);
            continue;
        }
        g_naddr++;
    }
}

unsigned elpis_forwardlist_match(const elpis_name_t *qname)
{
    pthread_once(&g_once, build);
    if (g_naddr == 0)
        return 0;
    return elpis_nameset_match(&g_set, qname);
}

unsigned elpis_forwardlist_count(void)
{
    pthread_once(&g_once, build);
    return g_set.count;
}

const elpis_addr_t *elpis_forwardlist_servers(unsigned *n)
{
    pthread_once(&g_once, build);
    *n = g_naddr;
    return g_addr;
}
