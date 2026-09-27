/*
 * quirks.c -- zones whose authorities misbehave in known ways.
 *
 * What each flag does is in elpis/quirks.h.  This is the list of zones known
 * to need one, each with the behaviour that put it here, as seen from a
 * resolver in Malaysia on the date given.  An entry is a claim about the
 * zone's servers, not about its names: it covers the zone and everything the
 * same servers answer for below it.
 *
 * An entry belongs here only when resolving the zone properly is not merely
 * slow but impossible, and the answer a quirk gives is the one the zone's
 * operator would give if their servers let them.  Remove one when the zone is
 * fixed: a quirk that is no longer needed only ever costs answers.
 *
 * Entries are for unsigned zones.  A made-up "no data" carries no proof, so
 * for a signed zone the validator refuses it and the answer is SERVFAIL, as
 * it would have been.  agrobank.com.my drops HTTPS like the ones below, and
 * is signed: nothing here can help it, so it is not listed.
 */
#include "elpis/quirks.h"
#include "elpis/util.h"

#include <pthread.h>

typedef struct {
    const char *zone;
    unsigned    flags;
} builtin_t;

static const builtin_t k_builtin[] = {
    /*
     * CIMB Bank (MY), 2026-09-27.  ns5/ns6/ns7.cimb.com answer A, AAAA, TXT,
     * MX, CAA, SOA and NS; HTTPS, SVCB and any type they do not know never
     * come back.  ns2/ns3/ns4.cimb.com.my answer nothing at all.  Every HTTPS
     * query for www.cimb.com.my ended in SERVFAIL after 2.6 s, here and on
     * 1.1.1.1 alike.
     */
    { "cimb.com.my.",   ELPIS_QUIRK_DROPS_SVCB },
    /*
     * Tenaga Nasional (MY), 2026-09-27.  ns1-3.tnb.com.my: the same firewall
     * behaviour -- HTTPS, SVCB and unknown types dropped, the rest answered.
     */
    { "tnb.com.my.",    ELPIS_QUIRK_DROPS_SVCB },
    /*
     * BPI (PH), 2026-09-28.  The Globe-hosted servers answer A and TXT and
     * drop HTTPS, SVCB and unknown types; one of them drops A as well.
     */
    { "bpi.com.ph.",    ELPIS_QUIRK_DROPS_SVCB },
    /*
     * M1 (SG), 2026-09-27.  com.sg delegates to ns01 and ns03.m1.com.sg only;
     * both answer an HTTPS query for www.m1.com.sg with NOERROR and an empty
     * message -- no record, no SOA, no AA.  ns02, which answers properly, is
     * in the zone's own NS set and not the parent's, so it is never reached.
     * Three rounds of the two broken servers ended in SERVFAIL.
     */
    { "m1.com.sg.",     ELPIS_QUIRK_EMPTY_NODATA },
    /*
     * Kementerian Keuangan (ID), 2026-09-27.  www.kemenkeu.go.id is delegated
     * to ns7 and ns9.kemenkeu.go.id, which answer A authoritatively and refer
     * every other type back to www.kemenkeu.go.id itself.  ns7 answers only
     * now and then.  AAAA and HTTPS ended in SERVFAIL, one of them after
     * 8.5 s; 1.1.1.1 answers "no data".
     */
    { "kemenkeu.go.id.", ELPIS_QUIRK_SELFREF_NODATA },
};

#define NBUILTIN ELPIS_ARRAY_LEN(k_builtin)

static elpis_name_t   g_builtin[NBUILTIN];
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void builtin_build(void)
{
    unsigned i;

    for (i = 0; i < NBUILTIN; i++) {
        if (elpis_name_from_text(&g_builtin[i], k_builtin[i].zone) != ELPIS_OK)
            g_builtin[i].len = 0;
        else
            elpis_name_lower(&g_builtin[i]);
    }
}

unsigned elpis_quirks_for(const elpis_quirk_t *conf_list, unsigned nconf,
                          const elpis_name_t *zone)
{
    unsigned i, flags = 0;
    int best = -1;                      /* labels of the deepest match */

    pthread_once(&g_once, builtin_build);

    for (i = 0; i < NBUILTIN; i++) {
        if (g_builtin[i].len == 0 || (int)g_builtin[i].labels <= best)
            continue;
        if (elpis_name_is_subdomain(zone, &g_builtin[i])) {
            best  = (int)g_builtin[i].labels;
            flags = k_builtin[i].flags;
        }
    }
    /* A configured entry as deep as the built-in one replaces it -- which is
     * how "quirk: zone none" switches one off. */
    for (i = 0; i < nconf; i++) {
        if ((int)conf_list[i].zone.labels < best)
            continue;
        if (elpis_name_is_subdomain(zone, &conf_list[i].zone)) {
            best  = (int)conf_list[i].zone.labels;
            flags = conf_list[i].flags;
        }
    }
    return flags;
}

static const struct {
    const char *word;
    unsigned    flag;
} k_words[] = {
    { "drops-svcb",     ELPIS_QUIRK_DROPS_SVCB },
    { "empty-nodata",   ELPIS_QUIRK_EMPTY_NODATA },
    { "selfref-nodata", ELPIS_QUIRK_SELFREF_NODATA },
};

int elpis_quirk_flag_parse(const char *word, unsigned *flags)
{
    unsigned i;

    if (!elpis_strcasecmp_ascii(word, "none"))
        return 0;
    for (i = 0; i < ELPIS_ARRAY_LEN(k_words); i++)
        if (!elpis_strcasecmp_ascii(word, k_words[i].word)) {
            *flags |= k_words[i].flag;
            return 0;
        }
    return -1;
}

void elpis_quirk_flags_str(unsigned flags, char *buf, size_t sz)
{
    unsigned i;

    if (sz == 0)
        return;
    buf[0] = '\0';
    for (i = 0; i < ELPIS_ARRAY_LEN(k_words); i++) {
        if (!(flags & k_words[i].flag))
            continue;
        if (buf[0] != '\0')
            elpis_strlcat(buf, " ", sz);
        elpis_strlcat(buf, k_words[i].word, sz);
    }
    if (buf[0] == '\0')
        elpis_strlcpy(buf, "none", sz);
}

unsigned elpis_quirks_builtin(const char **zones, unsigned *flags, unsigned max)
{
    unsigned i;

    for (i = 0; i < NBUILTIN && i < max; i++) {
        zones[i] = k_builtin[i].zone;
        flags[i] = k_builtin[i].flags;
    }
    return (unsigned)NBUILTIN;
}
