/*
 * roots.c -- root server hints.
 *
 * Addresses verified against https://www.internic.net/domain/named.root.
 * They change rarely (B moved to 170.247.170.2 in late 2023), and a stale
 * hint is survivable because priming replaces the whole set from the first
 * root server that answers.  A hints file may still be supplied to override
 * these entirely.
 */
#include "elpis/deleg.h"
#include "elpis/log.h"
#include "elpis/util.h"

#include <ctype.h>
#include <errno.h>

static const elpis_roothint_t k_hints[] = {
    { "a.root-servers.net.", "198.41.0.4",     "2001:503:ba3e::2:30" },
    { "b.root-servers.net.", "170.247.170.2",  "2801:1b8:10::b"      },
    { "c.root-servers.net.", "192.33.4.12",    "2001:500:2::c"       },
    { "d.root-servers.net.", "199.7.91.13",    "2001:500:2d::d"      },
    { "e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"      },
    { "f.root-servers.net.", "192.5.5.241",    "2001:500:2f::f"      },
    { "g.root-servers.net.", "192.112.36.4",   "2001:500:12::d0d"    },
    { "h.root-servers.net.", "198.97.190.53",  "2001:500:1::53"      },
    { "i.root-servers.net.", "192.36.148.17",  "2001:7fe::53"        },
    { "j.root-servers.net.", "192.58.128.30",  "2001:503:c27::2:30"  },
    { "k.root-servers.net.", "193.0.14.129",   "2001:7fd::1"         },
    { "l.root-servers.net.", "199.7.83.42",    "2001:500:9f::42"     },
    { "m.root-servers.net.", "202.12.27.33",   "2001:dc3::35"        }
};

const elpis_roothint_t *elpis_root_hints(unsigned *count)
{
    *count = (unsigned)ELPIS_ARRAY_LEN(k_hints);
    return k_hints;
}

void elpis_root_delegation(elpis_deleg_t *d)
{
    unsigned i;

    memset(d, 0, sizeof *d);
    elpis_name_init_root(&d->zone);
    d->sec      = ELPIS_SEC_SECURE;      /* the root is signed by definition */
    d->ds_state = ELPIS_DS_PRESENT;
    d->pinned   = 1;
    d->ttl      = 518400;                /* six days, as the hints file says */

    for (i = 0; i < ELPIS_ARRAY_LEN(k_hints) && i < ELPIS_DELEG_MAX_NS; i++) {
        elpis_name_t ns;
        uint8_t ip4[4], ip6[16];

        if (elpis_name_from_text(&ns, k_hints[i].name) != ELPIS_OK)
            continue;
        elpis_name_lower(&ns);
        elpis_deleg_add_ns(d, &ns);
        if (elpis_pton4(k_hints[i].v4, ip4) == 0)
            elpis_deleg_add_addr(d, &ns, ip4, AF_INET, ELPIS_NSF_GLUE);
        if (k_hints[i].v6 != NULL && elpis_pton6(k_hints[i].v6, ip6) == 0)
            elpis_deleg_add_addr(d, &ns, ip6, AF_INET6, ELPIS_NSF_GLUE);
    }
}

/* ------------------------------------------------------------------ */
/* named.root style hints file                                         */
/* ------------------------------------------------------------------ */

static char *next_token(char **s)
{
    char *p = *s;
    char *start;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == ';')
        return NULL;
    start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != ';')
        p++;
    if (*p != '\0')
        *p++ = '\0';
    *s = p;
    return start;
}

int elpis_root_hints_load(const char *path, elpis_deleg_t *out)
{
    FILE *fp = fopen(path, "r");
    char line[512];
    unsigned nns = 0, naddr = 0;
    elpis_deleg_t d;

    if (fp == NULL) {
        elpis_warn("root hints: cannot open '%s': %s", path, strerror(errno));
        return ELPIS_ERR;
    }

    memset(&d, 0, sizeof d);
    elpis_name_init_root(&d.zone);
    d.sec      = ELPIS_SEC_SECURE;
    d.ds_state = ELPIS_DS_PRESENT;
    d.pinned   = 1;
    d.ttl      = 518400;

    while (fgets(line, sizeof line, fp) != NULL) {
        char *cur = line;
        char *tok[5];
        int n = 0;
        char *semi;

        semi = strchr(line, ';');
        if (semi != NULL)
            *semi = '\0';

        while (n < 5) {
            char *t = next_token(&cur);
            if (t == NULL)
                break;
            tok[n++] = t;
        }
        if (n < 4)
            continue;

        /* NAME [TTL] [CLASS] TYPE RDATA -- locate the type token. */
        {
            int ti = -1, i;
            for (i = 1; i < n - 1; i++) {
                if (!elpis_strcasecmp_ascii(tok[i], "NS")   ||
                    !elpis_strcasecmp_ascii(tok[i], "A")    ||
                    !elpis_strcasecmp_ascii(tok[i], "AAAA")) {
                    ti = i;
                    break;
                }
            }
            if (ti < 0 || ti + 1 >= n)
                continue;

            if (!elpis_strcasecmp_ascii(tok[ti], "NS")) {
                elpis_name_t ns;
                if (elpis_name_from_text(&ns, tok[ti + 1]) != ELPIS_OK)
                    continue;
                elpis_name_lower(&ns);
                elpis_deleg_add_ns(&d, &ns);
                nns++;
            } else {
                elpis_name_t ns;
                uint8_t ip[16];
                if (elpis_name_from_text(&ns, tok[0]) != ELPIS_OK)
                    continue;
                elpis_name_lower(&ns);
                if (!elpis_strcasecmp_ascii(tok[ti], "A")) {
                    if (elpis_pton4(tok[ti + 1], ip) != 0)
                        continue;
                    elpis_deleg_add_addr(&d, &ns, ip, AF_INET, ELPIS_NSF_GLUE);
                } else {
                    if (elpis_pton6(tok[ti + 1], ip) != 0)
                        continue;
                    elpis_deleg_add_addr(&d, &ns, ip, AF_INET6, ELPIS_NSF_GLUE);
                }
                naddr++;
            }
        }
    }
    fclose(fp);

    if (d.nns == 0 || elpis_deleg_addr_count(&d) == 0) {
        elpis_warn("root hints: '%s' yielded no usable servers; keeping built-ins",
                   path);
        return ELPIS_ERR;
    }
    elpis_info("root hints: loaded %u servers (%u addresses) from %s",
               d.nns, elpis_deleg_addr_count(&d), path);
    *out = d;
    return ELPIS_OK;
}
