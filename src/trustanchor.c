/*
 * trustanchor.c -- DNSSEC trust anchors.
 *
 * The root anchors below are the published IANA values (KSK-2017, tag 20326,
 * and KSK-2024, tag 38696).  Both are kept: a resolver that only knows one
 * breaks the moment ICANN rolls, and holding both costs nothing.
 *
 * RFC 5011 automated rollover is deliberately not implemented.  It requires
 * durable state that survives restarts, and getting that subtly wrong is
 * worse than a scheduled config update: a resolver can be walked onto an
 * attacker's key if the state file is writable.  Point
 * trust-anchor-file at IANA's root.key instead and update it with the rest of
 * the system.
 */
#include "elpis/dnssec.h"
#include "elpis/log.h"
#include "elpis/util.h"

#include "elpis/crypto.h"

#include <ctype.h>
#include <errno.h>

typedef struct {
    const char *zone;
    uint16_t    keytag;
    uint8_t     alg;
    uint8_t     digest_type;
    const char *digest;
} builtin_ta_t;

static const builtin_ta_t k_builtin[] = {
    { ".", 20326, 8, 2,
      "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" },
    { ".", 38696, 8, 2,
      "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16" }
};

elpis_ta_store_t *elpis_ta_new(void)
{
    return (elpis_ta_store_t *)elpis_calloc(1, sizeof(elpis_ta_store_t));
}

void elpis_ta_free(elpis_ta_store_t *s)
{
    if (s == NULL)
        return;
    elpis_free(s->ta);
    elpis_free(s);
}

static int ta_push(elpis_ta_store_t *s, const elpis_ta_t *t)
{
    unsigned i;

    for (i = 0; i < s->n; i++) {
        if (s->ta[i].keytag == t->keytag && s->ta[i].alg == t->alg &&
            s->ta[i].digest_type == t->digest_type &&
            s->ta[i].digest_len == t->digest_len &&
            elpis_name_eq(&s->ta[i].name, &t->name) &&
            memcmp(s->ta[i].digest, t->digest, t->digest_len) == 0)
            return ELPIS_OK;             /* already known */
    }
    if (s->n == s->cap) {
        unsigned want = s->cap ? s->cap * 2u : 8u;
        elpis_ta_t *n = (elpis_ta_t *)elpis_realloc(s->ta, want * sizeof *n);
        if (n == NULL)
            return ELPIS_ENOMEM;
        s->ta = n;
        s->cap = want;
    }
    s->ta[s->n++] = *t;
    return ELPIS_OK;
}

static int hexdec(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
    size_t n = 0;
    int hi = -1;

    while (*s != '\0') {
        int v;
        if (isspace((unsigned char)*s)) { s++; continue; }
        if (*s >= '0' && *s <= '9')      v = *s - '0';
        else if (*s >= 'a' && *s <= 'f') v = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') v = *s - 'A' + 10;
        else return ELPIS_EFORMAT;
        s++;
        if (hi < 0) { hi = v; continue; }
        if (n >= cap)
            return ELPIS_ETRUNC;
        out[n++] = (uint8_t)((hi << 4) | v);
        hi = -1;
    }
    if (hi >= 0)
        return ELPIS_EFORMAT;
    *outlen = n;
    return ELPIS_OK;
}

int elpis_ta_add_builtin(elpis_ta_store_t *s)
{
    unsigned i;

    for (i = 0; i < ELPIS_ARRAY_LEN(k_builtin); i++) {
        elpis_ta_t t;
        size_t dl;

        memset(&t, 0, sizeof t);
        if (elpis_name_from_text(&t.name, k_builtin[i].zone) != ELPIS_OK)
            continue;
        elpis_name_lower(&t.name);
        t.keytag      = k_builtin[i].keytag;
        t.alg         = k_builtin[i].alg;
        t.digest_type = k_builtin[i].digest_type;
        if (hexdec(k_builtin[i].digest, t.digest, sizeof t.digest, &dl) != ELPIS_OK)
            continue;
        t.digest_len = (uint8_t)dl;
        ta_push(s, &t);
    }
    elpis_info("trust anchors: %u built-in root key%s", s->n,
               s->n == 1 ? "" : "s");
    return ELPIS_OK;
}

/*
 * Accepts the two shapes people actually have on disk:
 *   . IN DS 20326 8 2 E06D...
 *   . IN DNSKEY 257 3 8 AwEAAa...        (base64; we take its DS-SHA256)
 * plus BIND's "trust-anchors { ... }" wrapper, which we tolerate by ignoring
 * braces and semicolons.
 */
static int b64dec(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
    static const char *tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;

    for (; *s != '\0'; s++) {
        const char *p;
        if (isspace((unsigned char)*s) || *s == '"')
            continue;
        if (*s == '=')
            break;
        p = strchr(tbl, *s);
        if (p == NULL)
            return ELPIS_EFORMAT;
        acc = (acc << 6) | (uint32_t)(p - tbl);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap)
                return ELPIS_ETRUNC;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    *outlen = n;
    return ELPIS_OK;
}

int elpis_ta_load_file(elpis_ta_store_t *s, const char *path)
{
    FILE *fp;
    char line[4096];
    unsigned added = 0, lineno = 0;

    if (path == NULL || *path == '\0')
        return ELPIS_OK;
    fp = fopen(path, "r");
    if (fp == NULL) {
        elpis_warn("trust-anchor-file '%s': %s; keeping built-in anchors",
                   path, strerror(errno));
        return ELPIS_ERR;
    }

    while (fgets(line, sizeof line, fp) != NULL) {
        char *p = line;
        char *tok[8];
        unsigned nt = 0;
        elpis_ta_t t;

        lineno++;
        {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
        }
        while (*p != '\0' && nt < 8) {
            char *e;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' ||
                   *p == '{' || *p == '}')
                p++;
            if (*p == '\0')
                break;
            tok[nt++] = p;
            e = p;
            while (*e != '\0' && *e != ' ' && *e != '\t' && *e != '\r' &&
                   *e != '\n')
                e++;
            if (*e != '\0') { *e = '\0'; p = e + 1; }
            else            { p = e; }
        }
        if (nt < 5)
            continue;

        memset(&t, 0, sizeof t);
        if (elpis_name_from_text(&t.name, tok[0]) != ELPIS_OK)
            continue;
        elpis_name_lower(&t.name);

        {
            unsigned ti = 1;
            if (!elpis_strcasecmp_ascii(tok[ti], "IN") ||
                !elpis_strcasecmp_ascii(tok[ti], "CH"))
                ti++;
            if (ti + 1 >= nt)
                continue;

            if (!elpis_strcasecmp_ascii(tok[ti], "DS")) {
                uint32_t tag, alg, dt;
                size_t dl;
                if (ti + 4 >= nt)
                    continue;
                if (elpis_parse_u32(tok[ti + 1], &tag) != 0 ||
                    elpis_parse_u32(tok[ti + 2], &alg) != 0 ||
                    elpis_parse_u32(tok[ti + 3], &dt) != 0)
                    continue;
                /* The digest may be split across the remaining tokens. */
                {
                    char hex[512];
                    unsigned k;
                    hex[0] = '\0';
                    for (k = ti + 4; k < nt; k++)
                        elpis_strlcat(hex, tok[k], sizeof hex);
                    if (hexdec(hex, t.digest, sizeof t.digest, &dl) != ELPIS_OK)
                        continue;
                }
                t.keytag      = (uint16_t)tag;
                t.alg         = (uint8_t)alg;
                t.digest_type = (uint8_t)dt;
                t.digest_len  = (uint8_t)dl;
                if (ta_push(s, &t) == ELPIS_OK)
                    added++;
            } else if (!elpis_strcasecmp_ascii(tok[ti], "DNSKEY") ||
                       !elpis_strcasecmp_ascii(tok[ti], "KEY")) {
                uint32_t flags, proto, alg;
                uint8_t rd[4096];
                uint8_t ds[4 + 64];
                size_t kl, dl;
                char b64[8192];
                unsigned k;

                if (ti + 4 >= nt)
                    continue;
                if (elpis_parse_u32(tok[ti + 1], &flags) != 0 ||
                    elpis_parse_u32(tok[ti + 2], &proto) != 0 ||
                    elpis_parse_u32(tok[ti + 3], &alg) != 0)
                    continue;
                b64[0] = '\0';
                for (k = ti + 4; k < nt; k++)
                    elpis_strlcat(b64, tok[k], sizeof b64);
                elpis_put16(rd, (uint16_t)flags);
                rd[2] = (uint8_t)proto;
                rd[3] = (uint8_t)alg;
                if (b64dec(b64, rd + 4, sizeof rd - 4, &kl) != ELPIS_OK)
                    continue;
                kl += 4;

                /* Store the key as its SHA-256 DS so one code path validates. */
                {
                    elpis_sha256_t sh;
                    elpis_sha256_init(&sh);
                    elpis_sha256_update(&sh, t.name.d, t.name.len);
                    elpis_sha256_update(&sh, rd, kl);
                    elpis_sha256_final(&sh, ds);
                    dl = 32;
                }
                t.keytag      = elpis_dnskey_tag(rd, kl);
                t.alg         = (uint8_t)alg;
                t.digest_type = ELPIS_DS_SHA256;
                memcpy(t.digest, ds, dl);
                t.digest_len  = (uint8_t)dl;
                if (ta_push(s, &t) == ELPIS_OK)
                    added++;
            }
        }
    }
    fclose(fp);
    elpis_info("trust anchors: %u loaded from %s (%u total)", added, path, s->n);
    return ELPIS_OK;
}

const elpis_name_t *elpis_ta_closest(const elpis_ta_store_t *s,
                                     const elpis_name_t *name)
{
    const elpis_name_t *best = NULL;
    unsigned i;

    for (i = 0; i < s->n; i++) {
        if (!elpis_name_is_subdomain(name, &s->ta[i].name))
            continue;
        if (best == NULL || s->ta[i].name.labels > best->labels)
            best = &s->ta[i].name;
    }
    return best;
}

unsigned elpis_ta_for(const elpis_ta_store_t *s, const elpis_name_t *zone,
                      const elpis_ta_t **out, unsigned max)
{
    unsigned i, n = 0;
    for (i = 0; i < s->n && n < max; i++)
        if (elpis_name_eq(&s->ta[i].name, zone))
            out[n++] = &s->ta[i];
    return n;
}
