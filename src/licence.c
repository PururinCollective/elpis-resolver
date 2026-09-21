/*
 * licence.c -- decode and verify a signed deployment licence.
 *
 * The wire form is one line, safe to paste into a config file:
 *
 *   elpis1.<base64url payload>.<base64url signature>
 *
 * and the payload is fixed-layout binary rather than JSON, so the whole token
 * stays inside 255 bytes and fits in a single DNS character-string.
 *
 *   0   1  format version
 *   1   1  edition
 *   2   4  serial          big-endian
 *   6   8  issued          unix seconds, signed
 *   14  8  expires         unix seconds, 0 = perpetual
 *   22  1  length of org
 *   23  N  org, UTF-8
 *
 * What is signed is ELPIS_LICENCE_CONTEXT followed by those bytes.  The
 * context string is what stops a signature made here being meaningful
 * anywhere else, and vice versa.
 */
#include "elpis/licence.h"
#include "elpis/crypto.h"
#include "elpis/util.h"

#include <string.h>
#include <time.h>

#define LICENCE_FORMAT 2
#define PAYLOAD_FIXED  23

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t elpis_b64url_encode(const uint8_t *in, size_t n, char *out, size_t cap)
{
    size_t i = 0, o = 0;

    while (i < n) {
        uint32_t v = (uint32_t)in[i] << 16;
        unsigned have = 1;

        if (i + 1 < n) { v |= (uint32_t)in[i + 1] << 8; have++; }
        if (i + 2 < n) { v |= (uint32_t)in[i + 2];      have++; }

        if (o + have + 1u > cap)                 /* +1 for the terminator */
            return 0;
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        if (have > 1) out[o++] = b64[(v >> 6) & 63];
        if (have > 2) out[o++] = b64[v & 63];
        i += 3;
    }
    if (o >= cap)
        return 0;
    out[o] = '\0';
    return o;
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

int elpis_b64url_decode(const char *in, size_t n, uint8_t *out, size_t cap,
                        size_t *outn)
{
    size_t i = 0, o = 0;

    while (i < n) {
        uint32_t v = 0;
        unsigned have = 0, j;

        for (j = 0; j < 4 && i < n; j++) {
            int d = b64val(in[i]);
            if (d < 0)
                return ELPIS_ERR;
            v = (v << 6) | (uint32_t)d;
            have++; i++;
        }
        if (have < 2)                     /* a lone character encodes nothing */
            return ELPIS_ERR;
        v <<= 6u * (4u - have);

        if (o + (have - 1u) > cap)
            return ELPIS_ERR;
        out[o++] = (uint8_t)(v >> 16);
        if (have > 2) out[o++] = (uint8_t)(v >> 8);
        if (have > 3) out[o++] = (uint8_t)v;
    }
    *outn = o;
    return ELPIS_OK;
}

int elpis_hex_decode(const char *in, uint8_t *out, size_t cap, size_t *outn)
{
    size_t n = strlen(in), i;

    if (n % 2u != 0 || n / 2u > cap)
        return ELPIS_ERR;
    for (i = 0; i < n; i += 2) {
        unsigned v = 0, k;
        for (k = 0; k < 2; k++) {
            char c = in[i + k];
            v <<= 4;
            if      (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return ELPIS_ERR;
        }
        out[i / 2u] = (uint8_t)v;
    }
    *outn = n / 2u;
    return ELPIS_OK;
}

const char *elpis_edition_name(elpis_edition_t e)
{
    switch (e) {
    case ELPIS_ED_COMMERCIAL: return "commercial";
    case ELPIS_ED_COMMUNITY:  return "community";
    case ELPIS_ED_HOMELAB:    return "homelab";
    case ELPIS_ED_EVALUATION: return "evaluation";
    default:                  return "unknown";
    }
}

int elpis_edition_from_name(const char *s, elpis_edition_t *out)
{
    static const struct { const char *n; elpis_edition_t e; } map[] = {
        { "commercial", ELPIS_ED_COMMERCIAL },
        { "community",  ELPIS_ED_COMMUNITY  },
        { "homelab",    ELPIS_ED_HOMELAB    },
        { "evaluation", ELPIS_ED_EVALUATION }
    };
    unsigned i;

    for (i = 0; i < ELPIS_ARRAY_LEN(map); i++) {
        if (!elpis_strcasecmp_ascii(s, map[i].n)) {
            *out = map[i].e;
            return ELPIS_OK;
        }
    }
    return ELPIS_ERR;
}

void elpis_licence_date(int64_t t, char *out, size_t outsz)
{
    time_t tt = (time_t)t;
    struct tm tm;

    if (t == 0) {
        elpis_strlcpy(out, "never", outsz);
        return;
    }
#if defined(_POSIX_VERSION)
    if (gmtime_r(&tt, &tm) == NULL) {
        elpis_strlcpy(out, "?", outsz);
        return;
    }
#else
    {
        struct tm *p = gmtime(&tt);
        if (p == NULL) { elpis_strlcpy(out, "?", outsz); return; }
        tm = *p;
    }
#endif
    snprintf(out, outsz, "%04d-%02d-%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void put_i64(uint8_t *p, int64_t v)
{
    uint64_t u = (uint64_t)v;
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(u >> (56 - i * 8));
}

static int64_t get_i64(const uint8_t *p)
{
    uint64_t u = 0;
    int i;
    for (i = 0; i < 8; i++)
        u = (u << 8) | (uint64_t)p[i];
    return (int64_t)u;
}

size_t elpis_licence_payload(const elpis_licence_t *l, uint8_t *out, size_t cap)
{
    size_t orglen = strlen(l->org);

    if (orglen > ELPIS_LICENCE_MAX_ORG || cap < PAYLOAD_FIXED + orglen)
        return 0;
    out[0] = LICENCE_FORMAT;
    out[1] = (uint8_t)l->edition;
    put_u32(out + 2,  l->serial);
    put_i64(out + 6,  l->issued);
    put_i64(out + 14, l->expires);
    out[22] = (uint8_t)orglen;
    memcpy(out + 23, l->org, orglen);
    return PAYLOAD_FIXED + orglen;
}

int elpis_licence_enabled(void)
{
    return ELPIS_LICENCE_ISSUER[0] != '\0';
}

static int issuer_key(uint8_t pk[32])
{
    size_t n = 0;

    if (!elpis_licence_enabled())
        return ELPIS_ERR;
    if (elpis_hex_decode(ELPIS_LICENCE_ISSUER, pk, 32, &n) != ELPIS_OK || n != 32)
        return ELPIS_ERR;
    return ELPIS_OK;
}

static int fail(elpis_licence_t *out, const char *why)
{
    elpis_strlcpy(out->why, why, sizeof out->why);
    return ELPIS_ERR;
}

int elpis_licence_parse(const char *token, int64_t now, elpis_licence_t *out)
{
    const char *p1, *p2;
    uint8_t payload[ELPIS_LICENCE_MAX_TOKEN];
    uint8_t sig[80], pk[32], signed_buf[ELPIS_LICENCE_MAX_TOKEN + 32];
    size_t  plen = 0, slen = 0, ctxlen = strlen(ELPIS_LICENCE_CONTEXT);
    size_t  maglen = strlen(ELPIS_LICENCE_MAGIC);
    unsigned orglen;

    memset(out, 0, sizeof *out);
    out->present = 1;

    if (strlen(token) >= ELPIS_LICENCE_MAX_TOKEN)
        return fail(out, "token is too long");
    if (strncmp(token, ELPIS_LICENCE_MAGIC, maglen) != 0 || token[maglen] != '.')
        return fail(out, "not an " ELPIS_LICENCE_MAGIC " token");

    p1 = token + maglen + 1;
    p2 = strchr(p1, '.');
    if (p2 == NULL)
        return fail(out, "token has no signature");

    if (elpis_b64url_decode(p1, (size_t)(p2 - p1), payload, sizeof payload,
                            &plen) != ELPIS_OK)
        return fail(out, "payload is not valid base64url");
    if (elpis_b64url_decode(p2 + 1, strlen(p2 + 1), sig, sizeof sig,
                            &slen) != ELPIS_OK)
        return fail(out, "signature is not valid base64url");
    if (slen != 64)
        return fail(out, "signature is not 64 bytes");

    if (plen < PAYLOAD_FIXED)
        return fail(out, "payload is truncated");
    if (payload[0] != LICENCE_FORMAT) {
        char msg[96];
        snprintf(msg, sizeof msg,
                 "licence is format %u, this build speaks format %u",
                 (unsigned)payload[0], (unsigned)LICENCE_FORMAT);
        return fail(out, msg);
    }

    orglen = payload[22];
    if (plen != PAYLOAD_FIXED + orglen)
        return fail(out, "payload length does not match its org field");

    /*
     * Read the claims before checking the signature, so an unverified licence
     * can still be described in a log line -- but `valid` stays 0 until the
     * signature says otherwise, and nothing else in the resolver looks at
     * these fields without checking it.
     */
    out->edition = (elpis_edition_t)payload[1];
    out->serial  = get_u32(payload + 2);
    out->issued  = get_i64(payload + 6);
    out->expires = get_i64(payload + 14);
    memcpy(out->org, payload + 23, orglen);
    out->org[orglen] = '\0';

    if (issuer_key(pk) != ELPIS_OK)
        return fail(out, "this build carries no issuer key, so no licence can be checked");

    memcpy(signed_buf, ELPIS_LICENCE_CONTEXT, ctxlen);
    memcpy(signed_buf + ctxlen, payload, plen);
    if (!elpis_ed25519_verify(pk, signed_buf, ctxlen + plen, sig))
        return fail(out, "signature does not match this build's issuer key");

    out->valid = 1;
    if (out->expires != 0 && now > out->expires)
        out->expired = 1;
    return ELPIS_OK;
}
