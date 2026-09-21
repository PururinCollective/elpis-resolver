/*
 * sha1.c -- SHA-1 (FIPS 180-4).
 *
 * Still required: DS digest type 1 and DNSSEC algorithms 5 and 7 are widely
 * deployed.  Collision attacks on SHA-1 do not translate into a practical
 * DNSSEC forgery when the resolver also has a stronger digest available, and
 * the policy layer prefers SHA-256 whenever a zone publishes both.
 */
#include "elpis/crypto.h"

#define ROL(x, n) ((uint32_t)(((x) << (n)) | ((x) >> (32 - (n)))))

static void sha1_block(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 80; i++)
        w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);            k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6u; }
        {
            uint32_t t = ROL(a, 5) + f + e + k + w[i];
            e = d; d = c; c = ROL(b, 30); b = a; a = t;
        }
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void elpis_sha1_init(elpis_sha1_t *c)
{
    c->h[0] = 0x67452301u;
    c->h[1] = 0xEFCDAB89u;
    c->h[2] = 0x98BADCFEu;
    c->h[3] = 0x10325476u;
    c->h[4] = 0xC3D2E1F0u;
    c->len = 0;
    c->n = 0;
}

void elpis_sha1_update(elpis_sha1_t *c, const void *p, size_t n)
{
    const uint8_t *s = (const uint8_t *)p;
    c->len += (uint64_t)n;

    if (c->n) {
        unsigned take = 64u - c->n;
        if ((size_t)take > n)
            take = (unsigned)n;
        memcpy(c->buf + c->n, s, take);
        c->n += take;
        s += take;
        n -= take;
        if (c->n == 64) {
            sha1_block(c->h, c->buf);
            c->n = 0;
        }
    }
    while (n >= 64) {
        sha1_block(c->h, s);
        s += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, s, n);
        c->n = (unsigned)n;
    }
}

void elpis_sha1_final(elpis_sha1_t *c, uint8_t out[20])
{
    uint64_t bits = c->len * 8u;
    int i;

    c->buf[c->n++] = 0x80;            /* c->n was < 64, so this always fits */
    if (c->n > 56) {
        memset(c->buf + c->n, 0, 64u - c->n);
        sha1_block(c->h, c->buf);
        c->n = 0;
    }
    memset(c->buf + c->n, 0, 56u - c->n);
    elpis_put64(c->buf + 56, bits);
    sha1_block(c->h, c->buf);

    for (i = 0; i < 5; i++)
        elpis_put32(out + i * 4, c->h[i]);
}

void elpis_sha1(const void *p, size_t n, uint8_t out[20])
{
    elpis_sha1_t c;
    elpis_sha1_init(&c);
    elpis_sha1_update(&c, p, n);
    elpis_sha1_final(&c, out);
}
