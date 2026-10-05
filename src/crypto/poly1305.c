/*
 * poly1305.c -- the Poly1305 one-time authenticator (RFC 8439 section 2.5).
 *
 * The accumulator is five 26-bit limbs, so every product fits in 64 bits and
 * the code stays C99 with no 128-bit type -- the layout of Andrew Moon's
 * poly1305-donna.  No branch or index depends on the key or the message;
 * the final reduction picks between h and h - p with a mask.
 */
#include "elpis/tlscrypto.h"

#define M26 0x3ffffffu

static void blocks(elpis_poly1305_t *p, const uint8_t *m, size_t n,
                   uint32_t hibit)
{
    const uint32_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2],
                   r3 = p->r[3], r4 = p->r[4];
    const uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;
    uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2],
             h3 = p->h[3], h4 = p->h[4];

    while (n >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += elpis_get32le(m + 0) & M26;
        h1 += (elpis_get32le(m + 3) >> 2) & M26;
        h2 += (elpis_get32le(m + 6) >> 4) & M26;
        h3 += (elpis_get32le(m + 9) >> 6) & M26;
        h4 += (elpis_get32le(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
             (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
             (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
             (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
             (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
             (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & M26; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & M26; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & M26; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & M26; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & M26;
        h0 += c * 5u;
        c = h0 >> 26; h0 &= M26;
        h1 += c;

        m += 16;
        n -= 16;
    }
    p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

void elpis_poly1305_init(elpis_poly1305_t *p, const uint8_t key[32])
{
    /* r is clamped as section 2.5 says, already split into limbs. */
    p->r[0] = elpis_get32le(key + 0) & 0x3ffffffu;
    p->r[1] = (elpis_get32le(key + 3) >> 2) & 0x3ffff03u;
    p->r[2] = (elpis_get32le(key + 6) >> 4) & 0x3ffc0ffu;
    p->r[3] = (elpis_get32le(key + 9) >> 6) & 0x3f03fffu;
    p->r[4] = (elpis_get32le(key + 12) >> 8) & 0x00fffffu;
    memset(p->h, 0, sizeof p->h);
    p->pad[0] = elpis_get32le(key + 16);
    p->pad[1] = elpis_get32le(key + 20);
    p->pad[2] = elpis_get32le(key + 24);
    p->pad[3] = elpis_get32le(key + 28);
    p->n = 0;
}

void elpis_poly1305_update(elpis_poly1305_t *p, const uint8_t *m, size_t n)
{
    if (p->n > 0) {
        size_t take = 16u - p->n;
        if (take > n)
            take = n;
        memcpy(p->buf + p->n, m, take);
        p->n += (unsigned)take;
        m += take;
        n -= take;
        if (p->n < 16)
            return;
        blocks(p, p->buf, 16, 1u << 24);
        p->n = 0;
    }
    if (n >= 16) {
        size_t whole = n & ~(size_t)15;
        blocks(p, m, whole, 1u << 24);
        m += whole;
        n -= whole;
    }
    if (n > 0) {
        memcpy(p->buf, m, n);
        p->n = (unsigned)n;
    }
}

void elpis_poly1305_final(elpis_poly1305_t *p, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4, mask;
    uint64_t f;

    /* A short last block gets its 1 byte here instead of the 2^128 bit. */
    if (p->n > 0) {
        p->buf[p->n] = 1;
        memset(p->buf + p->n + 1, 0, 15u - p->n);
        blocks(p, p->buf, 16, 0);
    }

    h0 = p->h[0]; h1 = p->h[1]; h2 = p->h[2]; h3 = p->h[3]; h4 = p->h[4];

    c = h1 >> 26; h1 &= M26; h2 += c;
    c = h2 >> 26; h2 &= M26; h3 += c;
    c = h3 >> 26; h3 &= M26; h4 += c;
    c = h4 >> 26; h4 &= M26; h0 += c * 5u;
    c = h0 >> 26; h0 &= M26; h1 += c;

    /* g = h + 5 - 2^130, which is h - p; keep it when it did not borrow. */
    g0 = h0 + 5u; c = g0 >> 26; g0 &= M26;
    g1 = h1 + c;  c = g1 >> 26; g1 &= M26;
    g2 = h2 + c;  c = g2 >> 26; g2 &= M26;
    g3 = h3 + c;  c = g3 >> 26; g3 &= M26;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1u;            /* all ones when h >= p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h mod 2^128, as four 32-bit words, plus the pad. */
    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    f = (uint64_t)h0 + p->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + p->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + p->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + p->pad[3] + (f >> 32); h3 = (uint32_t)f;

    elpis_put32le(tag + 0, h0);
    elpis_put32le(tag + 4, h1);
    elpis_put32le(tag + 8, h2);
    elpis_put32le(tag + 12, h3);

    elpis_wipe(p, sizeof *p);
}
