/*
 * chachapoly.c -- ChaCha20-Poly1305 (RFC 8439), the mesh's cipher.
 *
 * Like x25519.c this handles secrets, so it runs in constant time: ChaCha20
 * is add-rotate-xor by design, Poly1305 is done in 26-bit limbs with no
 * data-dependent branches, and the tag is compared without an early exit.
 */
#include "elpis/crypto.h"

/* ------------------------------------------------------------------ */
/* Helpers for secrets                                                 */
/* ------------------------------------------------------------------ */

void elpis_memzero(void *p, size_t n)
{
    /* Through a volatile pointer, so a store to memory about to be freed is
     * not optimised away. */
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

int elpis_ct_eq(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t d = 0;
    size_t i;

    for (i = 0; i < n; i++)
        d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0;
}

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void st64(uint8_t *p, uint64_t v)
{
    st32(p, (uint32_t)v);
    st32(p + 4, (uint32_t)(v >> 32));
}

/* ------------------------------------------------------------------ */
/* ChaCha20                                                            */
/* ------------------------------------------------------------------ */

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d)                              \
    do {                                            \
        a += b; d ^= a; d = ROTL(d, 16);            \
        c += d; b ^= c; b = ROTL(b, 12);            \
        a += b; d ^= a; d = ROTL(d, 8);             \
        c += d; b ^= c; b = ROTL(b, 7);             \
    } while (0)

static void chacha_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = in[i];
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++)
        st32(out + 4 * i, x[i] + in[i]);
    elpis_memzero(x, sizeof x);
}

static void chacha_init(uint32_t st[16], const uint8_t key[32],
                        const uint8_t nonce[12], uint32_t counter)
{
    int i;

    st[0] = 0x61707865u;             /* "expand 32-byte k" */
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    for (i = 0; i < 8; i++)
        st[4 + i] = ld32(key + 4 * i);
    st[12] = counter;
    for (i = 0; i < 3; i++)
        st[13 + i] = ld32(nonce + 4 * i);
}

void elpis_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                        uint32_t counter, const uint8_t *in, uint8_t *out,
                        size_t n)
{
    uint32_t st[16];
    uint8_t ks[64];
    size_t i, k;

    chacha_init(st, key, nonce, counter);
    for (i = 0; i < n; i += 64) {
        size_t take = n - i < 64 ? n - i : 64;
        chacha_block(st, ks);
        for (k = 0; k < take; k++)
            out[i + k] = (uint8_t)(in[i + k] ^ ks[k]);
        st[12]++;
    }
    elpis_memzero(st, sizeof st);
    elpis_memzero(ks, sizeof ks);
}

/* ------------------------------------------------------------------ */
/* Poly1305, in five 26-bit limbs                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    size_t   n;
} poly_t;

static void poly_init(poly_t *p, const uint8_t key[32])
{
    /* r is clamped as it is loaded: RFC 8439 section 2.5. */
    p->r[0] = (ld32(key + 0)) & 0x3FFFFFFu;
    p->r[1] = (ld32(key + 3) >> 2) & 0x3FFFF03u;
    p->r[2] = (ld32(key + 6) >> 4) & 0x3FFC0FFu;
    p->r[3] = (ld32(key + 9) >> 6) & 0x3F03FFFu;
    p->r[4] = (ld32(key + 12) >> 8) & 0x00FFFFFu;
    memset(p->h, 0, sizeof p->h);
    p->pad[0] = ld32(key + 16);
    p->pad[1] = ld32(key + 20);
    p->pad[2] = ld32(key + 24);
    p->pad[3] = ld32(key + 28);
    p->n = 0;
}

/* One 16-byte block; `hibit` is 2^128 for a full block, 0 for the last. */
static void poly_block(poly_t *p, const uint8_t m[16], uint32_t hibit)
{
    uint32_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    h0 += (ld32(m + 0)) & 0x3FFFFFFu;
    h1 += (ld32(m + 3) >> 2) & 0x3FFFFFFu;
    h2 += (ld32(m + 6) >> 4) & 0x3FFFFFFu;
    h3 += (ld32(m + 9) >> 6) & 0x3FFFFFFu;
    h4 += (ld32(m + 12) >> 8) | hibit;

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

    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3FFFFFFu;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3FFFFFFu;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3FFFFFFu;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3FFFFFFu;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3FFFFFFu;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFFu;
    h1 += c;

    p->h[0] = h0; p->h[1] = h1; p->h[2] = h2; p->h[3] = h3; p->h[4] = h4;
}

static void poly_update(poly_t *p, const uint8_t *m, size_t n)
{
    while (n > 0) {
        size_t take = 16 - p->n < n ? 16 - p->n : n;
        memcpy(p->buf + p->n, m, take);
        p->n += take;
        m += take;
        n -= take;
        if (p->n == 16) {
            poly_block(p, p->buf, 1u << 24);
            p->n = 0;
        }
    }
}

/* Zeros up to the next 16-byte boundary, as the AEAD construction pads. */
static void poly_pad16(poly_t *p)
{
    static const uint8_t zero[16];
    if (p->n != 0)
        poly_update(p, zero, 16 - p->n);
}

static void poly_final(poly_t *p, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4, mask;
    uint64_t f;

    if (p->n != 0) {
        p->buf[p->n] = 1;
        memset(p->buf + p->n + 1, 0, 16 - p->n - 1);
        poly_block(p, p->buf, 0);
    }

    h0 = p->h[0]; h1 = p->h[1]; h2 = p->h[2]; h3 = p->h[3]; h4 = p->h[4];
    c = h1 >> 26; h1 &= 0x3FFFFFFu;
    h2 += c; c = h2 >> 26; h2 &= 0x3FFFFFFu;
    h3 += c; c = h3 >> 26; h3 &= 0x3FFFFFFu;
    h4 += c; c = h4 >> 26; h4 &= 0x3FFFFFFu;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3FFFFFFu;
    h1 += c;

    /* h - p, taken when it does not go negative, by mask. */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFFu;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFFu;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFFu;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFFu;
    g4 = h4 + c - (1u << 26);
    mask = (g4 >> 31) - 1u;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26));
    h1 = ((h1 >> 6) | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 << 8));

    f = (uint64_t)h0 + p->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + p->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + p->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + p->pad[3] + (f >> 32); h3 = (uint32_t)f;

    st32(tag + 0, h0);
    st32(tag + 4, h1);
    st32(tag + 8, h2);
    st32(tag + 12, h3);
    elpis_memzero(p, sizeof *p);
}

void elpis_poly1305(const uint8_t key[32], const uint8_t *m, size_t n,
                    uint8_t tag[16])
{
    poly_t p;
    poly_init(&p, key);
    poly_update(&p, m, n);
    poly_final(&p, tag);
}

/* ------------------------------------------------------------------ */
/* The AEAD                                                            */
/* ------------------------------------------------------------------ */

static void aead_tag(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *ct, size_t ctlen, uint8_t tag[16])
{
    uint8_t otk[64], lens[16];
    static const uint8_t zero[64];
    poly_t p;

    /* The one-time Poly1305 key is block 0 of the keystream. */
    elpis_chacha20_xor(key, nonce, 0, zero, otk, sizeof otk);
    poly_init(&p, otk);
    poly_update(&p, ad, adlen);
    poly_pad16(&p);
    poly_update(&p, ct, ctlen);
    poly_pad16(&p);
    st64(lens, (uint64_t)adlen);
    st64(lens + 8, (uint64_t)ctlen);
    poly_update(&p, lens, sizeof lens);
    poly_final(&p, tag);
    elpis_memzero(otk, sizeof otk);
}

void elpis_aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    elpis_chacha20_xor(key, nonce, 1, pt, out, ptlen);
    aead_tag(key, nonce, ad, adlen, out, ptlen, out + ptlen);
}

int elpis_aead_open(const uint8_t key[32], const uint8_t nonce[12],
                    const uint8_t *ad, size_t adlen,
                    const uint8_t *ct, size_t ctlen, uint8_t *out)
{
    uint8_t tag[16];

    if (ctlen < 16)
        return ELPIS_ERR;
    aead_tag(key, nonce, ad, adlen, ct, ctlen - 16, tag);
    if (!elpis_ct_eq(tag, ct + ctlen - 16, 16))
        return ELPIS_ERR;       /* nothing is decrypted from a forgery */
    elpis_chacha20_xor(key, nonce, 1, ct, out, ctlen - 16);
    return ELPIS_OK;
}
