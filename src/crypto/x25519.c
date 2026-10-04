/*
 * x25519.c -- Diffie-Hellman on Curve25519 (RFC 7748).
 *
 * The scalar is a secret, so unlike the signature code elsewhere in this
 * directory (which works on public data with the variable-time bignums in
 * bn.c) this is written to take the same time and touch the same memory
 * whatever the key: the Montgomery ladder with a masked swap, and field
 * arithmetic with no branch on a value.
 *
 * A field element is ten limbs in radix 2^25.5 -- 26 bits, then 25, in turn
 * -- held unsigned.  Every operation leaves its result carried, each limb
 * within a hair of its width, so a product of two limbs, doubled and times
 * 19, summed ten times, stays under 2^61 and a uint64_t never overflows.
 */
#include "elpis/tlscrypto.h"

typedef uint32_t fe[10];

#define M26 0x3ffffffu
#define M25 0x1ffffffu

/* Limb i holds bits [OFF(i), OFF(i) + WIDTH(i)). */
static const unsigned fe_off[10]   = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };
static const unsigned fe_width[10] = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };

/*
 * h (any limbs up to about 2^61) carried into an fe.  The carry out of the
 * top limb is worth 2^255, which is 19 mod p, so it comes back in at the
 * bottom; the small carry that leaves in limb 0 goes one step further.
 */
static void fe_carry(fe out, uint64_t h[10])
{
    uint64_t c;
    int i;

    for (i = 0; i < 9; i++) {
        c = h[i] >> fe_width[i];
        h[i] &= (i & 1) ? M25 : M26;
        h[i + 1] += c;
    }
    c = h[9] >> 25;
    h[9] &= M25;
    h[0] += c * 19u;
    c = h[0] >> 26;
    h[0] &= M26;
    h[1] += c;

    for (i = 0; i < 10; i++)
        out[i] = (uint32_t)h[i];
}

static void fe_0(fe f) { memset(f, 0, sizeof(fe)); }
static void fe_1(fe f) { fe_0(f); f[0] = 1; }
static void fe_copy(fe f, const fe g) { memcpy(f, g, sizeof(fe)); }

static void fe_add(fe out, const fe f, const fe g)
{
    uint64_t h[10];
    int i;
    for (i = 0; i < 10; i++)
        h[i] = (uint64_t)f[i] + g[i];
    fe_carry(out, h);
}

/* f - g, with 2p added first so no limb goes below zero.  g is carried, so
 * each of its limbs is below the matching limb of 2p. */
static void fe_sub(fe out, const fe f, const fe g)
{
    uint64_t h[10];
    int i;
    for (i = 0; i < 10; i++) {
        uint64_t two_p = (i & 1) ? 2u * M25 : 2u * M26;
        if (i == 0)
            two_p = 2u * (M26 - 18u);          /* 2 * (2^26 - 19) */
        h[i] = (uint64_t)f[i] + two_p - g[i];
    }
    fe_carry(out, h);
}

/*
 * Limb i times limb j lands at 2^(off(i) + off(j)).  That is off(i + j),
 * except when both are odd, where the half bits round up twice and it is
 * twice that.  Past limb 9 it wraps: 2^255 = 19 mod p.
 */
static void fe_mul(fe out, const fe f, const fe g)
{
    uint64_t h[10], g19[10];
    int i, k;

    for (i = 0; i < 10; i++)
        g19[i] = (uint64_t)g[i] * 19u;
    for (k = 0; k < 10; k++) {
        uint64_t s = 0;
        for (i = 0; i <= k; i++)
            s += ((uint64_t)f[i] * g[k - i]) << (i & (k - i) & 1);
        for (i = k + 1; i < 10; i++)
            s += ((uint64_t)f[i] * g19[k + 10 - i]) << (i & (k + 10 - i) & 1);
        h[k] = s;
    }
    fe_carry(out, h);
}

/* fe_mul(f, f) with each cross product counted once and doubled. */
static void fe_sq(fe out, const fe f)
{
    uint64_t h[10], f19[10];
    int i, k;

    for (i = 0; i < 10; i++)
        f19[i] = (uint64_t)f[i] * 19u;
    for (k = 0; k < 10; k++) {
        uint64_t s = 0;
        int j;

        for (i = 0; 2 * i < k; i++)
            s += ((uint64_t)f[i] * f[k - i]) << (1 + (i & (k - i) & 1));
        if ((k & 1) == 0)
            s += ((uint64_t)f[k / 2] * f[k / 2]) << ((k / 2) & 1);
        for (i = k + 1; i < 10; i++) {
            j = k + 10 - i;
            if (i < j)
                s += ((uint64_t)f[i] * f19[j]) << (1 + (i & j & 1));
            else if (i == j)
                s += ((uint64_t)f[i] * f19[i]) << (i & 1);
        }
        h[k] = s;
    }
    fe_carry(out, h);
}

static void fe_sqn(fe out, const fe f, int n)
{
    fe_sq(out, f);
    while (--n > 0)
        fe_sq(out, out);
}

static void fe_mul_small(fe out, const fe f, uint32_t k)
{
    uint64_t h[10];
    int i;
    for (i = 0; i < 10; i++)
        h[i] = (uint64_t)f[i] * k;
    fe_carry(out, h);
}

/* z^(p - 2) = 1/z, by the usual chain: 254 squarings and 11 products.  The
 * exponent is public, so this is constant time as it stands. */
static void fe_invert(fe out, const fe z)
{
    fe z2, z9, z11, z5, z10, z20, z50, z100, t;

    fe_sq(z2, z);                       /* 2 */
    fe_sqn(t, z2, 2);                   /* 8 */
    fe_mul(z9, t, z);                   /* 9 */
    fe_mul(z11, z9, z2);                /* 11 */
    fe_sq(t, z11);                      /* 22 */
    fe_mul(z5, t, z9);                  /* 2^5 - 1 */
    fe_sqn(t, z5, 5);
    fe_mul(z10, t, z5);                 /* 2^10 - 1 */
    fe_sqn(t, z10, 10);
    fe_mul(z20, t, z10);                /* 2^20 - 1 */
    fe_sqn(t, z20, 20);
    fe_mul(t, t, z20);                  /* 2^40 - 1 */
    fe_sqn(t, t, 10);
    fe_mul(z50, t, z10);                /* 2^50 - 1 */
    fe_sqn(t, z50, 50);
    fe_mul(z100, t, z50);               /* 2^100 - 1 */
    fe_sqn(t, z100, 100);
    fe_mul(t, t, z100);                 /* 2^200 - 1 */
    fe_sqn(t, t, 50);
    fe_mul(t, t, z50);                  /* 2^250 - 1 */
    fe_sqn(t, t, 5);                    /* 2^255 - 32 */
    fe_mul(out, t, z11);                /* 2^255 - 21 = p - 2 */

    elpis_wipe(z2, sizeof z2);
    elpis_wipe(z9, sizeof z9);
    elpis_wipe(z11, sizeof z11);
    elpis_wipe(z5, sizeof z5);
    elpis_wipe(z10, sizeof z10);
    elpis_wipe(z20, sizeof z20);
    elpis_wipe(z50, sizeof z50);
    elpis_wipe(z100, sizeof z100);
    elpis_wipe(t, sizeof t);
}

/* Swap f and g when bit is 1, without a branch. */
static void fe_cswap(fe f, fe g, uint32_t bit)
{
    uint32_t mask = 0u - bit;
    int i;
    for (i = 0; i < 10; i++) {
        uint32_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

/* 32 little-endian bytes, the top bit ignored as RFC 7748 says for u. */
static void fe_frombytes(fe f, const uint8_t s[32])
{
    uint64_t w[4];
    int i;

    for (i = 0; i < 4; i++)
        w[i] = elpis_get64le(s + i * 8);
    w[3] &= 0x7fffffffffffffffull;

    for (i = 0; i < 10; i++) {
        unsigned off = fe_off[i], sh = off & 63u;
        uint64_t v = w[off >> 6] >> sh;
        if (sh + fe_width[i] > 64u)
            v |= w[(off >> 6) + 1] << (64u - sh);
        f[i] = (uint32_t)(v & ((i & 1) ? M25 : M26));
    }
}

/* The unique representative in [0, p), as 32 little-endian bytes. */
static void fe_tobytes(uint8_t s[32], const fe f)
{
    uint64_t h[10], q, acc = 0;
    unsigned accbits = 0, k = 0;
    int i;

    for (i = 0; i < 10; i++)
        h[i] = f[i];

    /*
     * q = floor((h + 19) / 2^255): 1 exactly when h >= p, as h < 2p here.
     * Then h - q*p is h + 19q with the 2^255 bit dropped.
     */
    q = (h[0] + 19u) >> 26;
    for (i = 1; i < 10; i++)
        q = (h[i] + q) >> fe_width[i];

    h[0] += 19u * q;
    for (i = 0; i < 9; i++) {
        h[i + 1] += h[i] >> fe_width[i];
        h[i] &= (i & 1) ? M25 : M26;
    }
    h[9] &= M25;

    for (i = 0; i < 10; i++) {
        acc |= h[i] << accbits;
        accbits += fe_width[i];
        while (accbits >= 8) {
            s[k++] = (uint8_t)acc;
            acc >>= 8;
            accbits -= 8;
        }
    }
    s[31] = (uint8_t)acc;               /* the last 7 bits */
}

int elpis_x25519(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32])
{
    uint8_t k[32];
    fe x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t;
    uint32_t swap = 0;
    unsigned acc = 0;
    int pos, i;

    memcpy(k, scalar, 32);
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;

    fe_frombytes(x1, point);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    for (pos = 254; pos >= 0; pos--) {
        uint32_t bit = (uint32_t)(k[pos >> 3] >> (pos & 7)) & 1u;

        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b, x2, z2);
        fe_sq(bb, b);
        fe_sub(e, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);

        fe_add(t, da, cb);
        fe_sq(x3, t);
        fe_sub(t, da, cb);
        fe_sq(t, t);
        fe_mul(z3, x1, t);

        fe_mul(x2, aa, bb);
        fe_mul_small(t, e, 121665u);    /* (A - 2) / 4 */
        fe_add(t, aa, t);
        fe_mul(z2, e, t);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);

    for (i = 0; i < 32; i++)
        acc |= out[i];

    elpis_wipe(k, sizeof k);
    elpis_wipe(x2, sizeof x2);
    elpis_wipe(z2, sizeof z2);
    elpis_wipe(x3, sizeof x3);
    elpis_wipe(z3, sizeof z3);
    elpis_wipe(a, sizeof a);
    elpis_wipe(aa, sizeof aa);
    elpis_wipe(b, sizeof b);
    elpis_wipe(bb, sizeof bb);
    elpis_wipe(e, sizeof e);
    elpis_wipe(c, sizeof c);
    elpis_wipe(d, sizeof d);
    elpis_wipe(da, sizeof da);
    elpis_wipe(cb, sizeof cb);
    elpis_wipe(t, sizeof t);

    return acc == 0 ? -1 : 0;
}

void elpis_x25519_base(uint8_t pub[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = { 9 };
    (void)elpis_x25519(pub, scalar, nine);
}
