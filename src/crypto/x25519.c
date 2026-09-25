/*
 * x25519.c -- Diffie-Hellman on Curve25519 (RFC 7748), for the mesh.
 *
 * Unlike everything else in this directory this handles secrets -- the
 * ephemeral keys of a mesh handshake -- so it is written to run in constant
 * time: the ladder swaps with a mask rather than a branch, and the field
 * arithmetic has no data-dependent branches or table lookups.
 *
 * The field representation is sixteen 16-bit limbs held in int64_t, the
 * portable one TweetNaCl made well known: slower than 51-bit limbs, but it
 * needs no 128-bit multiply, so it builds the same on every target, and a
 * mesh does a handful of these per connection, not per query.
 */
#include "elpis/crypto.h"

typedef int64_t fe[16];

static const fe k_121665 = { 0xDB41, 1 };

/* Carry each limb into the next; 2^256 wraps to 38 (2^255 = 19). */
static void fe_carry(fe o)
{
    int i;
    int64_t c;

    for (i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        c = o[i] >> 16;
        if (i < 15)
            o[i + 1] += c - 1;
        else
            o[0] += 38 * (c - 1);
        o[i] -= c * 65536;
    }
}

/* Swap p and q when b is 1, without branching on b. */
static void fe_cswap(fe p, fe q, int64_t b)
{
    int64_t t, mask = ~(b - 1);
    int i;

    for (i = 0; i < 16; i++) {
        t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void fe_pack(uint8_t o[32], const fe n)
{
    int i, j;
    int64_t b;
    fe m, t;

    for (i = 0; i < 16; i++)
        t[i] = n[i];
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);
    /* Subtract p twice, keeping the result only while it stays positive. */
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xFFFF;
        fe_cswap(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xFF);
    }
}

static void fe_unpack(fe o, const uint8_t n[32])
{
    int i;

    for (i = 0; i < 16; i++)
        o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7FFF;            /* RFC 7748: the top bit is ignored */
}

static void fe_add(fe o, const fe a, const fe b)
{
    int i;
    for (i = 0; i < 16; i++)
        o[i] = a[i] + b[i];
}

static void fe_sub(fe o, const fe a, const fe b)
{
    int i;
    for (i = 0; i < 16; i++)
        o[i] = a[i] - b[i];
}

static void fe_mul(fe o, const fe a, const fe b)
{
    int64_t t[31];
    int i, j;

    for (i = 0; i < 31; i++)
        t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++)
        t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++)
        o[i] = t[i];
    fe_carry(o);
    fe_carry(o);
}

/* a^(p-2): the exponent is fixed, so the pattern of steps is too. */
static void fe_invert(fe o, const fe in)
{
    fe c;
    int a;

    for (a = 0; a < 16; a++)
        c[a] = in[a];
    for (a = 253; a >= 0; a--) {
        fe_mul(c, c, c);
        if (a != 2 && a != 4)
            fe_mul(c, c, in);
    }
    for (a = 0; a < 16; a++)
        o[a] = c[a];
}

int elpis_x25519(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32])
{
    uint8_t z[32];
    fe x, a, b, c, d, e, f;
    int64_t r;
    unsigned acc = 0;
    int i;

    for (i = 0; i < 32; i++)
        z[i] = scalar[i];
    z[31] = (uint8_t)((z[31] & 127) | 64);   /* clamp, RFC 7748 section 5 */
    z[0] &= 248;

    fe_unpack(x, point);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        a[i] = c[i] = d[i] = 0;
    }
    a[0] = d[0] = 1;

    /* The Montgomery ladder, one bit at a time, top down. */
    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        fe_cswap(a, b, r);
        fe_cswap(c, d, r);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_add(c, b, d);
        fe_sub(b, b, d);
        fe_mul(d, e, e);
        fe_mul(f, a, a);
        fe_mul(a, c, a);
        fe_mul(c, b, e);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_mul(b, a, a);
        fe_sub(c, d, f);
        fe_mul(a, c, k_121665);
        fe_add(a, a, d);
        fe_mul(c, c, a);
        fe_mul(a, d, f);
        fe_mul(d, b, x);
        fe_mul(b, e, e);
        fe_cswap(a, b, r);
        fe_cswap(c, d, r);
    }
    fe_invert(c, c);
    fe_mul(a, a, c);
    fe_pack(out, a);

    elpis_memzero(z, sizeof z);
    /*
     * A low-order peer point gives all zeros whatever our scalar was: a
     * shared secret the other side chose, not one it had to work out.
     */
    for (i = 0; i < 32; i++)
        acc |= out[i];
    return acc != 0 ? ELPIS_OK : ELPIS_ERR;
}

int elpis_x25519_base(uint8_t pub[32], const uint8_t secret[32])
{
    static const uint8_t k_base[32] = { 9 };
    return elpis_x25519(pub, secret, k_base);
}
