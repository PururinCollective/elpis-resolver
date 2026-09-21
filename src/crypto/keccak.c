/*
 * keccak.c -- Keccak-f[1600], SHA3 and SHAKE (FIPS 202).
 *
 * ML-DSA leans on SHAKE for absolutely everything: matrix expansion, hashing
 * the message, sampling the challenge.  Verification time is dominated by
 * this permutation, so it is worth keeping tight.
 */
#include "elpis/crypto.h"

#define NROUNDS 24

static const uint64_t k_rc[NROUNDS] = {
    0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull,
    0x8000000080008000ull, 0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008aull,
    0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull,
    0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull, 0x8000000080008081ull,
    0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
};

static const unsigned k_rho[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned k_pi[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static void keccak_f(uint64_t a[25])
{
    unsigned round;

    for (round = 0; round < NROUNDS; round++) {
        uint64_t bc[5], t;
        unsigned i, j;

        /* theta */
        for (i = 0; i < 5; i++)
            bc[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ elpis_rotl64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                a[i + j] ^= t;
        }

        /* rho and pi */
        t = a[1];
        for (i = 0; i < 24; i++) {
            unsigned k = k_pi[i];
            uint64_t tmp = a[k];
            a[k] = elpis_rotl64(t, k_rho[i]);
            t = tmp;
        }

        /* chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = a[j + i];
            for (i = 0; i < 5; i++)
                a[j + i] = bc[i] ^ (~bc[(i + 1) % 5] & bc[(i + 2) % 5]);
        }

        /* iota */
        a[0] ^= k_rc[round];
    }
}

void elpis_keccak_init(elpis_keccak_t *c, unsigned rate, uint8_t pad)
{
    memset(c->st, 0, sizeof c->st);
    c->rate      = rate;
    c->pos       = 0;
    c->pad       = pad;
    c->squeezing = 0;
}

void elpis_keccak_absorb(elpis_keccak_t *c, const void *p, size_t n)
{
    const uint8_t *s = (const uint8_t *)p;
    uint8_t blk[200];
    unsigned i;

    while (n > 0) {
        unsigned take = c->rate - c->pos;
        if ((size_t)take > n)
            take = (unsigned)n;

        /* XOR into the rate portion, lane by lane. */
        for (i = 0; i < take; i++) {
            unsigned idx = (c->pos + i) / 8u;
            unsigned sh  = ((c->pos + i) % 8u) * 8u;
            c->st[idx] ^= (uint64_t)s[i] << sh;
        }
        c->pos += take;
        s += take;
        n -= take;

        if (c->pos == c->rate) {
            keccak_f(c->st);
            c->pos = 0;
        }
    }
    (void)blk;
}

void elpis_keccak_squeeze(elpis_keccak_t *c, uint8_t *out, size_t n)
{
    if (!c->squeezing) {
        /* Multi-rate padding: pad byte at pos, 0x80 at the last rate byte. */
        c->st[c->pos / 8u] ^= (uint64_t)c->pad << ((c->pos % 8u) * 8u);
        c->st[(c->rate - 1u) / 8u] ^= 0x80ull << (((c->rate - 1u) % 8u) * 8u);
        keccak_f(c->st);
        c->pos = 0;
        c->squeezing = 1;
    }
    while (n > 0) {
        unsigned take = c->rate - c->pos;
        unsigned i;
        if ((size_t)take > n)
            take = (unsigned)n;
        for (i = 0; i < take; i++) {
            unsigned idx = (c->pos + i) / 8u;
            unsigned sh  = ((c->pos + i) % 8u) * 8u;
            out[i] = (uint8_t)(c->st[idx] >> sh);
        }
        out += take;
        n   -= take;
        c->pos += take;
        if (c->pos == c->rate) {
            keccak_f(c->st);
            c->pos = 0;
        }
    }
}

void elpis_shake128_init(elpis_keccak_t *c) { elpis_keccak_init(c, 168, 0x1F); }
void elpis_shake256_init(elpis_keccak_t *c) { elpis_keccak_init(c, 136, 0x1F); }

void elpis_shake256(const void *p, size_t n, uint8_t *out, size_t outlen)
{
    elpis_keccak_t c;
    elpis_shake256_init(&c);
    elpis_keccak_absorb(&c, p, n);
    elpis_keccak_squeeze(&c, out, outlen);
}

void elpis_sha3_256(const void *p, size_t n, uint8_t out[32])
{
    elpis_keccak_t c;
    elpis_keccak_init(&c, 136, 0x06);
    elpis_keccak_absorb(&c, p, n);
    elpis_keccak_squeeze(&c, out, 32);
}

void elpis_sha3_512(const void *p, size_t n, uint8_t out[64])
{
    elpis_keccak_t c;
    elpis_keccak_init(&c, 72, 0x06);
    elpis_keccak_absorb(&c, p, n);
    elpis_keccak_squeeze(&c, out, 64);
}
