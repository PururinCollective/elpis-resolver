/*
 * sha2.c -- SHA-224/256/384/512 (FIPS 180-4).
 */
#include "elpis/crypto.h"

/* ================================================================== */
/* SHA-256                                                             */
/* ================================================================== */

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define R32(x, n) elpis_rotr32((x), (n))
#define S0(x) (R32(x, 2)  ^ R32(x, 13) ^ R32(x, 22))
#define S1(x) (R32(x, 6)  ^ R32(x, 11) ^ R32(x, 25))
#define s0(x) (R32(x, 7)  ^ R32(x, 18) ^ ((x) >> 3))
#define s1(x) (R32(x, 17) ^ R32(x, 19) ^ ((x) >> 10))

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = elpis_get32(p + i * 4);
    for (i = 16; i < 64; i++)
        w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t t1 = hh + S1(e) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = S0(a) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void elpis_sha256_init(elpis_sha256_t *c)
{
    static const uint32_t iv[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
    c->n = 0;
    c->outlen = 32;
}

void elpis_sha256_update(elpis_sha256_t *c, const void *p, size_t n)
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
            sha256_block(c->h, c->buf);
            c->n = 0;
        }
    }
    while (n >= 64) {
        sha256_block(c->h, s);
        s += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, s, n);
        c->n = (unsigned)n;
    }
}

void elpis_sha256_final(elpis_sha256_t *c, uint8_t *out)
{
    uint64_t bits = c->len * 8u;
    unsigned i, words;

    c->buf[c->n++] = 0x80;
    if (c->n > 56) {
        memset(c->buf + c->n, 0, 64u - c->n);
        sha256_block(c->h, c->buf);
        c->n = 0;
    }
    memset(c->buf + c->n, 0, 56u - c->n);
    elpis_put64(c->buf + 56, bits);
    sha256_block(c->h, c->buf);

    words = c->outlen / 4u;
    for (i = 0; i < words; i++)
        elpis_put32(out + i * 4, c->h[i]);
}

void elpis_sha256(const void *p, size_t n, uint8_t out[32])
{
    elpis_sha256_t c;
    elpis_sha256_init(&c);
    elpis_sha256_update(&c, p, n);
    elpis_sha256_final(&c, out);
}

/* ================================================================== */
/* SHA-512 / SHA-384                                                   */
/* ================================================================== */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ull,0x7137449123ef65cdull,0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull,0x3956c25bf348b538ull,0x59f111f1b605d019ull,
    0x923f82a4af194f9bull,0xab1c5ed5da6d8118ull,0xd807aa98a3030242ull,
    0x12835b0145706fbeull,0x243185be4ee4b28cull,0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full,0x80deb1fe3b1696b1ull,0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull,0xe49b69c19ef14ad2ull,0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull,0x240ca1cc77ac9c65ull,0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull,0x5cb0a9dcbd41fbd4ull,0x76f988da831153b5ull,
    0x983e5152ee66dfabull,0xa831c66d2db43210ull,0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull,0xc6e00bf33da88fc2ull,0xd5a79147930aa725ull,
    0x06ca6351e003826full,0x142929670a0e6e70ull,0x27b70a8546d22ffcull,
    0x2e1b21385c26c926ull,0x4d2c6dfc5ac42aedull,0x53380d139d95b3dfull,
    0x650a73548baf63deull,0x766a0abb3c77b2a8ull,0x81c2c92e47edaee6ull,
    0x92722c851482353bull,0xa2bfe8a14cf10364ull,0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull,0xc76c51a30654be30ull,0xd192e819d6ef5218ull,
    0xd69906245565a910ull,0xf40e35855771202aull,0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull,0x1e376c085141ab53ull,0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull,0x391c0cb3c5c95a63ull,0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull,0x682e6ff3d6b2b8a3ull,0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull,0x84c87814a1f0ab72ull,0x8cc702081a6439ecull,
    0x90befffa23631e28ull,0xa4506cebde82bde9ull,0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull,0xca273eceea26619cull,0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull,0xf57d4f7fee6ed178ull,0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull,0x113f9804bef90daeull,0x1b710b35131c471bull,
    0x28db77f523047d84ull,0x32caab7b40c72493ull,0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull,0x4cc5d4becb3e42b6ull,0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull,0x6c44198c4a475817ull
};

#define R64(x, n) elpis_rotr64((x), (n))
#define T0(x) (R64(x, 28) ^ R64(x, 34) ^ R64(x, 39))
#define T1(x) (R64(x, 14) ^ R64(x, 18) ^ R64(x, 41))
#define t0(x) (R64(x, 1)  ^ R64(x, 8)  ^ ((x) >> 7))
#define t1(x) (R64(x, 19) ^ R64(x, 61) ^ ((x) >> 6))

static void sha512_block(uint64_t h[8], const uint8_t *p)
{
    uint64_t w[80], a, b, c, d, e, f, g, hh;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = elpis_get64(p + i * 8);
    for (i = 16; i < 80; i++)
        w[i] = t1(w[i - 2]) + w[i - 7] + t0(w[i - 15]) + w[i - 16];

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 80; i++) {
        uint64_t x1 = hh + T1(e) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
        uint64_t x2 = T0(a) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + x1;
        d = c; c = b; b = a; a = x1 + x2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void elpis_sha512_init(elpis_sha512_t *c)
{
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ull,0xbb67ae8584caa73bull,0x3c6ef372fe94f82bull,
        0xa54ff53a5f1d36f1ull,0x510e527fade682d1ull,0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull,0x5be0cd19137e2179ull
    };
    memcpy(c->h, iv, sizeof iv);
    c->lenlo = c->lenhi = 0;
    c->n = 0;
    c->outlen = 64;
}

void elpis_sha384_init(elpis_sha512_t *c)
{
    static const uint64_t iv[8] = {
        0xcbbb9d5dc1059ed8ull,0x629a292a367cd507ull,0x9159015a3070dd17ull,
        0x152fecd8f70e5939ull,0x67332667ffc00b31ull,0x8eb44a8768581511ull,
        0xdb0c2e0d64f98fa7ull,0x47b5481dbefa4fa4ull
    };
    memcpy(c->h, iv, sizeof iv);
    c->lenlo = c->lenhi = 0;
    c->n = 0;
    c->outlen = 48;
}

void elpis_sha512_update(elpis_sha512_t *c, const void *p, size_t n)
{
    const uint8_t *s = (const uint8_t *)p;
    uint64_t prev = c->lenlo;

    c->lenlo += (uint64_t)n;
    if (c->lenlo < prev)
        c->lenhi++;

    if (c->n) {
        unsigned take = 128u - c->n;
        if ((size_t)take > n)
            take = (unsigned)n;
        memcpy(c->buf + c->n, s, take);
        c->n += take;
        s += take;
        n -= take;
        if (c->n == 128) {
            sha512_block(c->h, c->buf);
            c->n = 0;
        }
    }
    while (n >= 128) {
        sha512_block(c->h, s);
        s += 128;
        n -= 128;
    }
    if (n) {
        memcpy(c->buf, s, n);
        c->n = (unsigned)n;
    }
}

void elpis_sha512_final(elpis_sha512_t *c, uint8_t *out)
{
    uint64_t lo = c->lenlo << 3;
    uint64_t hi = (c->lenhi << 3) | (c->lenlo >> 61);
    unsigned i, words;

    c->buf[c->n++] = 0x80;
    if (c->n > 112) {
        memset(c->buf + c->n, 0, 128u - c->n);
        sha512_block(c->h, c->buf);
        c->n = 0;
    }
    memset(c->buf + c->n, 0, 112u - c->n);
    elpis_put64(c->buf + 112, hi);
    elpis_put64(c->buf + 120, lo);
    sha512_block(c->h, c->buf);

    words = c->outlen / 8u;
    for (i = 0; i < words; i++)
        elpis_put64(out + i * 8, c->h[i]);
}

void elpis_sha512(const void *p, size_t n, uint8_t out[64])
{
    elpis_sha512_t c;
    elpis_sha512_init(&c);
    elpis_sha512_update(&c, p, n);
    elpis_sha512_final(&c, out);
}

void elpis_sha384(const void *p, size_t n, uint8_t out[48])
{
    elpis_sha512_t c;
    uint8_t full[64];      /* final() writes whole 64-bit words */

    elpis_sha384_init(&c);
    elpis_sha512_update(&c, p, n);
    elpis_sha512_final(&c, full);
    memcpy(out, full, 48);
}

/* ================================================================== */
/* Dispatch                                                            */
/* ================================================================== */

size_t elpis_hash_len(int alg)
{
    switch (alg) {
    case ELPIS_HASH_SHA1:   return 20;
    case ELPIS_HASH_SHA256: return 32;
    case ELPIS_HASH_SHA384: return 48;
    case ELPIS_HASH_SHA512: return 64;
    default:                return 0;
    }
}

int elpis_hash(int alg, const void *p, size_t n, uint8_t *out)
{
    switch (alg) {
    case ELPIS_HASH_SHA1:   elpis_sha1(p, n, out);   return ELPIS_OK;
    case ELPIS_HASH_SHA256: elpis_sha256(p, n, out); return ELPIS_OK;
    case ELPIS_HASH_SHA384: elpis_sha384(p, n, out); return ELPIS_OK;
    case ELPIS_HASH_SHA512: elpis_sha512(p, n, out); return ELPIS_OK;
    default:                return ELPIS_ERR;
    }
}
