/*
 * aes.c -- AES-128 and GHASH in portable, constant-time C.
 *
 * The usual fast AES looks the state up in tables, and which cache lines it
 * touches gives the key away to anyone timing it.  So the S-box here is
 * computed, not looked up: the inverse in GF(2^8) as x^254, then the affine
 * map, done on eight bytes at once in a 64-bit word.  GHASH likewise
 * multiplies bit by bit under a mask instead of using the 4-bit tables.
 *
 * It is slow -- tens of MB/s against GB/s for AES-NI -- and that is fine for
 * what it is for: ChaCha20-Poly1305 is the suite a client offers first, and
 * this only carries a server that refuses it, on a CPU without AES-NI.
 */
#include "aes.h"

#define LO7 0x7f7f7f7f7f7f7f7full
#define LSB 0x0101010101010101ull

/* Multiply each of eight bytes by x in GF(2^8). */
static uint64_t xtime8(uint64_t a)
{
    return ((a & LO7) << 1) ^ (((a >> 7) & LSB) * 0x1bu);
}

/* Eight independent GF(2^8) products, lane by lane. */
static uint64_t gfmul8(uint64_t a, uint64_t b)
{
    uint64_t r = 0;
    int i;
    for (i = 0; i < 8; i++) {
        r ^= a & (((b >> i) & LSB) * 0xffu);
        a = xtime8(a);
    }
    return r;
}

/* Rotate each byte left by k. */
static uint64_t rotl8(uint64_t x, unsigned k)
{
    uint64_t hi = (0xffu << k) & 0xffu, lo = 0xffu >> (8u - k);
    return ((x << k) & (hi * LSB)) | ((x >> (8u - k)) & (lo * LSB));
}

/* The AES S-box on eight bytes: x^254 (0 stays 0), then the affine map. */
static uint64_t sub8(uint64_t x)
{
    uint64_t x2, x3, x12, x15, y;

    x2  = gfmul8(x, x);
    x3  = gfmul8(x2, x);
    x12 = gfmul8(x3, x3);
    x12 = gfmul8(x12, x12);             /* x^12 */
    x15 = gfmul8(x12, x3);
    y   = gfmul8(x15, x15);
    y   = gfmul8(y, y);
    y   = gfmul8(y, y);
    y   = gfmul8(y, y);                 /* x^240 */
    y   = gfmul8(y, x12);               /* x^252 */
    y   = gfmul8(y, x2);                /* x^254 */

    return y ^ rotl8(y, 1) ^ rotl8(y, 2) ^ rotl8(y, 3) ^ rotl8(y, 4) ^
           (0x63u * LSB);
}

static void sub_bytes(uint8_t s[16])
{
    uint64_t a = elpis_get64le(s), b = elpis_get64le(s + 8);
    elpis_put64le(s, sub8(a));
    elpis_put64le(s + 8, sub8(b));
}

/* Row r of the state (bytes r, r+4, r+8, r+12) moves left by r. */
static void shift_rows(uint8_t s[16])
{
    uint8_t t;

    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static uint8_t xtime(uint8_t b)
{
    return (uint8_t)((b << 1) ^ (((b >> 7) & 1u) * 0x1bu));
}

static void mix_columns(uint8_t s[16])
{
    int c;
    for (c = 0; c < 4; c++) {
        uint8_t *p = s + 4 * c;
        uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        p[0] = (uint8_t)(a0 ^ all ^ xtime((uint8_t)(a0 ^ a1)));
        p[1] = (uint8_t)(a1 ^ all ^ xtime((uint8_t)(a1 ^ a2)));
        p[2] = (uint8_t)(a2 ^ all ^ xtime((uint8_t)(a2 ^ a3)));
        p[3] = (uint8_t)(a3 ^ all ^ xtime((uint8_t)(a3 ^ a0)));
    }
}

static void add_round_key(uint8_t s[16], const uint8_t *k)
{
    int i;
    for (i = 0; i < 16; i++)
        s[i] ^= k[i];
}

void elpis_aes_soft_expand(uint8_t rk[176], const uint8_t key[16])
{
    uint8_t rcon = 1;
    int i;

    memcpy(rk, key, 16);
    for (i = 16; i < 176; i += 16) {
        const uint8_t *prev = rk + i - 16;
        uint8_t t[8];
        int j;

        /* SubWord(RotWord(w[i-1])), padded to a word pair for sub8. */
        t[0] = prev[13]; t[1] = prev[14]; t[2] = prev[15]; t[3] = prev[12];
        t[4] = t[5] = t[6] = t[7] = 0;
        elpis_put64le(t, sub8(elpis_get64le(t)));
        t[0] ^= rcon;
        rcon = xtime(rcon);

        for (j = 0; j < 4; j++)
            rk[i + j] = (uint8_t)(prev[j] ^ t[j]);
        for (j = 4; j < 16; j++)
            rk[i + j] = (uint8_t)(prev[j] ^ rk[i + j - 4]);
        elpis_wipe(t, sizeof t);
    }
}

void elpis_aes_soft_encrypt(const uint8_t rk[176], const uint8_t in[16],
                            uint8_t out[16])
{
    uint8_t s[16];
    int r;

    memcpy(s, in, 16);
    add_round_key(s, rk);
    for (r = 1; r < 10; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, rk + 16 * r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, rk + 160);
    memcpy(out, s, 16);
    elpis_wipe(s, sizeof s);
}

void elpis_aes_soft_ctr(const uint8_t rk[176], const uint8_t ctr[16],
                        const uint8_t *in, uint8_t *out, size_t n)
{
    uint8_t cb[16], ks[16];
    uint32_t c = elpis_get32(ctr + 12);

    memcpy(cb, ctr, 12);
    while (n > 0) {
        size_t take = n < 16 ? n : 16, i;

        elpis_put32(cb + 12, c++);
        elpis_aes_soft_encrypt(rk, cb, ks);
        for (i = 0; i < take; i++)
            out[i] = (uint8_t)(in[i] ^ ks[i]);
        in  += take;
        out += take;
        n   -= take;
    }
    elpis_wipe(ks, sizeof ks);
}

/*
 * y = y * h in GF(2^128) with GCM's bit order: bit 0 is the top bit of the
 * first byte, and R = 0xe1 || 0^120 (SP 800-38D, algorithm 1), every step
 * under a mask.
 */
static void gf128_mul(uint64_t *yh, uint64_t *yl, uint64_t hh, uint64_t hl)
{
    uint64_t zh = 0, zl = 0, vh = hh, vl = hl;
    uint64_t xh = *yh, xl = *yl;
    int i;

    for (i = 0; i < 128; i++) {
        uint64_t bit = (i < 64 ? xh >> (63 - i) : xl >> (127 - i)) & 1u;
        uint64_t m = 0u - bit;
        uint64_t lsb = 0u - (vl & 1u);

        zh ^= vh & m;
        zl ^= vl & m;
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (0xe100000000000000ull & lsb);
    }
    *yh = zh;
    *yl = zl;
}

void elpis_ghash_soft(const uint8_t h[16], uint8_t y[16],
                      const uint8_t *data, size_t n)
{
    uint64_t hh = elpis_get64(h), hl = elpis_get64(h + 8);
    uint64_t yh = elpis_get64(y), yl = elpis_get64(y + 8);

    while (n > 0) {
        uint8_t blk[16];
        size_t take = n < 16 ? n : 16;

        memset(blk, 0, sizeof blk);
        memcpy(blk, data, take);
        yh ^= elpis_get64(blk);
        yl ^= elpis_get64(blk + 8);
        gf128_mul(&yh, &yl, hh, hl);
        data += take;
        n    -= take;
    }
    elpis_put64(y, yh);
    elpis_put64(y + 8, yl);
}
