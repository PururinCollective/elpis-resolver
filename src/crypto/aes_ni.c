/*
 * aes_ni.c -- AES-128 and GHASH on AES-NI and PCLMULQDQ.
 *
 * Built with -maes -mpclmul -mssse3 and called only when CPUID says the
 * instructions are there (simd.c), the same arrangement as simd_avx2.c.  The
 * hardware rounds take no table lookups, so they are constant time as well as
 * fast.  GHASH is the reflected-operand multiply from Gueron and Kounavis,
 * "Intel Carry-Less Multiplication Instruction and its Usage for Computing
 * the GCM Mode", with blocks byte-reversed on the way in and out.
 */
#include "aes.h"

#include <wmmintrin.h>
#include <tmmintrin.h>

static __m128i expand_step(__m128i key, __m128i assist)
{
    assist = _mm_shuffle_epi32(assist, 0xff);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, assist);
}

void elpis_aes_ni_expand(uint8_t rk[176], const uint8_t key[16])
{
    __m128i k[11];
    int i;

    /* aeskeygenassist wants its round constant as an immediate. */
    k[0]  = _mm_loadu_si128((const __m128i *)(const void *)key);
    k[1]  = expand_step(k[0], _mm_aeskeygenassist_si128(k[0], 0x01));
    k[2]  = expand_step(k[1], _mm_aeskeygenassist_si128(k[1], 0x02));
    k[3]  = expand_step(k[2], _mm_aeskeygenassist_si128(k[2], 0x04));
    k[4]  = expand_step(k[3], _mm_aeskeygenassist_si128(k[3], 0x08));
    k[5]  = expand_step(k[4], _mm_aeskeygenassist_si128(k[4], 0x10));
    k[6]  = expand_step(k[5], _mm_aeskeygenassist_si128(k[5], 0x20));
    k[7]  = expand_step(k[6], _mm_aeskeygenassist_si128(k[6], 0x40));
    k[8]  = expand_step(k[7], _mm_aeskeygenassist_si128(k[7], 0x80));
    k[9]  = expand_step(k[8], _mm_aeskeygenassist_si128(k[8], 0x1b));
    k[10] = expand_step(k[9], _mm_aeskeygenassist_si128(k[9], 0x36));

    for (i = 0; i < 11; i++)
        _mm_storeu_si128((__m128i *)(void *)(rk + 16 * i), k[i]);
    for (i = 0; i < 11; i++)
        k[i] = _mm_setzero_si128();
}

static __m128i encrypt_block(const uint8_t rk[176], __m128i b)
{
    int r;

    b = _mm_xor_si128(b, _mm_loadu_si128((const __m128i *)(const void *)rk));
    for (r = 1; r < 10; r++)
        b = _mm_aesenc_si128(b,
                _mm_loadu_si128((const __m128i *)(const void *)(rk + 16 * r)));
    return _mm_aesenclast_si128(b,
                _mm_loadu_si128((const __m128i *)(const void *)(rk + 160)));
}

void elpis_aes_ni_encrypt(const uint8_t rk[176], const uint8_t in[16],
                          uint8_t out[16])
{
    __m128i b = _mm_loadu_si128((const __m128i *)(const void *)in);
    _mm_storeu_si128((__m128i *)(void *)out, encrypt_block(rk, b));
}

void elpis_aes_ni_ctr(const uint8_t rk[176], const uint8_t ctr[16],
                      const uint8_t *in, uint8_t *out, size_t n)
{
    uint8_t cb[16], ks[16];
    uint32_t c = elpis_get32(ctr + 12);

    memcpy(cb, ctr, 12);
    while (n >= 16) {
        __m128i k;

        elpis_put32(cb + 12, c++);
        k = encrypt_block(rk, _mm_loadu_si128((const __m128i *)(const void *)cb));
        _mm_storeu_si128((__m128i *)(void *)out,
            _mm_xor_si128(k, _mm_loadu_si128((const __m128i *)(const void *)in)));
        in  += 16;
        out += 16;
        n   -= 16;
    }
    if (n > 0) {
        size_t i;

        elpis_put32(cb + 12, c);
        elpis_aes_ni_encrypt(rk, cb, ks);
        for (i = 0; i < n; i++)
            out[i] = (uint8_t)(in[i] ^ ks[i]);
        elpis_wipe(ks, sizeof ks);
    }
}

/* a * b in GF(2^128), operands and result byte-reversed. */
static __m128i gfmul(__m128i a, __m128i b)
{
    __m128i t2, t3, t4, t5, t6, t7, t8, t9;

    t3 = _mm_clmulepi64_si128(a, b, 0x00);
    t4 = _mm_clmulepi64_si128(a, b, 0x10);
    t5 = _mm_clmulepi64_si128(a, b, 0x01);
    t6 = _mm_clmulepi64_si128(a, b, 0x11);

    t4 = _mm_xor_si128(t4, t5);
    t5 = _mm_slli_si128(t4, 8);
    t4 = _mm_srli_si128(t4, 8);
    t3 = _mm_xor_si128(t3, t5);
    t6 = _mm_xor_si128(t6, t4);

    /* The 256-bit product, shifted left one bit for the reflected order. */
    t7 = _mm_srli_epi32(t3, 31);
    t8 = _mm_srli_epi32(t6, 31);
    t3 = _mm_slli_epi32(t3, 1);
    t6 = _mm_slli_epi32(t6, 1);
    t9 = _mm_srli_si128(t7, 12);
    t8 = _mm_slli_si128(t8, 4);
    t7 = _mm_slli_si128(t7, 4);
    t3 = _mm_or_si128(t3, t7);
    t6 = _mm_or_si128(t6, t8);
    t6 = _mm_or_si128(t6, t9);

    /* Reduce modulo x^128 + x^7 + x^2 + x + 1. */
    t7 = _mm_slli_epi32(t3, 31);
    t8 = _mm_slli_epi32(t3, 30);
    t9 = _mm_slli_epi32(t3, 25);
    t7 = _mm_xor_si128(t7, t8);
    t7 = _mm_xor_si128(t7, t9);
    t8 = _mm_srli_si128(t7, 4);
    t7 = _mm_slli_si128(t7, 12);
    t3 = _mm_xor_si128(t3, t7);

    t2 = _mm_srli_epi32(t3, 1);
    t4 = _mm_srli_epi32(t3, 2);
    t5 = _mm_srli_epi32(t3, 7);
    t2 = _mm_xor_si128(t2, t4);
    t2 = _mm_xor_si128(t2, t5);
    t2 = _mm_xor_si128(t2, t8);
    t3 = _mm_xor_si128(t3, t2);
    return _mm_xor_si128(t6, t3);
}

void elpis_ghash_ni(const uint8_t h[16], uint8_t y[16],
                    const uint8_t *data, size_t n)
{
    const __m128i rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7,
                                     8, 9, 10, 11, 12, 13, 14, 15);
    __m128i hh = _mm_shuffle_epi8(
        _mm_loadu_si128((const __m128i *)(const void *)h), rev);
    __m128i yy = _mm_shuffle_epi8(
        _mm_loadu_si128((const __m128i *)(const void *)y), rev);

    while (n > 0) {
        uint8_t blk[16];
        __m128i x;

        if (n >= 16) {
            x = _mm_loadu_si128((const __m128i *)(const void *)data);
            data += 16;
            n    -= 16;
        } else {
            memset(blk, 0, sizeof blk);
            memcpy(blk, data, n);
            x = _mm_loadu_si128((const __m128i *)(const void *)blk);
            n = 0;
        }
        yy = gfmul(_mm_xor_si128(yy, _mm_shuffle_epi8(x, rev)), hh);
    }
    _mm_storeu_si128((__m128i *)(void *)y, _mm_shuffle_epi8(yy, rev));
}
