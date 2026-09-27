/*
 * simd_avx2.c -- AVX2 kernels.  Compiled with -mavx2 -mbmi -mbmi2 and only
 * entered after CPUID plus XGETBV confirm the OS saves YMM state.
 *
 * Nothing else in the tree may be compiled with -mavx2, or the binary would
 * fault on older CPUs before reaching the dispatch code.
 */
#include "simd_internal.h"

#if defined(ELPIS_ARCH_X86)
#include <immintrin.h>

static inline __m256i lower32(__m256i v)
{
    __m256i ge = _mm256_cmpgt_epi8(v, _mm256_set1_epi8(0x40));
    __m256i le = _mm256_cmpgt_epi8(_mm256_set1_epi8(0x5B), v);
    __m256i m  = _mm256_and_si256(_mm256_and_si256(ge, le), _mm256_set1_epi8(0x20));
    return _mm256_or_si256(v, m);
}

static inline __m128i lower16(__m128i v)
{
    __m128i ge = _mm_cmpgt_epi8(v, _mm_set1_epi8(0x40));
    __m128i le = _mm_cmplt_epi8(v, _mm_set1_epi8(0x5B));
    __m128i m  = _mm_and_si128(_mm_and_si128(ge, le), _mm_set1_epi8(0x20));
    return _mm_or_si128(v, m);
}

void elpis_avx2_lower(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(const void *)(src + i));
        _mm256_storeu_si256((__m256i *)(void *)(dst + i), lower32(v));
    }
    for (; i + 16 <= n; i += 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)(const void *)(src + i));
        _mm_storeu_si128((__m128i *)(void *)(dst + i), lower16(v));
    }
    for (; i + 8 <= n; i += 8) {
        uint64_t w = elpis_swar_lower64(elpis_load64(src + i));
        memcpy(dst + i, &w, 8);
    }
    for (; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
    _mm256_zeroupper();
}

int elpis_avx2_eq_ci(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i = 0;
    int eq = 1;

    for (; i + 32 <= n; i += 32) {
        __m256i va = lower32(_mm256_loadu_si256((const __m256i *)(const void *)(a + i)));
        __m256i vb = lower32(_mm256_loadu_si256((const __m256i *)(const void *)(b + i)));
        if ((uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(va, vb)) != 0xFFFFFFFFu) {
            eq = 0;
            goto out;
        }
    }
    for (; i + 16 <= n; i += 16) {
        __m128i va = lower16(_mm_loadu_si128((const __m128i *)(const void *)(a + i)));
        __m128i vb = lower16(_mm_loadu_si128((const __m128i *)(const void *)(b + i)));
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)) != 0xFFFF) {
            eq = 0;
            goto out;
        }
    }
    for (; i + 8 <= n; i += 8) {
        if (elpis_swar_lower64(elpis_load64(a + i)) !=
            elpis_swar_lower64(elpis_load64(b + i))) {
            eq = 0;
            goto out;
        }
    }
    for (; i < n; i++) {
        uint8_t ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (uint8_t)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (uint8_t)(cb + 32);
        if (ca != cb) {
            eq = 0;
            goto out;
        }
    }
out:
    _mm256_zeroupper();
    return eq;
}

uint64_t elpis_avx2_hash_ci(const uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t h = elpis_hash_seed(seed);
    uint64_t a, b;
    size_t i = 0;
    ELPIS_ALIGN(32) uint8_t tmp[32];

    /* Fold 32 bytes per load, then feed the serial mixer in 16-byte steps so
     * the digest matches the scalar kernel exactly. */
    while (i + 32 <= n) {
        __m256i v = lower32(_mm256_loadu_si256((const __m256i *)(const void *)(p + i)));
        _mm256_store_si256((__m256i *)(void *)tmp, v);
        h = elpis_hash_step(h, elpis_load64(tmp),      elpis_load64(tmp + 8));
        h = elpis_hash_step(h, elpis_load64(tmp + 16), elpis_load64(tmp + 24));
        i += 32;
    }
    if (i + 16 <= n) {
        __m128i v = lower16(_mm_loadu_si128((const __m128i *)(const void *)(p + i)));
        _mm_store_si128((__m128i *)(void *)tmp, v);
        h = elpis_hash_step(h, elpis_load64(tmp), elpis_load64(tmp + 8));
        i += 16;
    }
    elpis_hash_tail(p + i, n - i, &a, &b);
    _mm256_zeroupper();
    return elpis_hash_finish(h, a, b, n);
}

#endif /* ELPIS_ARCH_X86 */
