/*
 * simd_sse2.c -- SSE2 kernels.  Compiled with -msse2; selected at runtime.
 *
 * SSE2 is architecturally guaranteed on x86-64, so this is the floor for
 * every 64-bit x86 host.  The 32-bit build falls back to the scalar kernels
 * when CPUID says SSE2 is absent.
 */
#include "simd_internal.h"

#if defined(ELPIS_ARCH_X86)
#include <emmintrin.h>

/* Same transform as elpis_sse2_lower16(), duplicated so this translation
 * unit compiles even when the header baseline lacks -msse2. */
static inline __m128i lower16(__m128i v)
{
    __m128i ge = _mm_cmpgt_epi8(v, _mm_set1_epi8(0x40));
    __m128i le = _mm_cmplt_epi8(v, _mm_set1_epi8(0x5B));
    __m128i m  = _mm_and_si128(_mm_and_si128(ge, le), _mm_set1_epi8(0x20));
    return _mm_or_si128(v, m);
}

void elpis_sse2_lower(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i = 0;
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
}

int elpis_sse2_eq_ci(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m128i a0 = lower16(_mm_loadu_si128((const __m128i *)(const void *)(a + i)));
        __m128i b0 = lower16(_mm_loadu_si128((const __m128i *)(const void *)(b + i)));
        __m128i a1 = lower16(_mm_loadu_si128((const __m128i *)(const void *)(a + i + 16)));
        __m128i b1 = lower16(_mm_loadu_si128((const __m128i *)(const void *)(b + i + 16)));
        __m128i d  = _mm_or_si128(_mm_xor_si128(a0, b0), _mm_xor_si128(a1, b1));
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(d, _mm_setzero_si128())) != 0xFFFF)
            return 0;
    }
    for (; i + 16 <= n; i += 16) {
        __m128i va = lower16(_mm_loadu_si128((const __m128i *)(const void *)(a + i)));
        __m128i vb = lower16(_mm_loadu_si128((const __m128i *)(const void *)(b + i)));
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)) != 0xFFFF)
            return 0;
    }
    for (; i + 8 <= n; i += 8) {
        if (elpis_swar_lower64(elpis_load64(a + i)) !=
            elpis_swar_lower64(elpis_load64(b + i)))
            return 0;
    }
    for (; i < n; i++) {
        uint8_t ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (uint8_t)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (uint8_t)(cb + 32);
        if (ca != cb)
            return 0;
    }
    return 1;
}

uint64_t elpis_sse2_hash_ci(const uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t h = elpis_hash_seed(seed);
    uint64_t a, b;
    size_t i = 0;
    uint8_t tmp[16];

    /* The mixing chain is serial; SSE2 earns its keep on the case fold. */
    while (i + 16 <= n) {
        __m128i v = lower16(_mm_loadu_si128((const __m128i *)(const void *)(p + i)));
        _mm_storeu_si128((__m128i *)(void *)tmp, v);
        h = elpis_hash_step(h, elpis_load64(tmp), elpis_load64(tmp + 8));
        i += 16;
    }
    elpis_hash_tail(p + i, n - i, &a, &b);
    return elpis_hash_finish(h, a, b, n);
}

#endif /* ELPIS_ARCH_X86 */
