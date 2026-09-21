/*
 * elpis/simd.h -- vectorised primitives with runtime dispatch.
 *
 * Two tiers:
 *
 *   1. Inline kernels (below) for the very hot, very short operations:
 *      DNS-name lowercasing, case-insensitive compare and the 16-slot control
 *      word probe used by the cache.  These use the architecture baseline
 *      (SSE2 on x86-64, NEON on AArch64, SWAR elsewhere), so there is no
 *      indirect call in the packet path.
 *
 *   2. Dispatched kernels (function pointers) for bulk work -- zone parsing,
 *      cache scrubbing, large rdata compares -- where an AVX2/AVX-512 path is
 *      worth the call overhead.  Selected once at startup from CPUID.
 *
 * The scalar fallbacks are always compiled and are the reference behaviour;
 * tests/test_main.c cross-checks every vector path against them.
 */
#ifndef ELPIS_SIMD_H
#define ELPIS_SIMD_H

#include "elpis/common.h"

#if defined(ELPIS_ARCH_X86) && (defined(__SSE2__) || defined(_M_X64) || defined(__x86_64__))
#  include <emmintrin.h>
#  define ELPIS_HAVE_SSE2 1
#endif

#if defined(ELPIS_ARCH_ARM) && (defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__))
#  include <arm_neon.h>
#  define ELPIS_HAVE_NEON 1
#endif

/* ------------------------------------------------------------------ */
/* CPU feature discovery                                               */
/* ------------------------------------------------------------------ */
typedef struct {
    unsigned sse2   : 1;
    unsigned ssse3  : 1;
    unsigned sse41  : 1;
    unsigned avx2   : 1;
    unsigned bmi2   : 1;
    unsigned avx512f: 1;
    unsigned avx512bw:1;
    unsigned neon   : 1;
    unsigned crc32  : 1;
} elpis_cpu_t;

void               elpis_simd_init(void);
const elpis_cpu_t *elpis_cpu(void);
const char        *elpis_simd_backend(void);   /* "avx2", "sse2", "neon", ... */

/* ------------------------------------------------------------------ */
/* Dispatched bulk kernels                                             */
/* ------------------------------------------------------------------ */
/* Lowercase `n` ASCII bytes from src into dst (may alias exactly).     */
extern void     (*elpis_simd_lower)(uint8_t *dst, const uint8_t *src, size_t n);
/* Case-insensitive compare; returns 1 on equal.                        */
extern int      (*elpis_simd_eq_ci)(const uint8_t *a, const uint8_t *b, size_t n);
/* 64-bit hash of a case-folded byte range (lowercases on the fly).     */
extern uint64_t (*elpis_simd_hash_ci)(const uint8_t *p, size_t n, uint64_t seed);

/* Reference implementations; exported for the self-test. */
void     elpis_scalar_lower(uint8_t *dst, const uint8_t *src, size_t n);
int      elpis_scalar_eq_ci(const uint8_t *a, const uint8_t *b, size_t n);
uint64_t elpis_scalar_hash_ci(const uint8_t *p, size_t n, uint64_t seed);

/* Architecture kernels (defined only when the arch is selected). */
#if defined(ELPIS_ARCH_X86)
void     elpis_sse2_lower(uint8_t *dst, const uint8_t *src, size_t n);
int      elpis_sse2_eq_ci(const uint8_t *a, const uint8_t *b, size_t n);
uint64_t elpis_sse2_hash_ci(const uint8_t *p, size_t n, uint64_t seed);
void     elpis_avx2_lower(uint8_t *dst, const uint8_t *src, size_t n);
int      elpis_avx2_eq_ci(const uint8_t *a, const uint8_t *b, size_t n);
uint64_t elpis_avx2_hash_ci(const uint8_t *p, size_t n, uint64_t seed);
#endif
#if defined(ELPIS_ARCH_ARM)
void     elpis_neon_lower(uint8_t *dst, const uint8_t *src, size_t n);
int      elpis_neon_eq_ci(const uint8_t *a, const uint8_t *b, size_t n);
uint64_t elpis_neon_hash_ci(const uint8_t *p, size_t n, uint64_t seed);
#endif

/* ================================================================== */
/* Inline kernels                                                      */
/* ================================================================== */

#define ELPIS_SWAR_LO  0x7f7f7f7f7f7f7f7full
#define ELPIS_SWAR_HI  0x8080808080808080ull
#define ELPIS_SWAR_GEA 0x3f3f3f3f3f3f3f3full   /* 0x7f - 'A' + 1 == 0x3f */
#define ELPIS_SWAR_GTZ 0x2525252525252525ull   /* 0x7f - 'Z'      == 0x25 */

/*
 * Fold 'A'..'Z' to lowercase across all eight lanes of a word.
 * Bit 7 of each lane is cleared before the additions so carries cannot cross
 * a lane boundary; bytes >= 0x80 are excluded explicitly.
 */
ELPIS_INLINE uint64_t elpis_swar_lower64(uint64_t x)
{
    uint64_t lo = x & ELPIS_SWAR_LO;
    uint64_t hi = x & ELPIS_SWAR_HI;
    uint64_t ge = (lo + ELPIS_SWAR_GEA) & ELPIS_SWAR_HI;  /* byte >= 'A' */
    uint64_t gt = (lo + ELPIS_SWAR_GTZ) & ELPIS_SWAR_HI;  /* byte >  'Z' */
    uint64_t m  = ge & ~gt & ~hi;
    return x | (m >> 2);                                   /* 0x80 >> 2 == 0x20 */
}

#if defined(ELPIS_HAVE_SSE2)
ELPIS_INLINE __m128i elpis_sse2_lower16(__m128i v)
{
    /* Signed compares: bytes >= 0x80 are negative and fail the 'A' test. */
    __m128i ge = _mm_cmpgt_epi8(v, _mm_set1_epi8(0x40));   /* > '@'  */
    __m128i le = _mm_cmplt_epi8(v, _mm_set1_epi8(0x5B));   /* < '['  */
    __m128i m  = _mm_and_si128(_mm_and_si128(ge, le), _mm_set1_epi8(0x20));
    return _mm_or_si128(v, m);
}
#endif

#if defined(ELPIS_HAVE_NEON)
ELPIS_INLINE uint8x16_t elpis_neon_lower16(uint8x16_t v)
{
    uint8x16_t ge = vcgeq_u8(v, vdupq_n_u8(0x41));
    uint8x16_t le = vcleq_u8(v, vdupq_n_u8(0x5A));
    uint8x16_t m  = vandq_u8(vandq_u8(ge, le), vdupq_n_u8(0x20));
    return vorrq_u8(v, m);
}
#endif

/*
 * Lowercase up to 255 bytes -- the DNS name path.  Callers guarantee `dst`
 * has room for `n` rounded up to 16, which lets us skip the scalar tail.
 */
ELPIS_INLINE void elpis_lower_pad16(uint8_t *dst, const uint8_t *src, size_t n)
{
#if defined(ELPIS_HAVE_SSE2)
    size_t i;
    for (i = 0; i < n; i += 16)
        _mm_storeu_si128((__m128i *)(void *)(dst + i),
                         elpis_sse2_lower16(_mm_loadu_si128((const __m128i *)(const void *)(src + i))));
#elif defined(ELPIS_HAVE_NEON)
    size_t i;
    for (i = 0; i < n; i += 16)
        vst1q_u8(dst + i, elpis_neon_lower16(vld1q_u8(src + i)));
#else
    size_t i;
    for (i = 0; i + 8 <= n; i += 8) {
        uint64_t w = elpis_swar_lower64(elpis_load64(src + i));
        memcpy(dst + i, &w, 8);
    }
    for (; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
#endif
}

/* Exact-length case-insensitive compare, no padding assumptions. */
ELPIS_INLINE int elpis_eq_ci(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i = 0;
#if defined(ELPIS_HAVE_SSE2)
    for (; i + 16 <= n; i += 16) {
        __m128i va = elpis_sse2_lower16(_mm_loadu_si128((const __m128i *)(const void *)(a + i)));
        __m128i vb = elpis_sse2_lower16(_mm_loadu_si128((const __m128i *)(const void *)(b + i)));
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)) != 0xFFFF)
            return 0;
    }
#elif defined(ELPIS_HAVE_NEON)
    for (; i + 16 <= n; i += 16) {
        uint8x16_t va = elpis_neon_lower16(vld1q_u8(a + i));
        uint8x16_t vb = elpis_neon_lower16(vld1q_u8(b + i));
        uint8x16_t d  = veorq_u8(va, vb);
        if (vmaxvq_u8(d) != 0)
            return 0;
    }
#endif
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

/* ------------------------------------------------------------------ */
/* Cache control-word probing (16 slots per group)                     */
/* ------------------------------------------------------------------ */
#define ELPIS_GROUP 16

/* Returns a bitmask of slots in the group whose control byte equals `tag`. */
ELPIS_INLINE uint32_t elpis_group_match(const uint8_t *ctrl, uint8_t tag)
{
#if defined(ELPIS_HAVE_SSE2)
    __m128i c = _mm_loadu_si128((const __m128i *)(const void *)ctrl);
    __m128i t = _mm_set1_epi8((char)tag);
    return (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(c, t));
#elif defined(ELPIS_HAVE_NEON)
    /* NEON has no movemask; fold the 0xFF lanes into a 16-bit word. */
    static const uint8_t kbit[16] = { 1,2,4,8,16,32,64,128, 1,2,4,8,16,32,64,128 };
    uint8x16_t c = vld1q_u8(ctrl);
    uint8x16_t m = vceqq_u8(c, vdupq_n_u8(tag));
    uint8x16_t b = vandq_u8(m, vld1q_u8(kbit));
    return (uint32_t)vaddv_u8(vget_low_u8(b)) |
           ((uint32_t)vaddv_u8(vget_high_u8(b)) << 8);
#else
    uint32_t r = 0;
    int i;
    for (i = 0; i < ELPIS_GROUP; i++)
        r |= (uint32_t)(ctrl[i] == tag) << i;
    return r;
#endif
}

/* Bitmask of slots whose control byte has the high bit set (empty/deleted). */
ELPIS_INLINE uint32_t elpis_group_special(const uint8_t *ctrl)
{
#if defined(ELPIS_HAVE_SSE2)
    __m128i c = _mm_loadu_si128((const __m128i *)(const void *)ctrl);
    return (uint32_t)_mm_movemask_epi8(c);
#elif defined(ELPIS_HAVE_NEON)
    static const uint8_t kbit[16] = { 1,2,4,8,16,32,64,128, 1,2,4,8,16,32,64,128 };
    uint8x16_t c = vld1q_u8(ctrl);
    uint8x16_t m = vcgeq_u8(c, vdupq_n_u8(0x80));
    uint8x16_t b = vandq_u8(m, vld1q_u8(kbit));
    return (uint32_t)vaddv_u8(vget_low_u8(b)) |
           ((uint32_t)vaddv_u8(vget_high_u8(b)) << 8);
#else
    uint32_t r = 0;
    int i;
    for (i = 0; i < ELPIS_GROUP; i++)
        r |= (uint32_t)((ctrl[i] & 0x80u) != 0) << i;
    return r;
#endif
}

/* Index of the lowest set bit; the mask must be non-zero. */
ELPIS_INLINE unsigned elpis_ctz32(uint32_t m)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_ctz(m);
#else
    unsigned n = 0;
    while ((m & 1u) == 0u) { m >>= 1; n++; }
    return n;
#endif
}

ELPIS_INLINE unsigned elpis_popcount32(uint32_t m)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_popcount(m);
#else
    unsigned n = 0;
    while (m) { m &= m - 1u; n++; }
    return n;
#endif
}

/* ------------------------------------------------------------------ */
/* 64-bit mixing                                                       */
/* ------------------------------------------------------------------ */
ELPIS_INLINE uint64_t elpis_mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

/*
 * 64x64 -> 128 folded to 64; the core of the hash.  __int128 is a compiler
 * extension, so the pure-C99 path below is kept as the portable fallback.
 */
#if defined(__SIZEOF_INT128__) && (defined(__GNUC__) || defined(__clang__))
__extension__ typedef unsigned __int128 elpis_u128;
#define ELPIS_HAVE_U128 1
#endif

ELPIS_INLINE uint64_t elpis_mul_fold(uint64_t a, uint64_t b)
{
#if defined(ELPIS_HAVE_U128)
    elpis_u128 r = (elpis_u128)a * (elpis_u128)b;
    return (uint64_t)r ^ (uint64_t)(r >> 64);
#else
    uint64_t alo = a & 0xFFFFFFFFull, ahi = a >> 32;
    uint64_t blo = b & 0xFFFFFFFFull, bhi = b >> 32;
    uint64_t p0 = alo * blo, p1 = alo * bhi, p2 = ahi * blo, p3 = ahi * bhi;
    uint64_t mid = (p0 >> 32) + (p1 & 0xFFFFFFFFull) + (p2 & 0xFFFFFFFFull);
    uint64_t lo  = (p0 & 0xFFFFFFFFull) | (mid << 32);
    uint64_t hi  = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return lo ^ hi;
#endif
}

#endif /* ELPIS_SIMD_H */
