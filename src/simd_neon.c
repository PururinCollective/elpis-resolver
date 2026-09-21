/*
 * simd_neon.c -- AArch64 / ARMv7 NEON kernels.
 */
#include "simd_internal.h"

#if defined(ELPIS_ARCH_ARM) && \
    (defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__))
#include <arm_neon.h>

static inline uint8x16_t lower16(uint8x16_t v)
{
    uint8x16_t ge = vcgeq_u8(v, vdupq_n_u8(0x41));
    uint8x16_t le = vcleq_u8(v, vdupq_n_u8(0x5A));
    uint8x16_t m  = vandq_u8(vandq_u8(ge, le), vdupq_n_u8(0x20));
    return vorrq_u8(v, m);
}

void elpis_neon_lower(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i = 0;
    for (; i + 16 <= n; i += 16)
        vst1q_u8(dst + i, lower16(vld1q_u8(src + i)));
    for (; i + 8 <= n; i += 8) {
        uint64_t w = elpis_swar_lower64(elpis_load64(src + i));
        memcpy(dst + i, &w, 8);
    }
    for (; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
}

/* vmaxvq_u8 is AArch64 only; ARMv7 reduces pairwise. */
static inline unsigned any_nonzero(uint8x16_t d)
{
#if defined(__aarch64__)
    return vmaxvq_u8(d) != 0;
#else
    uint8x8_t r = vorr_u8(vget_low_u8(d), vget_high_u8(d));
    uint32x2_t w = vreinterpret_u32_u8(r);
    return (vget_lane_u32(w, 0) | vget_lane_u32(w, 1)) != 0;
#endif
}

int elpis_neon_eq_ci(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        uint8x16_t d = veorq_u8(lower16(vld1q_u8(a + i)), lower16(vld1q_u8(b + i)));
        if (any_nonzero(d))
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

uint64_t elpis_neon_hash_ci(const uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t h = elpis_hash_seed(seed);
    uint64_t a, b;
    size_t i = 0;
    uint8_t tmp[16];

    while (i + 16 <= n) {
        vst1q_u8(tmp, lower16(vld1q_u8(p + i)));
        h = elpis_hash_step(h, elpis_load64(tmp), elpis_load64(tmp + 8));
        i += 16;
    }
    elpis_hash_tail(p + i, n - i, &a, &b);
    return elpis_hash_finish(h, a, b, n);
}

#endif /* ELPIS_ARCH_ARM && NEON */
