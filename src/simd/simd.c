/*
 * simd.c -- CPU feature detection, kernel dispatch, scalar reference kernels.
 */
#include "elpis/simd.h"
#include "elpis/log.h"

#if defined(ELPIS_ARCH_X86)
#  if defined(__GNUC__) || defined(__clang__)
#    include <cpuid.h>
#  endif
#endif
#if defined(ELPIS_ARCH_ARM) && defined(__linux__)
#  include <sys/auxv.h>
#  ifndef HWCAP_ASIMD
#    define HWCAP_ASIMD (1 << 1)
#  endif
#  ifndef HWCAP_CRC32
#    define HWCAP_CRC32 (1 << 7)
#  endif
#endif

static elpis_cpu_t g_cpu;
static const char *g_backend = "scalar";
static int g_inited;

/* ------------------------------------------------------------------ */
/* Scalar reference kernels                                            */
/* ------------------------------------------------------------------ */

void elpis_scalar_lower(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t w = elpis_swar_lower64(elpis_load64(src + i));
        memcpy(dst + i, &w, 8);
    }
    for (; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
}

int elpis_scalar_eq_ci(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i = 0;
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

/*
 * Case-folding 64-bit hash.  Every backend must produce bit-identical output:
 * the cache stores the hash alongside the key, and a mismatch between the
 * startup-selected kernel and the reference would silently split the table.
 * tests/test_main.c enforces this.
 */
#include "simd_internal.h"

/* Load the 0..15 byte tail, case-folded, into two words. */
void elpis_hash_tail(const uint8_t *p, size_t n, uint64_t *a, uint64_t *b)
{
    uint8_t t[16];
    size_t i;
    memset(t, 0, sizeof t);
    for (i = 0; i < n; i++) {
        uint8_t c = p[i];
        t[i] = (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
    *a = elpis_load64(t);
    *b = elpis_load64(t + 8);
}

uint64_t elpis_hash_finish(uint64_t h, uint64_t a, uint64_t b, size_t n)
{
    h = elpis_hash_step(h, a, b);
    return elpis_mix64(h ^ ((uint64_t)n * HK3));
}

uint64_t elpis_scalar_hash_ci(const uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t h = elpis_hash_seed(seed);
    uint64_t a, b;
    size_t i = 0;

    while (i + 16 <= n) {
        a = elpis_swar_lower64(elpis_load64(p + i));
        b = elpis_swar_lower64(elpis_load64(p + i + 8));
        h = elpis_hash_step(h, a, b);
        i += 16;
    }
    elpis_hash_tail(p + i, n - i, &a, &b);
    return elpis_hash_finish(h, a, b, n);
}

/* ------------------------------------------------------------------ */
/* Dispatch table                                                      */
/* ------------------------------------------------------------------ */
void     (*elpis_simd_lower)(uint8_t *, const uint8_t *, size_t)       = elpis_scalar_lower;
int      (*elpis_simd_eq_ci)(const uint8_t *, const uint8_t *, size_t) = elpis_scalar_eq_ci;
uint64_t (*elpis_simd_hash_ci)(const uint8_t *, size_t, uint64_t)      = elpis_scalar_hash_ci;

/* ------------------------------------------------------------------ */
/* Feature detection                                                   */
/* ------------------------------------------------------------------ */

#if defined(ELPIS_ARCH_X86)
static int x86_cpuid(unsigned leaf, unsigned sub, unsigned r[4])
{
#if defined(__GNUC__) || defined(__clang__)
    return __get_cpuid_count(leaf, sub, &r[0], &r[1], &r[2], &r[3]) ? 0 : -1;
#else
    (void)leaf; (void)sub; (void)r;
    return -1;
#endif
}

/*
 * AVX state must be enabled by the OS (XCR0 bits 1 and 2) before YMM
 * registers may be used, otherwise a VEX instruction faults.
 */
static int x86_ymm_enabled(void)
{
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
    unsigned eax, edx;
    __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return (eax & 0x6u) == 0x6u;
#else
    return 0;
#endif
}

static void detect_x86(void)
{
    unsigned r[4];

    if (x86_cpuid(1, 0, r) == 0) {
        g_cpu.sse2  = (r[3] >> 26) & 1u;
        g_cpu.ssse3 = (r[2] >> 9)  & 1u;
        g_cpu.sse41 = (r[2] >> 19) & 1u;
        if (((r[2] >> 27) & 1u) && ((r[2] >> 28) & 1u) && x86_ymm_enabled()) {
            if (x86_cpuid(7, 0, r) == 0) {
                g_cpu.avx2     = (r[1] >> 5)  & 1u;
                g_cpu.bmi2     = (r[1] >> 8)  & 1u;
                g_cpu.avx512f  = (r[1] >> 16) & 1u;
                g_cpu.avx512bw = (r[1] >> 30) & 1u;
            }
        }
    }
#if defined(__x86_64__)
    g_cpu.sse2 = 1;   /* architecturally guaranteed */
#endif
}
#endif /* ELPIS_ARCH_X86 */

void elpis_simd_init(void)
{
    if (g_inited)
        return;
    g_inited = 1;
    memset(&g_cpu, 0, sizeof g_cpu);

#if defined(ELPIS_ARCH_X86)
    detect_x86();
    if (g_cpu.avx2) {
        elpis_simd_lower   = elpis_avx2_lower;
        elpis_simd_eq_ci   = elpis_avx2_eq_ci;
        elpis_simd_hash_ci = elpis_avx2_hash_ci;
        g_backend = "avx2";
    } else if (g_cpu.sse2) {
        elpis_simd_lower   = elpis_sse2_lower;
        elpis_simd_eq_ci   = elpis_sse2_eq_ci;
        elpis_simd_hash_ci = elpis_sse2_hash_ci;
        g_backend = "sse2";
    }
#elif defined(ELPIS_ARCH_ARM)
#  if defined(__aarch64__)
    g_cpu.neon = 1;               /* mandatory on AArch64 */
#  elif defined(__linux__)
    g_cpu.neon = (getauxval(AT_HWCAP) & HWCAP_ASIMD) ? 1u : 0u;
#  endif
#  if defined(__linux__)
    g_cpu.crc32 = (getauxval(AT_HWCAP) & HWCAP_CRC32) ? 1u : 0u;
#  endif
    if (g_cpu.neon) {
        elpis_simd_lower   = elpis_neon_lower;
        elpis_simd_eq_ci   = elpis_neon_eq_ci;
        elpis_simd_hash_ci = elpis_neon_hash_ci;
        g_backend = "neon";
    }
#endif
}

const elpis_cpu_t *elpis_cpu(void)
{
    if (!g_inited)
        elpis_simd_init();
    return &g_cpu;
}

const char *elpis_simd_backend(void)
{
    if (!g_inited)
        elpis_simd_init();
    return g_backend;
}
