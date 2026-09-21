/*
 * elpis/common.h -- base types, portability shims, small helpers.
 *
 * Everything here is strict C99.  Compiler/OS specific behaviour is confined
 * to the ELPIS_* macros below so the rest of the tree stays portable.
 */
#ifndef ELPIS_COMMON_H
#define ELPIS_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#ifndef ELPIS_VERSION
#define ELPIS_VERSION "0.0.0"
#endif
#ifndef ELPIS_SYSCONFDIR
#define ELPIS_SYSCONFDIR "/etc"
#endif

/* ------------------------------------------------------------------ */
/* Compiler feature probes                                             */
/* ------------------------------------------------------------------ */
#if defined(__GNUC__) || defined(__clang__)
#  define ELPIS_LIKELY(x)    __builtin_expect(!!(x), 1)
#  define ELPIS_UNLIKELY(x)  __builtin_expect(!!(x), 0)
#  define ELPIS_INLINE       static inline __attribute__((always_inline))
#  define ELPIS_NOINLINE     __attribute__((noinline))
#  define ELPIS_PURE         __attribute__((pure))
#  define ELPIS_CONST        __attribute__((const))
#  define ELPIS_UNUSED       __attribute__((unused))
#  define ELPIS_PRINTF(a,b)  __attribute__((format(printf, a, b)))
#  define ELPIS_PREFETCH(p)  __builtin_prefetch((p), 0, 3)
#  define ELPIS_PREFETCHW(p) __builtin_prefetch((p), 1, 3)
#  define ELPIS_ALIGN(n)     __attribute__((aligned(n)))
#  define ELPIS_TLS          __thread
#else
#  define ELPIS_LIKELY(x)    (x)
#  define ELPIS_UNLIKELY(x)  (x)
#  define ELPIS_INLINE       static inline
#  define ELPIS_NOINLINE
#  define ELPIS_PURE
#  define ELPIS_CONST
#  define ELPIS_UNUSED
#  define ELPIS_PRINTF(a,b)
#  define ELPIS_PREFETCH(p)  ((void)0)
#  define ELPIS_PREFETCHW(p) ((void)0)
#  define ELPIS_ALIGN(n)
#  define ELPIS_TLS
#endif

/* C99 has no _Static_assert; emulate with a negative-width bitfield. */
#define ELPIS_CTASSERT3(e, l) \
    typedef char elpis_ctassert_##l[(e) ? 1 : -1] ELPIS_UNUSED
#define ELPIS_CTASSERT2(e, l) ELPIS_CTASSERT3(e, l)
#define ELPIS_CTASSERT(e)     ELPIS_CTASSERT2(e, __LINE__)

#define ELPIS_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define ELPIS_MIN(a, b)    ((a) < (b) ? (a) : (b))
#define ELPIS_MAX(a, b)    ((a) > (b) ? (a) : (b))
#define ELPIS_CLAMP(v, lo, hi) ELPIS_MIN(ELPIS_MAX((v), (lo)), (hi))

/* container_of, without relying on GNU typeof */
#define ELPIS_CONTAINER_OF(ptr, type, member) \
    ((type *)(void *)((char *)(ptr) - offsetof(type, member)))

/* ------------------------------------------------------------------ */
/* Endian-safe unaligned access                                        */
/* ------------------------------------------------------------------ */
ELPIS_INLINE uint16_t elpis_get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
ELPIS_INLINE uint32_t elpis_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
ELPIS_INLINE uint64_t elpis_get64(const uint8_t *p)
{
    return ((uint64_t)elpis_get32(p) << 32) | (uint64_t)elpis_get32(p + 4);
}
ELPIS_INLINE void elpis_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
ELPIS_INLINE void elpis_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
ELPIS_INLINE void elpis_put64(uint8_t *p, uint64_t v)
{
    elpis_put32(p, (uint32_t)(v >> 32));
    elpis_put32(p + 4, (uint32_t)v);
}

/* Load native 64-bit word from possibly-unaligned memory. */
ELPIS_INLINE uint64_t elpis_load64(const void *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof v);
    return v;
}
ELPIS_INLINE uint32_t elpis_load32(const void *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

ELPIS_INLINE uint32_t elpis_rotl32(uint32_t x, unsigned n)
{
    return (uint32_t)((x << n) | (x >> ((32 - n) & 31)));
}
ELPIS_INLINE uint32_t elpis_rotr32(uint32_t x, unsigned n)
{
    return (uint32_t)((x >> n) | (x << ((32 - n) & 31)));
}
ELPIS_INLINE uint64_t elpis_rotl64(uint64_t x, unsigned n)
{
    return (x << n) | (x >> ((64 - n) & 63));
}
ELPIS_INLINE uint64_t elpis_rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << ((64 - n) & 63));
}

/* Branch-free constant-time byte compare; returns 0 on equal. */
int elpis_ct_memcmp(const void *a, const void *b, size_t n);

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */
typedef enum {
    ELPIS_OK          =  0,
    ELPIS_ERR         = -1,
    ELPIS_ENOMEM      = -2,
    ELPIS_EFORMAT     = -3,   /* malformed wire data                    */
    ELPIS_ETRUNC      = -4,   /* buffer too small / message truncated   */
    ELPIS_ETIMEOUT    = -5,
    ELPIS_EAGAIN      = -6,
    ELPIS_ENOTFOUND   = -7,
    ELPIS_ELOOP       = -8,
    ELPIS_EREFUSED    = -9,
    ELPIS_EBOGUS      = -10   /* DNSSEC validation failure              */
} elpis_rc_t;


#endif /* ELPIS_COMMON_H */
