/*
 * simd_internal.h -- shared pieces of the hash so every backend stays
 * bit-identical.  Not installed; internal to src/.
 */
#ifndef ELPIS_SIMD_INTERNAL_H
#define ELPIS_SIMD_INTERNAL_H

#include "elpis/simd.h"

#define HK0 0xa0761d6478bd642full
#define HK1 0xe7037ed1a0b428dbull
#define HK2 0x8ebc6af09c88c6e3ull
#define HK3 0x589965cc75374cc3ull

/* Case-folded 0..15 byte tail, zero padded, split into two words. */
void     elpis_hash_tail(const uint8_t *p, size_t n, uint64_t *a, uint64_t *b);
uint64_t elpis_hash_finish(uint64_t h, uint64_t a, uint64_t b, size_t n);

ELPIS_INLINE uint64_t elpis_hash_seed(uint64_t seed)
{
    return seed ^ elpis_mul_fold(seed ^ HK0, HK1);
}
ELPIS_INLINE uint64_t elpis_hash_step(uint64_t h, uint64_t a, uint64_t b)
{
    return elpis_mul_fold(a ^ h ^ HK1, b ^ HK2);
}

#endif /* ELPIS_SIMD_INTERNAL_H */
