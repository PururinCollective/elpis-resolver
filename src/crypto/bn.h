/*
 * bn.h -- fixed-width big integers for RSA and ECDSA verification.
 *
 * 32-bit limbs with 64-bit products: no compiler extensions, no assembly,
 * identical results on every target.  Only what verification needs is here.
 * These operate exclusively on public values (signatures, public keys), so
 * they are not written to be constant time and must not be reused for
 * anything secret.
 */
#ifndef ELPIS_BN_H
#define ELPIS_BN_H

#include "elpis/common.h"

/*
 * 4608 bits.  RSA-4096 needs 128 limbs for the modulus; Montgomery
 * multiplication needs two more for the running total, and the rest is slack.
 * DNSSEC zones signed with RSA-4096 keys are common at the TLD level, so this
 * headroom is not theoretical.
 */
#define BN_MAX_LIMBS 144

typedef struct {
    unsigned n;                    /* significant limbs, least first */
    uint32_t d[BN_MAX_LIMBS];
} bn_t;

void bn_zero(bn_t *a);
void bn_set_u32(bn_t *a, uint32_t v);
void bn_copy(bn_t *r, const bn_t *a);
void bn_trim(bn_t *a);
int  bn_is_zero(const bn_t *a);
int  bn_cmp(const bn_t *a, const bn_t *b);
unsigned bn_bits(const bn_t *a);
int  bn_bit(const bn_t *a, unsigned i);

int  bn_from_bytes(bn_t *a, const uint8_t *p, size_t n);
int  bn_to_bytes(const bn_t *a, uint8_t *p, size_t n);

/* r = a + b, r = a - b (a >= b required), r = a * b */
void bn_add(bn_t *r, const bn_t *a, const bn_t *b);
void bn_sub(bn_t *r, const bn_t *a, const bn_t *b);
void bn_mul(bn_t *r, const bn_t *a, const bn_t *b);

/* r = a mod m, by shift-and-subtract. */
void bn_mod(bn_t *r, const bn_t *a, const bn_t *m);

/* Montgomery arithmetic modulo an odd m. */
typedef struct {
    bn_t     m;
    bn_t     rr;       /* R^2 mod m, R = 2^(32 * m.n)      */
    uint32_t m0inv;    /* -m^-1 mod 2^32                    */
    unsigned k;        /* limb count of m                   */
} mont_t;

int  mont_init(mont_t *c, const bn_t *m);
void mont_mul(bn_t *r, const bn_t *a, const bn_t *b, const mont_t *c);
void mont_to(bn_t *r, const bn_t *a, const mont_t *c);     /* a -> aR   */
void mont_from(bn_t *r, const bn_t *a, const mont_t *c);   /* aR -> a   */

/* r = a^e mod m, using Montgomery form internally. */
void bn_modexp(bn_t *r, const bn_t *a, const bn_t *e, const mont_t *c);
/* r = a^-1 mod m for prime m, via Fermat's little theorem. */
void bn_modinv_prime(bn_t *r, const bn_t *a, const mont_t *c);

/* Modular helpers used by the EC code; all operands must be < m. */
void bn_addmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);
void bn_submod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m);

#endif /* ELPIS_BN_H */
