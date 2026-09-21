/*
 * ec.h -- short Weierstrass curves over prime fields (a = -3), enough for
 * ECDSA verification on P-256 and P-384.
 *
 * Field elements are held in Montgomery form throughout; points are Jacobian.
 * Everything operates on public data, so the scalar ladder is a plain
 * double-and-add with Shamir's trick rather than a constant-time ladder.
 */
#ifndef ELPIS_EC_H
#define ELPIS_EC_H

#include "bn.h"

typedef struct {
    bn_t X, Y, Z;     /* Jacobian, Montgomery form: x = X/Z^2, y = Y/Z^3 */
    int  inf;
} ecp_t;

typedef struct {
    mont_t   fp;        /* field modulus p                    */
    mont_t   fn;        /* group order n                      */
    bn_t     b;         /* curve b, Montgomery form           */
    ecp_t    G;         /* generator, Montgomery form         */
    unsigned bytes;     /* field element width in octets      */
    unsigned nbits;     /* bit length of n                    */
    int      ready;
} ec_group_t;

const ec_group_t *ec_p256(void);
const ec_group_t *ec_p384(void);

void ec_set_inf(ecp_t *p);
void ec_dbl(ecp_t *r, const ecp_t *p, const ec_group_t *g);
void ec_add(ecp_t *r, const ecp_t *p, const ecp_t *q, const ec_group_t *g);
/* r = k1*G + k2*Q, both scalars reduced mod n by the caller. */
void ec_mul2(ecp_t *r, const bn_t *k1, const ecp_t *q, const bn_t *k2,
             const ec_group_t *g);
/* Affine x coordinate, in normal (non-Montgomery) form. */
int  ec_affine_x(bn_t *x, const ecp_t *p, const ec_group_t *g);
/* Load an uncompressed point (no 0x04 prefix) and check it is on the curve. */
int  ec_point_load(ecp_t *p, const uint8_t *buf, size_t len, const ec_group_t *g);

#endif /* ELPIS_EC_H */
