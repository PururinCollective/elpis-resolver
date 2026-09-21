/*
 * ecdsa.c -- ECDSA verification for DNSSEC algorithms 13 and 14 (RFC 6605).
 */
#include "elpis/crypto.h"
#include "ec.h"

/*
 * Reduce the message hash to a field-order integer, taking the leftmost
 * bitlen(n) bits (FIPS 186-4 section 6.4).  For P-256/SHA-256 and
 * P-384/SHA-384 the hash and the order are the same width, so this is just a
 * range reduction, but the general rule costs nothing to implement.
 */
static int hash_to_bn(bn_t *e, const uint8_t *hash, size_t hashlen,
                      const ec_group_t *g)
{
    size_t use = hashlen;
    unsigned excess;

    if (use * 8u > g->nbits + 512u)
        return ELPIS_ERR;
    if (use > (size_t)BN_MAX_LIMBS * 4u)
        return ELPIS_ERR;
    if (bn_from_bytes(e, hash, use) != ELPIS_OK)
        return ELPIS_ERR;

    if (hashlen * 8u > g->nbits) {
        excess = (unsigned)(hashlen * 8u - g->nbits);
        while (excess-- > 0) {
            /* Right shift by one: drop the low bit across all limbs. */
            unsigned i;
            for (i = 0; i + 1u < e->n; i++)
                e->d[i] = (e->d[i] >> 1) | (e->d[i + 1] << 31);
            if (e->n)
                e->d[e->n - 1] >>= 1;
            bn_trim(e);
        }
    }
    if (bn_cmp(e, &g->fn.m) >= 0)
        bn_sub(e, e, &g->fn.m);
    return ELPIS_OK;
}

int elpis_ecdsa_verify(int curve, const uint8_t *pub, size_t publen,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *hash, size_t hashlen)
{
    const ec_group_t *g;
    ecp_t Q, R;
    bn_t r, s, e, w, u1, u2, x, one;
    size_t half;

    switch (curve) {
    case ELPIS_CURVE_P256: g = ec_p256(); break;
    case ELPIS_CURVE_P384: g = ec_p384(); break;
    default: return 0;
    }
    if (g == NULL)
        return 0;

    half = g->bytes;
    if (siglen != half * 2u || publen != half * 2u)
        return 0;

    if (bn_from_bytes(&r, sig, half) != ELPIS_OK) return 0;
    if (bn_from_bytes(&s, sig + half, half) != ELPIS_OK) return 0;

    bn_set_u32(&one, 1);
    if (bn_is_zero(&r) || bn_is_zero(&s))            return 0;
    if (bn_cmp(&r, &g->fn.m) >= 0)                   return 0;
    if (bn_cmp(&s, &g->fn.m) >= 0)                   return 0;

    if (ec_point_load(&Q, pub, publen, g) != ELPIS_OK)
        return 0;
    if (hash_to_bn(&e, hash, hashlen, g) != ELPIS_OK)
        return 0;

    /* w = s^-1 mod n; u1 = e*w mod n; u2 = r*w mod n */
    bn_modinv_prime(&w, &s, &g->fn);
    {
        bn_t tw, te, tr, prod;
        mont_to(&tw, &w, &g->fn);
        mont_to(&te, &e, &g->fn);
        mont_to(&tr, &r, &g->fn);
        mont_mul(&prod, &te, &tw, &g->fn);
        mont_from(&u1, &prod, &g->fn);
        mont_mul(&prod, &tr, &tw, &g->fn);
        mont_from(&u2, &prod, &g->fn);
    }

    ec_mul2(&R, &u1, &Q, &u2, g);
    if (R.inf)
        return 0;
    if (ec_affine_x(&x, &R, g) != ELPIS_OK)
        return 0;

    /* The signature is valid when x mod n equals r. */
    if (bn_cmp(&x, &g->fn.m) >= 0)
        bn_sub(&x, &x, &g->fn.m);
    return bn_cmp(&x, &r) == 0;
}
