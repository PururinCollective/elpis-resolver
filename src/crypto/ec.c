/*
 * ec.c -- P-256 and P-384 point arithmetic.
 */
#include "ec.h"

#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Curve constants (SEC 2 / FIPS 186-4)                                */
/* ------------------------------------------------------------------ */

static const char P256_P[] =
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
static const char P256_B[] =
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
static const char P256_N[] =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
static const char P256_GX[] =
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
static const char P256_GY[] =
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

static const char P384_P[] =
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
    "ffffffff0000000000000000ffffffff";
static const char P384_B[] =
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
    "c656398d8a2ed19d2a85c8edd3ec2aef";
static const char P384_N[] =
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
    "581a0db248b0a77aecec196accc52973";
static const char P384_GX[] =
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
    "5502f25dbf55296c3a545e3872760ab7";
static const char P384_GY[] =
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
    "0a60b1ce1d7e819d7a431d7c90ea0e5f";

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int bn_from_hex(bn_t *a, const char *s)
{
    uint8_t buf[BN_MAX_LIMBS * 4];
    size_t n = strlen(s);
    size_t bytes, i;

    if (n % 2u != 0 || n / 2u > sizeof buf)
        return ELPIS_ERR;
    bytes = n / 2u;
    for (i = 0; i < bytes; i++) {
        int hi = hexval(s[i * 2]);
        int lo = hexval(s[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return ELPIS_ERR;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return bn_from_bytes(a, buf, bytes);
}

/* ------------------------------------------------------------------ */
/* Field helpers (all operands in Montgomery form)                     */
/* ------------------------------------------------------------------ */

#define FMUL(r, a, b) mont_mul((r), (a), (b), &g->fp)
#define FADD(r, a, b) bn_addmod((r), (a), (b), &g->fp.m)
#define FSUB(r, a, b) bn_submod((r), (a), (b), &g->fp.m)

void ec_set_inf(ecp_t *p)
{
    bn_set_u32(&p->X, 1);
    bn_set_u32(&p->Y, 1);
    bn_zero(&p->Z);
    p->inf = 1;
}

/*
 * Jacobian doubling specialised for a = -3 (true for both NIST curves):
 *   delta = Z^2, gamma = Y^2, beta = X*gamma
 *   alpha = 3*(X - delta)*(X + delta)
 *   X' = alpha^2 - 8*beta
 *   Z' = (Y + Z)^2 - gamma - delta
 *   Y' = alpha*(4*beta - X') - 8*gamma^2
 */
void ec_dbl(ecp_t *r, const ecp_t *p, const ec_group_t *g)
{
    bn_t delta, gamma, beta, alpha, t0, t1;

    if (p->inf || bn_is_zero(&p->Z)) {
        ec_set_inf(r);
        return;
    }

    FMUL(&delta, &p->Z, &p->Z);
    FMUL(&gamma, &p->Y, &p->Y);
    FMUL(&beta,  &p->X, &gamma);

    FSUB(&t0, &p->X, &delta);
    FADD(&t1, &p->X, &delta);
    FMUL(&alpha, &t0, &t1);
    FADD(&t0, &alpha, &alpha);
    FADD(&alpha, &t0, &alpha);            /* alpha *= 3 */

    FADD(&t0, &p->Y, &p->Z);
    FMUL(&t0, &t0, &t0);
    FSUB(&t0, &t0, &gamma);
    FSUB(&t0, &t0, &delta);               /* Z' */

    FMUL(&t1, &alpha, &alpha);
    {
        bn_t eight_beta;
        FADD(&eight_beta, &beta, &beta);          /* 2b  */
        FADD(&eight_beta, &eight_beta, &eight_beta); /* 4b */
        FADD(&beta, &eight_beta, &eight_beta);    /* beta = 8b, keep 4b */
        FSUB(&t1, &t1, &beta);                    /* X' = alpha^2 - 8b */

        /* Y' = alpha*(4b - X') - 8*gamma^2 */
        FSUB(&eight_beta, &eight_beta, &t1);
        FMUL(&eight_beta, &alpha, &eight_beta);
        FMUL(&gamma, &gamma, &gamma);
        FADD(&gamma, &gamma, &gamma);
        FADD(&gamma, &gamma, &gamma);
        FADD(&gamma, &gamma, &gamma);             /* 8*gamma^2 */
        FSUB(&r->Y, &eight_beta, &gamma);
    }
    r->X = t1;
    r->Z = t0;
    r->inf = bn_is_zero(&r->Z);
}

/*
 * Jacobian addition (add-2007-bl).
 */
void ec_add(ecp_t *r, const ecp_t *p, const ecp_t *q, const ec_group_t *g)
{
    bn_t z1z1, z2z2, u1, u2, s1, s2, h, rr, i, j, v, t0;

    if (p->inf) { *r = *q; return; }
    if (q->inf) { *r = *p; return; }

    FMUL(&z1z1, &p->Z, &p->Z);
    FMUL(&z2z2, &q->Z, &q->Z);
    FMUL(&u1, &p->X, &z2z2);
    FMUL(&u2, &q->X, &z1z1);
    FMUL(&t0, &q->Z, &z2z2);
    FMUL(&s1, &p->Y, &t0);
    FMUL(&t0, &p->Z, &z1z1);
    FMUL(&s2, &q->Y, &t0);

    FSUB(&h, &u2, &u1);
    FSUB(&rr, &s2, &s1);

    if (bn_is_zero(&h)) {
        if (bn_is_zero(&rr)) {
            ec_dbl(r, p, g);
        } else {
            ec_set_inf(r);
        }
        return;
    }

    FADD(&t0, &h, &h);
    FMUL(&i, &t0, &t0);          /* I = (2H)^2 */
    FMUL(&j, &h, &i);            /* J = H*I    */
    FADD(&rr, &rr, &rr);         /* r = 2(S2-S1) */
    FMUL(&v, &u1, &i);

    FMUL(&t0, &rr, &rr);
    FSUB(&t0, &t0, &j);
    FSUB(&t0, &t0, &v);
    FSUB(&t0, &t0, &v);          /* X3 */

    {
        bn_t y3, z3, tmp;
        FSUB(&tmp, &v, &t0);
        FMUL(&y3, &rr, &tmp);
        FMUL(&tmp, &s1, &j);
        FADD(&tmp, &tmp, &tmp);
        FSUB(&y3, &y3, &tmp);    /* Y3 */

        FADD(&z3, &p->Z, &q->Z);
        FMUL(&z3, &z3, &z3);
        FSUB(&z3, &z3, &z1z1);
        FSUB(&z3, &z3, &z2z2);
        FMUL(&z3, &z3, &h);      /* Z3 */

        r->X = t0;
        r->Y = y3;
        r->Z = z3;
        r->inf = bn_is_zero(&z3);
    }
}

void ec_mul2(ecp_t *r, const bn_t *k1, const ecp_t *q, const bn_t *k2,
             const ec_group_t *g)
{
    ecp_t tbl[4];      /* O, G, Q, G+Q */
    unsigned bits1 = bn_bits(k1);
    unsigned bits2 = bn_bits(k2);
    unsigned bits = bits1 > bits2 ? bits1 : bits2;
    unsigned i;

    ec_set_inf(&tbl[0]);
    tbl[1] = g->G;
    tbl[2] = *q;
    ec_add(&tbl[3], &g->G, q, g);

    ec_set_inf(r);
    if (bits == 0)
        return;

    /* Shamir's trick: one doubling per bit position for both scalars. */
    for (i = bits; i-- > 0; ) {
        unsigned idx;
        ec_dbl(r, r, g);
        idx = (unsigned)bn_bit(k1, i) | ((unsigned)bn_bit(k2, i) << 1);
        if (idx != 0)
            ec_add(r, r, &tbl[idx], g);
    }
}

int ec_affine_x(bn_t *x, const ecp_t *p, const ec_group_t *g)
{
    bn_t zinv, z2inv, t;

    if (p->inf || bn_is_zero(&p->Z))
        return ELPIS_ERR;

    /* Z is in Montgomery form; the inverse is taken in the same domain. */
    mont_from(&t, &p->Z, &g->fp);
    bn_modinv_prime(&zinv, &t, &g->fp);
    mont_to(&zinv, &zinv, &g->fp);
    FMUL(&z2inv, &zinv, &zinv);
    FMUL(&t, &p->X, &z2inv);
    mont_from(x, &t, &g->fp);
    return ELPIS_OK;
}

int ec_point_load(ecp_t *p, const uint8_t *buf, size_t len, const ec_group_t *g)
{
    bn_t x, y, lhs, rhs, t;

    if (len != (size_t)g->bytes * 2u)
        return ELPIS_EFORMAT;
    if (bn_from_bytes(&x, buf, g->bytes) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (bn_from_bytes(&y, buf + g->bytes, g->bytes) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (bn_cmp(&x, &g->fp.m) >= 0 || bn_cmp(&y, &g->fp.m) >= 0)
        return ELPIS_EFORMAT;
    if (bn_is_zero(&x) && bn_is_zero(&y))
        return ELPIS_EFORMAT;            /* the point at infinity is not a key */

    mont_to(&p->X, &x, &g->fp);
    mont_to(&p->Y, &y, &g->fp);
    {
        bn_t one;
        bn_set_u32(&one, 1);
        mont_to(&p->Z, &one, &g->fp);
    }
    p->inf = 0;

    /*
     * Reject points that are not on the curve.  Skipping this check is a
     * classic way to leak information or get a wrong answer from an
     * attacker-supplied key, so it is not optional even for verification.
     *   y^2 == x^3 - 3x + b
     */
    FMUL(&lhs, &p->Y, &p->Y);
    FMUL(&rhs, &p->X, &p->X);
    FMUL(&rhs, &rhs, &p->X);
    {
        bn_t three_x;
        FADD(&t, &p->X, &p->X);
        FADD(&three_x, &t, &p->X);
        FSUB(&rhs, &rhs, &three_x);
    }
    FADD(&rhs, &rhs, &g->b);
    if (bn_cmp(&lhs, &rhs) != 0)
        return ELPIS_EFORMAT;

    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Group setup                                                         */
/* ------------------------------------------------------------------ */

static ec_group_t g_p256, g_p384;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static int group_build(ec_group_t *g, const char *p, const char *b,
                       const char *n, const char *gx, const char *gy,
                       unsigned bytes)
{
    bn_t tp, tb, tn, tx, ty, one;

    if (bn_from_hex(&tp, p) != ELPIS_OK) return ELPIS_ERR;
    if (bn_from_hex(&tb, b) != ELPIS_OK) return ELPIS_ERR;
    if (bn_from_hex(&tn, n) != ELPIS_OK) return ELPIS_ERR;
    if (bn_from_hex(&tx, gx) != ELPIS_OK) return ELPIS_ERR;
    if (bn_from_hex(&ty, gy) != ELPIS_OK) return ELPIS_ERR;

    if (mont_init(&g->fp, &tp) != ELPIS_OK) return ELPIS_ERR;
    if (mont_init(&g->fn, &tn) != ELPIS_OK) return ELPIS_ERR;

    mont_to(&g->b, &tb, &g->fp);
    mont_to(&g->G.X, &tx, &g->fp);
    mont_to(&g->G.Y, &ty, &g->fp);
    bn_set_u32(&one, 1);
    mont_to(&g->G.Z, &one, &g->fp);
    g->G.inf = 0;

    g->bytes = bytes;
    g->nbits = bn_bits(&tn);
    g->ready = 1;
    return ELPIS_OK;
}

static void groups_init(void)
{
    group_build(&g_p256, P256_P, P256_B, P256_N, P256_GX, P256_GY, 32);
    group_build(&g_p384, P384_P, P384_B, P384_N, P384_GX, P384_GY, 48);
}

const ec_group_t *ec_p256(void)
{
    pthread_once(&g_once, groups_init);
    return g_p256.ready ? &g_p256 : NULL;
}

const ec_group_t *ec_p384(void)
{
    pthread_once(&g_once, groups_init);
    return g_p384.ready ? &g_p384 : NULL;
}
