/*
 * bn.c -- fixed-width big integer arithmetic.
 */
#include "bn.h"

void bn_zero(bn_t *a)
{
    memset(a->d, 0, sizeof a->d);
    a->n = 0;
}

void bn_set_u32(bn_t *a, uint32_t v)
{
    bn_zero(a);
    if (v) {
        a->d[0] = v;
        a->n = 1;
    }
}

void bn_copy(bn_t *r, const bn_t *a)
{
    if (r != a)
        *r = *a;
}

void bn_trim(bn_t *a)
{
    while (a->n > 0 && a->d[a->n - 1] == 0)
        a->n--;
}

int bn_is_zero(const bn_t *a)
{
    unsigned i;
    for (i = 0; i < a->n; i++)
        if (a->d[i])
            return 0;
    return 1;
}

int bn_cmp(const bn_t *a, const bn_t *b)
{
    unsigned n = a->n > b->n ? a->n : b->n;
    unsigned i = n;

    while (i-- > 0) {
        uint32_t x = (i < a->n) ? a->d[i] : 0u;
        uint32_t y = (i < b->n) ? b->d[i] : 0u;
        if (x != y)
            return x < y ? -1 : 1;
    }
    return 0;
}

unsigned bn_bits(const bn_t *a)
{
    unsigned i = a->n;
    uint32_t v;
    unsigned b;

    while (i > 0 && a->d[i - 1] == 0)
        i--;
    if (i == 0)
        return 0;
    v = a->d[i - 1];
    b = 0;
    while (v) {
        b++;
        v >>= 1;
    }
    return (i - 1u) * 32u + b;
}

int bn_bit(const bn_t *a, unsigned i)
{
    unsigned limb = i / 32u;
    if (limb >= a->n)
        return 0;
    return (int)((a->d[limb] >> (i % 32u)) & 1u);
}

int bn_from_bytes(bn_t *a, const uint8_t *p, size_t n)
{
    size_t i;

    while (n > 0 && *p == 0) { p++; n--; }
    if ((n + 3u) / 4u > BN_MAX_LIMBS)
        return ELPIS_ERR;

    bn_zero(a);
    for (i = 0; i < n; i++) {
        size_t rev = n - 1u - i;
        a->d[rev / 4u] |= (uint32_t)p[i] << ((rev % 4u) * 8u);
    }
    a->n = (unsigned)((n + 3u) / 4u);
    bn_trim(a);
    return ELPIS_OK;
}

int bn_to_bytes(const bn_t *a, uint8_t *p, size_t n)
{
    size_t i;

    if (bn_bits(a) > n * 8u)
        return ELPIS_ERR;
    memset(p, 0, n);
    for (i = 0; i < n; i++) {
        size_t rev = n - 1u - i;
        uint32_t limb = (rev / 4u < a->n) ? a->d[rev / 4u] : 0u;
        p[i] = (uint8_t)(limb >> ((rev % 4u) * 8u));
    }
    return ELPIS_OK;
}

void bn_add(bn_t *r, const bn_t *a, const bn_t *b)
{
    unsigned n = a->n > b->n ? a->n : b->n;
    uint64_t carry = 0;
    unsigned i;

    if (n >= BN_MAX_LIMBS)
        n = BN_MAX_LIMBS - 1u;
    for (i = 0; i < n; i++) {
        uint64_t s = carry;
        s += (i < a->n) ? a->d[i] : 0u;
        s += (i < b->n) ? b->d[i] : 0u;
        r->d[i] = (uint32_t)s;
        carry = s >> 32;
    }
    if (carry && n < BN_MAX_LIMBS) {
        r->d[n++] = (uint32_t)carry;
    }
    for (i = n; i < BN_MAX_LIMBS; i++)
        r->d[i] = 0;
    r->n = n;
    bn_trim(r);
}

void bn_sub(bn_t *r, const bn_t *a, const bn_t *b)
{
    int64_t borrow = 0;
    unsigned i;

    for (i = 0; i < BN_MAX_LIMBS; i++) {
        int64_t s = (int64_t)((i < a->n) ? a->d[i] : 0u) - borrow;
        s -= (int64_t)((i < b->n) ? b->d[i] : 0u);
        if (s < 0) {
            s += ((int64_t)1 << 32);
            borrow = 1;
        } else {
            borrow = 0;
        }
        r->d[i] = (uint32_t)s;
    }
    r->n = a->n;
    bn_trim(r);
}

void bn_mul(bn_t *r, const bn_t *a, const bn_t *b)
{
    bn_t t;
    unsigned i, j;

    bn_zero(&t);
    for (i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        if (a->d[i] == 0)
            continue;
        for (j = 0; j < b->n; j++) {
            uint64_t p;
            if (i + j >= BN_MAX_LIMBS)
                break;
            p = (uint64_t)a->d[i] * b->d[j] + t.d[i + j] + carry;
            t.d[i + j] = (uint32_t)p;
            carry = p >> 32;
        }
        if (i + b->n < BN_MAX_LIMBS) {
            uint64_t p = (uint64_t)t.d[i + b->n] + carry;
            t.d[i + b->n] = (uint32_t)p;
            /* A further carry cannot occur: the product fits in a->n + b->n. */
        }
    }
    t.n = a->n + b->n;
    if (t.n > BN_MAX_LIMBS)
        t.n = BN_MAX_LIMBS;
    bn_trim(&t);
    *r = t;
}

/* r <<= 1 */
static void bn_shl1(bn_t *a)
{
    uint32_t carry = 0;
    unsigned i;

    for (i = 0; i < BN_MAX_LIMBS; i++) {
        uint32_t nc = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = nc;
    }
    if (a->n < BN_MAX_LIMBS)
        a->n++;
    bn_trim(a);
}

void bn_mod(bn_t *r, const bn_t *a, const bn_t *m)
{
    bn_t rem;
    unsigned bits, i;

    if (bn_cmp(a, m) < 0) {
        bn_copy(r, a);
        return;
    }
    bn_zero(&rem);
    bits = bn_bits(a);
    for (i = bits; i-- > 0; ) {
        bn_shl1(&rem);
        if (bn_bit(a, i))
            rem.d[0] |= 1u;
        if (rem.n == 0)
            rem.n = 1;
        if (bn_cmp(&rem, m) >= 0)
            bn_sub(&rem, &rem, m);
    }
    bn_trim(&rem);
    *r = rem;
}

void bn_addmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    bn_add(r, a, b);
    if (bn_cmp(r, m) >= 0)
        bn_sub(r, r, m);
}

void bn_submod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    if (bn_cmp(a, b) >= 0) {
        bn_sub(r, a, b);
    } else {
        bn_t t;
        bn_sub(&t, m, b);
        bn_add(r, a, &t);
        if (bn_cmp(r, m) >= 0)
            bn_sub(r, r, m);
    }
}

/* ------------------------------------------------------------------ */
/* Montgomery                                                          */
/* ------------------------------------------------------------------ */

int mont_init(mont_t *c, const bn_t *m)
{
    uint32_t inv, m0;
    unsigned i;
    bn_t t;

    if (m->n == 0 || (m->d[0] & 1u) == 0)
        return ELPIS_ERR;              /* modulus must be odd */
    /*
     * mont_mul() keeps a running total of k + 2 limbs; nothing here ever
     * forms a full 2k-limb product, so that is the only bound that matters.
     */
    if (m->n + 2u > BN_MAX_LIMBS)
        return ELPIS_ERR;

    c->m = *m;
    bn_trim(&c->m);
    c->k = c->m.n;

    /* Newton's iteration: each step doubles the number of correct bits. */
    m0 = c->m.d[0];
    inv = 1;
    for (i = 0; i < 5; i++)
        inv *= 2u - m0 * inv;
    c->m0inv = (uint32_t)(0u - inv);    /* -m^-1 mod 2^32 */

    /* rr = 2^(64k) mod m, computed by repeated doubling. */
    bn_set_u32(&t, 1);
    for (i = 0; i < c->k * 64u; i++) {
        bn_shl1(&t);
        if (bn_cmp(&t, &c->m) >= 0)
            bn_sub(&t, &t, &c->m);
    }
    c->rr = t;
    return ELPIS_OK;
}

/*
 * CIOS Montgomery multiplication.  r = a * b * R^-1 mod m, with a, b < m.
 */
void mont_mul(bn_t *r, const bn_t *a, const bn_t *b, const mont_t *c)
{
    uint32_t t[BN_MAX_LIMBS + 2];
    unsigned k = c->k;
    unsigned i, j;

    memset(t, 0, (k + 2u) * sizeof t[0]);

    for (i = 0; i < k; i++) {
        uint64_t carry = 0;
        uint32_t ai = (i < a->n) ? a->d[i] : 0u;
        uint32_t mi;

        for (j = 0; j < k; j++) {
            uint64_t p = (uint64_t)ai * ((j < b->n) ? b->d[j] : 0u)
                       + t[j] + carry;
            t[j] = (uint32_t)p;
            carry = p >> 32;
        }
        {
            uint64_t s = (uint64_t)t[k] + carry;
            t[k] = (uint32_t)s;
            t[k + 1] = (uint32_t)(s >> 32);
        }

        mi = (uint32_t)(t[0] * c->m0inv);
        carry = 0;
        for (j = 0; j < k; j++) {
            uint64_t p = (uint64_t)mi * c->m.d[j] + t[j] + carry;
            t[j] = (uint32_t)p;
            carry = p >> 32;
        }
        {
            uint64_t s = (uint64_t)t[k] + carry;
            t[k] = (uint32_t)s;
            t[k + 1] += (uint32_t)(s >> 32);
        }

        /* Shift right one limb: t[0] is now zero by construction. */
        for (j = 0; j <= k; j++)
            t[j] = t[j + 1];
        t[k + 1] = 0;
    }

    bn_zero(r);
    for (i = 0; i < k && i < BN_MAX_LIMBS; i++)
        r->d[i] = t[i];
    r->n = k;
    if (t[k] != 0 && k < BN_MAX_LIMBS) {
        r->d[k] = t[k];
        r->n = k + 1u;
    }
    bn_trim(r);
    if (bn_cmp(r, &c->m) >= 0)
        bn_sub(r, r, &c->m);
}

void mont_to(bn_t *r, const bn_t *a, const mont_t *c)
{
    mont_mul(r, a, &c->rr, c);
}

void mont_from(bn_t *r, const bn_t *a, const mont_t *c)
{
    bn_t one;
    bn_set_u32(&one, 1);
    mont_mul(r, a, &one, c);
}

void bn_modexp(bn_t *r, const bn_t *a, const bn_t *e, const mont_t *c)
{
    bn_t base, acc, am;
    unsigned bits, i;

    bn_mod(&am, a, &c->m);
    mont_to(&base, &am, c);

    /* acc = 1 in Montgomery form */
    {
        bn_t one;
        bn_set_u32(&one, 1);
        mont_to(&acc, &one, c);
    }

    bits = bn_bits(e);
    if (bits == 0) {
        mont_from(r, &acc, c);
        return;
    }
    for (i = bits; i-- > 0; ) {
        mont_mul(&acc, &acc, &acc, c);
        if (bn_bit(e, i))
            mont_mul(&acc, &acc, &base, c);
    }
    mont_from(r, &acc, c);
}

void bn_modinv_prime(bn_t *r, const bn_t *a, const mont_t *c)
{
    bn_t e, two;
    bn_set_u32(&two, 2);
    bn_sub(&e, &c->m, &two);         /* e = m - 2 */
    bn_modexp(r, a, &e, c);
}
