/*
 * bn.c -- fixed-width big integer arithmetic.
 *
 * A bn_t is wide enough for RSA-4096, but most of what passes through here is
 * eight limbs of P-256 or Ed25519.  So nothing looks past a->n: the limbs
 * above it are unspecified, never read, and never cleared.  Every loop used to
 * run the full 144 limbs whatever the operand -- bn_sub alone was the largest
 * cost of an ECDSA verification, which took 2.7 ms where eight limbs of work
 * take a fraction of that.
 */
#include "bn.h"

void bn_zero(bn_t *a)
{
    a->d[0] = 0;
    a->n = 0;
}

void bn_set_u32(bn_t *a, uint32_t v)
{
    a->d[0] = v;
    a->n = v ? 1u : 0u;
}

void bn_copy(bn_t *r, const bn_t *a)
{
    if (r == a)
        return;
    r->n = a->n;
    memcpy(r->d, a->d, (size_t)a->n * sizeof a->d[0]);
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

    memset(a->d, 0, ((n + 3u) / 4u) * sizeof a->d[0]);
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
    unsigned an = a->n, bn = b->n;
    unsigned n = an > bn ? an : bn;
    uint64_t carry = 0;
    unsigned i;

    if (n >= BN_MAX_LIMBS)
        n = BN_MAX_LIMBS - 1u;
    for (i = 0; i < n; i++) {
        uint64_t s = carry;
        s += (i < an) ? a->d[i] : 0u;
        s += (i < bn) ? b->d[i] : 0u;
        r->d[i] = (uint32_t)s;
        carry = s >> 32;
    }
    if (carry)
        r->d[n++] = (uint32_t)carry;
    r->n = n;
    bn_trim(r);
}

void bn_sub(bn_t *r, const bn_t *a, const bn_t *b)
{
    unsigned an = a->n, bn = b->n;
    unsigned n = an > bn ? an : bn;
    uint32_t borrow = 0;
    unsigned i;

    for (i = 0; i < n; i++) {
        uint64_t x = (i < an) ? a->d[i] : 0u;
        uint64_t y = (i < bn) ? b->d[i] : 0u;
        uint64_t d = x - y - borrow;
        r->d[i] = (uint32_t)d;
        borrow = (uint32_t)(d >> 63);
    }
    r->n = n;
    bn_trim(r);
}

void bn_mul(bn_t *r, const bn_t *a, const bn_t *b)
{
    bn_t t;
    unsigned i, j;
    unsigned tn = a->n + b->n;

    if (tn > BN_MAX_LIMBS)
        tn = BN_MAX_LIMBS;
    memset(t.d, 0, (size_t)tn * sizeof t.d[0]);
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
    t.n = tn;
    bn_trim(&t);
    bn_copy(r, &t);
}

/* r <<= 1 */
static void bn_shl1(bn_t *a)
{
    uint32_t carry = 0;
    unsigned i;

    for (i = 0; i < a->n; i++) {
        uint32_t nc = a->d[i] >> 31;
        a->d[i] = (a->d[i] << 1) | carry;
        carry = nc;
    }
    if (carry && a->n < BN_MAX_LIMBS)
        a->d[a->n++] = carry;
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
        if (bn_bit(a, i)) {
            if (rem.n == 0) {
                rem.d[0] = 1u;
                rem.n = 1;
            } else {
                rem.d[0] |= 1u;
            }
        }
        if (bn_cmp(&rem, m) >= 0)
            bn_sub(&rem, &rem, m);
    }
    bn_trim(&rem);
    bn_copy(r, &rem);
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
#ifdef BN_HAVE_U128
    if ((c->k & 1u) == 0) {
        uint64_t m064 = (uint64_t)c->m.d[0] | ((uint64_t)c->m.d[1] << 32);
        uint64_t inv64 = 1;
        for (i = 0; i < 6; i++)
            inv64 *= 2u - m064 * inv64;
        c->m0inv64 = (uint64_t)0 - inv64;
        for (i = 0; i < c->k / 2u; i++)
            c->m64[i] = (uint64_t)c->m.d[2u * i] |
                        ((uint64_t)c->m.d[2u * i + 1u] << 32);
    }
#endif

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
 *
 * The operands are copied into zero-padded k-limb arrays first, so the inner
 * loops carry no "is this limb present" test, and the reduction writes each
 * limb one place down as it goes rather than shifting the whole total after.
 */
#ifdef BN_HAVE_U128
__extension__ typedef unsigned __int128 bn_u128;

/* The same CIOS loop over 64-bit limbs: a quarter of the multiplications. */
static void mont_mul64(bn_t *r, const uint32_t *A, const uint32_t *B,
                       const mont_t *c)
{
    uint64_t a[BN_MAX_LIMBS / 2], b[BN_MAX_LIMBS / 2], t[BN_MAX_LIMBS / 2 + 2];
    const uint64_t *m = c->m64;
    unsigned k = c->k / 2u;
    unsigned i, j;

    for (i = 0; i < k; i++) {
        a[i] = (uint64_t)A[2u * i] | ((uint64_t)A[2u * i + 1u] << 32);
        b[i] = (uint64_t)B[2u * i] | ((uint64_t)B[2u * i + 1u] << 32);
    }
    memset(t, 0, (k + 2u) * sizeof t[0]);

    for (i = 0; i < k; i++) {
        bn_u128 p;
        uint64_t carry = 0, ai = a[i], mi;

        for (j = 0; j < k; j++) {
            p = (bn_u128)ai * b[j] + t[j] + carry;
            t[j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        p = (bn_u128)t[k] + carry;
        t[k]     = (uint64_t)p;
        t[k + 1] = (uint64_t)(p >> 64);

        mi = t[0] * c->m0inv64;
        p = (bn_u128)mi * m[0] + t[0];
        carry = (uint64_t)(p >> 64);
        for (j = 1; j < k; j++) {
            p = (bn_u128)mi * m[j] + t[j] + carry;
            t[j - 1] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        p = (bn_u128)t[k] + carry;
        t[k - 1] = (uint64_t)p;
        t[k]     = t[k + 1] + (uint64_t)(p >> 64);
    }

    for (i = 0; i < k; i++) {
        r->d[2u * i]      = (uint32_t)t[i];
        r->d[2u * i + 1u] = (uint32_t)(t[i] >> 32);
    }
    r->n = 2u * k;
    if (t[k] != 0 && r->n + 2u <= BN_MAX_LIMBS) {
        r->d[r->n++] = (uint32_t)t[k];
        r->d[r->n++] = (uint32_t)(t[k] >> 32);
    }
    bn_trim(r);
    if (bn_cmp(r, &c->m) >= 0)
        bn_sub(r, r, &c->m);
}
#endif

void mont_mul(bn_t *r, const bn_t *a, const bn_t *b, const mont_t *c)
{
    uint32_t t[BN_MAX_LIMBS + 2];
    uint32_t A[BN_MAX_LIMBS], B[BN_MAX_LIMBS];
    const uint32_t *m = c->m.d;
    unsigned k = c->k;
    unsigned an = a->n < k ? a->n : k, bn = b->n < k ? b->n : k;
    unsigned i, j;

    memcpy(A, a->d, (size_t)an * sizeof A[0]);
    memset(A + an, 0, (size_t)(k - an) * sizeof A[0]);
    memcpy(B, b->d, (size_t)bn * sizeof B[0]);
    memset(B + bn, 0, (size_t)(k - bn) * sizeof B[0]);
#ifdef BN_HAVE_U128
    if ((k & 1u) == 0) {
        mont_mul64(r, A, B, c);
        return;
    }
#endif
    memset(t, 0, (k + 2u) * sizeof t[0]);

    for (i = 0; i < k; i++) {
        uint64_t p, carry = 0;
        uint32_t ai = A[i], mi;

        for (j = 0; j < k; j++) {
            p = (uint64_t)ai * B[j] + t[j] + carry;
            t[j] = (uint32_t)p;
            carry = p >> 32;
        }
        p = (uint64_t)t[k] + carry;
        t[k]     = (uint32_t)p;
        t[k + 1] = (uint32_t)(p >> 32);

        mi = (uint32_t)(t[0] * c->m0inv);
        p = (uint64_t)mi * m[0] + t[0];
        carry = p >> 32;
        for (j = 1; j < k; j++) {
            p = (uint64_t)mi * m[j] + t[j] + carry;
            t[j - 1] = (uint32_t)p;
            carry = p >> 32;
        }
        p = (uint64_t)t[k] + carry;
        t[k - 1] = (uint32_t)p;
        t[k]     = t[k + 1] + (uint32_t)(p >> 32);
    }

    /* t < 2m: k + 1 limbs at most. */
    memcpy(r->d, t, (size_t)k * sizeof t[0]);
    r->n = k;
    if (k < BN_MAX_LIMBS && t[k] != 0)
        r->d[r->n++] = t[k];
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
