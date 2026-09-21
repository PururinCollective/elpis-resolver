/*
 * mldsa.c -- ML-DSA verification (FIPS 204), variants 44, 65 and 87.
 *
 * Verification only: pkDecode, sigDecode, ExpandA, SampleInBall, the NTT and
 * the hint reconstruction.  Key generation and signing are deliberately
 * absent -- a resolver never holds an ML-DSA private key.
 *
 * All three parameter sets share one code path, driven by a parameter table,
 * so the variants cannot drift apart.  The NTT twiddle factors are derived at
 * startup from zeta = 1753 rather than pasted in as a literal table, which
 * removes a whole class of transcription bug.
 *
 * DNSSEC codepoints for these algorithms are not yet assigned by IANA; see
 * draft-ietf-dnsop-dnssec-mldsa and the mldsa*-algorithm settings in
 * elpis.conf.
 */
#include "elpis/crypto.h"

#include <pthread.h>

#define MLD_N     256
#define MLD_Q     8380417
#define MLD_D     13
#define MLD_QINV  58728449u          /* q^-1 mod 2^32 */
#define MLD_ZETA  1753
#define MLD_SEEDBYTES 32
#define MLD_TRBYTES   64
#define MLD_CRHBYTES  64

#define MLD_K_MAX 8
#define MLD_L_MAX 7

typedef struct { int32_t c[MLD_N]; } poly_t;

typedef struct {
    int      k, l;
    int      tau;
    int      beta;           /* tau * eta                    */
    int      omega;
    int32_t  gamma1;         /* 1 << 17 or 1 << 19           */
    int      gamma1_bits;    /* 18 or 20                     */
    int32_t  gamma2;
    int      w1_bits;        /* 6 or 4                       */
    int      ctilde_bytes;   /* lambda / 4                   */
    size_t   pk_bytes, sig_bytes;
    size_t   z_packed;       /* per polynomial               */
    size_t   w1_packed;      /* per polynomial               */
} mld_param_t;

static const mld_param_t k_param[3] = {
    /* ML-DSA-44 */
    { 4, 4, 39,  78, 80, 1 << 17, 18,  95232, 6, 32, 1312, 2420, 576, 192 },
    /* ML-DSA-65 */
    { 6, 5, 49, 196, 55, 1 << 19, 20, 261888, 4, 48, 1952, 3309, 640, 128 },
    /* ML-DSA-87 */
    { 8, 7, 60, 120, 75, 1 << 19, 20, 261888, 4, 64, 2592, 4627, 640, 128 }
};

static const mld_param_t *param_of(int variant)
{
    switch (variant) {
    case ELPIS_MLDSA_44: return &k_param[0];
    case ELPIS_MLDSA_65: return &k_param[1];
    case ELPIS_MLDSA_87: return &k_param[2];
    default:             return NULL;
    }
}

size_t elpis_mldsa_pk_bytes(int variant)
{
    const mld_param_t *p = param_of(variant);
    return p ? p->pk_bytes : 0;
}

size_t elpis_mldsa_sig_bytes(int variant)
{
    const mld_param_t *p = param_of(variant);
    return p ? p->sig_bytes : 0;
}

/* ================================================================== */
/* Modular arithmetic                                                  */
/* ================================================================== */

/* a * 2^-32 mod q, result in (-q, q). */
static int32_t mont_reduce(int64_t a)
{
    int32_t t = (int32_t)((uint32_t)((uint64_t)a) * MLD_QINV);
    return (int32_t)((a - (int64_t)t * MLD_Q) >> 32);
}

/* Centred reduction of a 32-bit value to (-6283009, 6283007). */
static int32_t reduce32(int32_t a)
{
    int32_t t = (a + (1 << 22)) >> 23;
    return a - t * MLD_Q;
}

static int32_t caddq(int32_t a)
{
    return a + ((a >> 31) & MLD_Q);
}

/* ------------------------------------------------------------------ */
/* NTT                                                                 */
/* ------------------------------------------------------------------ */

static int32_t g_zetas[MLD_N];
static pthread_once_t g_zeta_once = PTHREAD_ONCE_INIT;

static unsigned brv8(unsigned x)
{
    unsigned r = 0, i;
    for (i = 0; i < 8; i++)
        r |= ((x >> i) & 1u) << (7u - i);
    return r;
}

static void zetas_init(void)
{
    unsigned i;
    uint64_t r_mod_q = (uint64_t)((((uint64_t)1 << 32) % MLD_Q));

    for (i = 0; i < MLD_N; i++) {
        unsigned e = brv8(i);
        uint64_t acc = 1;
        uint64_t base = MLD_ZETA;
        unsigned bits = e;

        while (bits) {
            if (bits & 1u)
                acc = (acc * base) % MLD_Q;
            base = (base * base) % MLD_Q;
            bits >>= 1;
        }
        acc = (acc * r_mod_q) % MLD_Q;            /* Montgomery domain */
        g_zetas[i] = (int32_t)(acc > (uint64_t)(MLD_Q / 2)
                               ? (int64_t)acc - MLD_Q : (int64_t)acc);
    }
    g_zetas[0] = 0;                               /* never referenced */
}

static void ntt(int32_t a[MLD_N])
{
    unsigned len, start, j, k = 0;

    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < MLD_N; start = j + len) {
            int32_t zeta = g_zetas[++k];
            for (j = start; j < start + len; ++j) {
                int32_t t = mont_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j]       = a[j] + t;
            }
        }
    }
}

static void invntt_tomont(int32_t a[MLD_N])
{
    const int32_t f = 41978;          /* mont^2 / 256 */
    unsigned start, len, j, k = MLD_N;

    for (len = 1; len < MLD_N; len <<= 1) {
        for (start = 0; start < MLD_N; start = j + len) {
            int32_t zeta = -g_zetas[--k];
            for (j = start; j < start + len; ++j) {
                int32_t t = a[j];
                a[j]       = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = mont_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }
    for (j = 0; j < MLD_N; ++j)
        a[j] = mont_reduce((int64_t)f * a[j]);
}

/* ------------------------------------------------------------------ */
/* Polynomial helpers                                                  */
/* ------------------------------------------------------------------ */

static void poly_pointwise_acc(poly_t *r, const poly_t *a, const poly_t *b,
                               int accumulate)
{
    unsigned i;
    for (i = 0; i < MLD_N; i++) {
        int32_t v = mont_reduce((int64_t)a->c[i] * b->c[i]);
        r->c[i] = accumulate ? (r->c[i] + v) : v;
    }
}

static void poly_sub(poly_t *r, const poly_t *a, const poly_t *b)
{
    unsigned i;
    for (i = 0; i < MLD_N; i++)
        r->c[i] = a->c[i] - b->c[i];
}

static void poly_reduce(poly_t *a)
{
    unsigned i;
    for (i = 0; i < MLD_N; i++)
        a->c[i] = reduce32(a->c[i]);
}

static void poly_caddq(poly_t *a)
{
    unsigned i;
    for (i = 0; i < MLD_N; i++)
        a->c[i] = caddq(a->c[i]);
}

static void poly_shiftl(poly_t *a)
{
    unsigned i;
    for (i = 0; i < MLD_N; i++)
        a->c[i] <<= MLD_D;
}

/* 1 when any coefficient is >= B in absolute value. */
static int poly_chknorm(const poly_t *a, int32_t B)
{
    unsigned i;
    if (B > (MLD_Q - 1) / 8)
        return 1;
    for (i = 0; i < MLD_N; i++) {
        /* Absolute value without a branch on the sign bit. */
        int32_t t = a->c[i] >> 31;
        t = a->c[i] - (t & (2 * a->c[i]));
        if (t >= B)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Decompose / hints (FIPS 204 section 7.4)                            */
/* ------------------------------------------------------------------ */

static int32_t decompose(int32_t *a0, int32_t a, int32_t gamma2)
{
    int32_t a1 = (a + 127) >> 7;

    if (gamma2 == (MLD_Q - 1) / 32) {
        a1  = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {                         /* (q-1)/88 */
        a1  = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    *a0  = a - a1 * 2 * gamma2;
    *a0 -= (((MLD_Q - 1) / 2 - *a0) >> 31) & MLD_Q;
    return a1;
}

static int32_t use_hint(int32_t a, unsigned hint, int32_t gamma2)
{
    int32_t a0, a1 = decompose(&a0, a, gamma2);

    if (hint == 0)
        return a1;
    if (gamma2 == (MLD_Q - 1) / 32)
        return (a0 > 0) ? ((a1 + 1) & 15) : ((a1 - 1) & 15);
    if (a0 > 0)
        return (a1 == 43) ? 0 : a1 + 1;
    return (a1 == 0) ? 43 : a1 - 1;
}

/* ------------------------------------------------------------------ */
/* Packing                                                             */
/* ------------------------------------------------------------------ */

/* t1: 10 bits per coefficient. */
static void polyt1_unpack(poly_t *r, const uint8_t *a)
{
    unsigned i;
    for (i = 0; i < MLD_N / 4u; i++) {
        r->c[4 * i + 0] = (int32_t)(((uint32_t)a[5 * i + 0] >> 0) |
                                    ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->c[4 * i + 1] = (int32_t)(((uint32_t)a[5 * i + 1] >> 2) |
                                    ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->c[4 * i + 2] = (int32_t)(((uint32_t)a[5 * i + 2] >> 4) |
                                    ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->c[4 * i + 3] = (int32_t)(((uint32_t)a[5 * i + 3] >> 6) |
                                    ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
    }
}

static void polyz_unpack(poly_t *r, const uint8_t *a, int32_t gamma1)
{
    unsigned i;

    if (gamma1 == (1 << 17)) {
        for (i = 0; i < MLD_N / 4u; i++) {
            r->c[4 * i + 0] = (int32_t)((((uint32_t)a[9 * i + 0]) |
                                         ((uint32_t)a[9 * i + 1] << 8) |
                                         ((uint32_t)a[9 * i + 2] << 16)) & 0x3FFFF);
            r->c[4 * i + 1] = (int32_t)(((((uint32_t)a[9 * i + 2]) >> 2) |
                                         ((uint32_t)a[9 * i + 3] << 6) |
                                         ((uint32_t)a[9 * i + 4] << 14)) & 0x3FFFF);
            r->c[4 * i + 2] = (int32_t)(((((uint32_t)a[9 * i + 4]) >> 4) |
                                         ((uint32_t)a[9 * i + 5] << 4) |
                                         ((uint32_t)a[9 * i + 6] << 12)) & 0x3FFFF);
            r->c[4 * i + 3] = (int32_t)(((((uint32_t)a[9 * i + 6]) >> 6) |
                                         ((uint32_t)a[9 * i + 7] << 2) |
                                         ((uint32_t)a[9 * i + 8] << 10)) & 0x3FFFF);
            r->c[4 * i + 0] = gamma1 - r->c[4 * i + 0];
            r->c[4 * i + 1] = gamma1 - r->c[4 * i + 1];
            r->c[4 * i + 2] = gamma1 - r->c[4 * i + 2];
            r->c[4 * i + 3] = gamma1 - r->c[4 * i + 3];
        }
    } else {
        for (i = 0; i < MLD_N / 2u; i++) {
            r->c[2 * i + 0] = (int32_t)((((uint32_t)a[5 * i + 0]) |
                                         ((uint32_t)a[5 * i + 1] << 8) |
                                         ((uint32_t)a[5 * i + 2] << 16)) & 0xFFFFF);
            r->c[2 * i + 1] = (int32_t)(((((uint32_t)a[5 * i + 2]) >> 4) |
                                         ((uint32_t)a[5 * i + 3] << 4) |
                                         ((uint32_t)a[5 * i + 4] << 12)) & 0xFFFFF);
            r->c[2 * i + 0] = gamma1 - r->c[2 * i + 0];
            r->c[2 * i + 1] = gamma1 - r->c[2 * i + 1];
        }
    }
}

static void polyw1_pack(uint8_t *r, const poly_t *a, int w1_bits)
{
    unsigned i;
    if (w1_bits == 6) {
        for (i = 0; i < MLD_N / 4u; i++) {
            r[3 * i + 0] = (uint8_t)(a->c[4 * i + 0] | (a->c[4 * i + 1] << 6));
            r[3 * i + 1] = (uint8_t)((a->c[4 * i + 1] >> 2) | (a->c[4 * i + 2] << 4));
            r[3 * i + 2] = (uint8_t)((a->c[4 * i + 2] >> 4) | (a->c[4 * i + 3] << 2));
        }
    } else {
        for (i = 0; i < MLD_N / 2u; i++)
            r[i] = (uint8_t)(a->c[2 * i + 0] | (a->c[2 * i + 1] << 4));
    }
}

/* ------------------------------------------------------------------ */
/* Sampling                                                            */
/* ------------------------------------------------------------------ */

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

static unsigned rej_uniform(int32_t *a, unsigned len,
                            const uint8_t *buf, unsigned buflen)
{
    unsigned ctr = 0, pos = 0;

    while (ctr < len && pos + 3 <= buflen) {
        uint32_t t = (uint32_t)buf[pos]
                   | ((uint32_t)buf[pos + 1] << 8)
                   | ((uint32_t)buf[pos + 2] << 16);
        pos += 3;
        t &= 0x7FFFFF;
        if (t < MLD_Q)
            a[ctr++] = (int32_t)t;
    }
    return ctr;
}

/* ExpandA: one matrix entry from SHAKE128(rho || nonce). */
static void poly_uniform(poly_t *a, const uint8_t seed[MLD_SEEDBYTES],
                         uint16_t nonce)
{
    elpis_keccak_t st;
    uint8_t buf[SHAKE128_RATE * 3];
    uint8_t ext[MLD_SEEDBYTES + 2];
    unsigned ctr;

    memcpy(ext, seed, MLD_SEEDBYTES);
    ext[MLD_SEEDBYTES]     = (uint8_t)(nonce & 0xFF);
    ext[MLD_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    elpis_shake128_init(&st);
    elpis_keccak_absorb(&st, ext, sizeof ext);
    elpis_keccak_squeeze(&st, buf, sizeof buf);

    ctr = rej_uniform(a->c, MLD_N, buf, (unsigned)sizeof buf);
    while (ctr < MLD_N) {
        elpis_keccak_squeeze(&st, buf, SHAKE128_RATE);
        ctr += rej_uniform(a->c + ctr, MLD_N - ctr, buf, SHAKE128_RATE);
    }
}

/* SampleInBall: tau coefficients of +-1, the rest zero. */
static void poly_challenge(poly_t *c, const uint8_t *seed, int seedlen, int tau)
{
    elpis_keccak_t st;
    uint8_t buf[SHAKE256_RATE];
    uint64_t signs = 0;
    unsigned i, pos;

    elpis_shake256_init(&st);
    elpis_keccak_absorb(&st, seed, (size_t)seedlen);
    elpis_keccak_squeeze(&st, buf, sizeof buf);

    for (i = 0; i < 8; i++)
        signs |= (uint64_t)buf[i] << (8u * i);
    pos = 8;

    for (i = 0; i < MLD_N; i++)
        c->c[i] = 0;

    for (i = (unsigned)(MLD_N - tau); i < MLD_N; i++) {
        unsigned b;
        do {
            if (pos >= SHAKE256_RATE) {
                elpis_keccak_squeeze(&st, buf, SHAKE256_RATE);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->c[i] = c->c[b];
        c->c[b] = 1 - 2 * (int32_t)(signs & 1u);
        signs >>= 1;
    }
}

/* ------------------------------------------------------------------ */
/* Signature decoding                                                  */
/* ------------------------------------------------------------------ */

static int unpack_sig(const mld_param_t *p, const uint8_t *sig,
                      uint8_t *ctilde, poly_t *z, poly_t *h)
{
    const uint8_t *s = sig;
    int i, j, k;

    memcpy(ctilde, s, (size_t)p->ctilde_bytes);
    s += p->ctilde_bytes;

    for (i = 0; i < p->l; i++)
        polyz_unpack(&z[i], s + (size_t)i * p->z_packed, p->gamma1);
    s += (size_t)p->l * p->z_packed;

    /*
     * Hint decoding, with the strong-unforgeability checks from FIPS 204
     * Algorithm 20: positions strictly increasing within a polynomial, the
     * per-polynomial cursor non-decreasing and bounded by omega, and every
     * unused byte zero.  Skipping any of these admits multiple signatures
     * for one message.
     */
    k = 0;
    for (i = 0; i < p->k; i++) {
        for (j = 0; j < MLD_N; j++)
            h[i].c[j] = 0;

        if (s[p->omega + i] < k || s[p->omega + i] > p->omega)
            return ELPIS_ERR;

        for (j = k; j < s[p->omega + i]; j++) {
            if (j > k && s[j] <= s[j - 1])
                return ELPIS_ERR;
            h[i].c[s[j]] = 1;
        }
        k = s[p->omega + i];
    }
    for (j = k; j < p->omega; j++)
        if (s[j] != 0)
            return ELPIS_ERR;

    return ELPIS_OK;
}

/* ================================================================== */
/* Verify                                                              */
/* ================================================================== */

int elpis_mldsa_verify(int variant, const uint8_t *pk, size_t pklen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *sig, size_t siglen)
{
    const mld_param_t *p = param_of(variant);
    poly_t z[MLD_L_MAX], h[MLD_K_MAX], t1[MLD_K_MAX], w[MLD_K_MAX];
    poly_t cp, tmp;
    uint8_t ctilde[64], ctilde2[64];
    uint8_t mu[MLD_CRHBYTES], tr[MLD_TRBYTES];
    uint8_t w1buf[MLD_K_MAX * 192];
    const uint8_t *rho;
    elpis_keccak_t st;
    int i, j;

    if (p == NULL)
        return 0;
    if (pklen != p->pk_bytes || siglen != p->sig_bytes)
        return 0;

    pthread_once(&g_zeta_once, zetas_init);

    rho = pk;
    for (i = 0; i < p->k; i++)
        polyt1_unpack(&t1[i], pk + MLD_SEEDBYTES + (size_t)i * 320);

    if (unpack_sig(p, sig, ctilde, z, h) != ELPIS_OK)
        return 0;

    /* ||z||inf must stay below gamma1 - beta. */
    for (i = 0; i < p->l; i++)
        if (poly_chknorm(&z[i], p->gamma1 - p->beta))
            return 0;

    /* tr = H(pk, 64); mu = H(tr || 0x00 || |ctx| || ctx || M, 64) */
    elpis_shake256_init(&st);
    elpis_keccak_absorb(&st, pk, pklen);
    elpis_keccak_squeeze(&st, tr, MLD_TRBYTES);

    elpis_shake256_init(&st);
    elpis_keccak_absorb(&st, tr, MLD_TRBYTES);
    {
        /* Pure ML-DSA with an empty context string. */
        static const uint8_t pre[2] = { 0x00, 0x00 };
        elpis_keccak_absorb(&st, pre, sizeof pre);
    }
    elpis_keccak_absorb(&st, m, mlen);
    elpis_keccak_squeeze(&st, mu, MLD_CRHBYTES);

    poly_challenge(&cp, ctilde, p->ctilde_bytes, p->tau);

    /* w = A*NTT(z) - NTT(c) * NTT(t1 * 2^d) */
    for (i = 0; i < p->l; i++)
        ntt(z[i].c);

    for (i = 0; i < p->k; i++) {
        for (j = 0; j < p->l; j++) {
            poly_uniform(&tmp, rho, (uint16_t)((i << 8) + j));
            poly_pointwise_acc(&w[i], &tmp, &z[j], j != 0);
        }
    }

    ntt(cp.c);
    for (i = 0; i < p->k; i++) {
        poly_shiftl(&t1[i]);
        ntt(t1[i].c);
        poly_pointwise_acc(&tmp, &cp, &t1[i], 0);
        poly_sub(&w[i], &w[i], &tmp);
        poly_reduce(&w[i]);
        invntt_tomont(w[i].c);
        poly_caddq(&w[i]);
    }

    /* w1 = UseHint(h, w) */
    for (i = 0; i < p->k; i++) {
        for (j = 0; j < MLD_N; j++)
            w[i].c[j] = use_hint(w[i].c[j], (unsigned)h[i].c[j], p->gamma2);
        polyw1_pack(w1buf + (size_t)i * p->w1_packed, &w[i], p->w1_bits);
    }

    elpis_shake256_init(&st);
    elpis_keccak_absorb(&st, mu, MLD_CRHBYTES);
    elpis_keccak_absorb(&st, w1buf, (size_t)p->k * p->w1_packed);
    elpis_keccak_squeeze(&st, ctilde2, (size_t)p->ctilde_bytes);

    return elpis_ct_memcmp(ctilde, ctilde2, (size_t)p->ctilde_bytes) == 0;
}
