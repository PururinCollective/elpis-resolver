/*
 * ed25519.c -- Ed25519 signature verification (RFC 8032, DNSSEC algorithm 15).
 *
 * Built on the generic bignum rather than a 51-bit limb representation.  That
 * is perhaps four times slower per verification, but a recursive resolver
 * verifies a handful of signatures per query, not millions, and the shared
 * arithmetic is code that is already exercised by the RSA and ECDSA paths.
 */
#include "elpis/crypto.h"
#include "bn.h"

#include <pthread.h>

/* Curve25519 / edwards25519 constants. */
static const char ED_P[]  =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
static const char ED_D[]  =
    "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
static const char ED_L[]  =
    "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";
static const char ED_BX[] =
    "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a";
static const char ED_BY[] =
    "6666666666666666666666666666666666666666666666666666666666666658";
static const char ED_SQRTM1[] =
    "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0";

typedef struct {
    bn_t X, Y, Z, T;     /* extended coordinates, Montgomery form */
} edp_t;

typedef struct {
    mont_t fp;           /* field, p = 2^255 - 19 */
    mont_t fl;           /* group order L         */
    bn_t   d;            /* curve d, Montgomery   */
    bn_t   d2;           /* 2*d, Montgomery       */
    bn_t   sqrtm1;       /* sqrt(-1), Montgomery  */
    bn_t   one, zero;
    edp_t  B;
    int    ready;
} edctx_t;

static edctx_t g_ed;
static pthread_once_t g_ed_once = PTHREAD_ONCE_INIT;

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int bn_hex(bn_t *a, const char *s)
{
    uint8_t buf[64];
    size_t n = strlen(s), i;
    if (n % 2u || n / 2u > sizeof buf)
        return ELPIS_ERR;
    for (i = 0; i < n / 2u; i++) {
        int hi = hexval(s[i * 2]), lo = hexval(s[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return ELPIS_ERR;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return bn_from_bytes(a, buf, n / 2u);
}

#define EMUL(r, a, b) mont_mul((r), (a), (b), &g_ed.fp)
#define EADD(r, a, b) bn_addmod((r), (a), (b), &g_ed.fp.m)
#define ESUB(r, a, b) bn_submod((r), (a), (b), &g_ed.fp.m)

static void ed_init(void)
{
    bn_t p, d, l, bx, by, sq, one, two;

    memset(&g_ed, 0, sizeof g_ed);
    if (bn_hex(&p, ED_P) != ELPIS_OK) return;
    if (bn_hex(&d, ED_D) != ELPIS_OK) return;
    if (bn_hex(&l, ED_L) != ELPIS_OK) return;
    if (bn_hex(&bx, ED_BX) != ELPIS_OK) return;
    if (bn_hex(&by, ED_BY) != ELPIS_OK) return;
    if (bn_hex(&sq, ED_SQRTM1) != ELPIS_OK) return;

    if (mont_init(&g_ed.fp, &p) != ELPIS_OK) return;
    if (mont_init(&g_ed.fl, &l) != ELPIS_OK) return;

    bn_set_u32(&one, 1);
    bn_set_u32(&two, 2);
    mont_to(&g_ed.one, &one, &g_ed.fp);
    bn_zero(&g_ed.zero);

    mont_to(&g_ed.d, &d, &g_ed.fp);
    bn_addmod(&g_ed.d2, &g_ed.d, &g_ed.d, &g_ed.fp.m);     /* 2d */
    mont_to(&g_ed.sqrtm1, &sq, &g_ed.fp);

    mont_to(&g_ed.B.X, &bx, &g_ed.fp);
    mont_to(&g_ed.B.Y, &by, &g_ed.fp);
    g_ed.B.Z = g_ed.one;
    EMUL(&g_ed.B.T, &g_ed.B.X, &g_ed.B.Y);

    g_ed.ready = 1;
}

static void ed_identity(edp_t *p)
{
    bn_zero(&p->X);
    p->Y = g_ed.one;
    p->Z = g_ed.one;
    bn_zero(&p->T);
}

/* Extended coordinates, a = -1 (add-2008-hwcd-3). */
static void ed_add(edp_t *r, const edp_t *p, const edp_t *q)
{
    bn_t A, B, C, D, E, F, G, H, t;

    ESUB(&t, &p->Y, &p->X);
    ESUB(&A, &q->Y, &q->X);
    EMUL(&A, &t, &A);

    EADD(&t, &p->Y, &p->X);
    EADD(&B, &q->Y, &q->X);
    EMUL(&B, &t, &B);

    EMUL(&C, &p->T, &g_ed.d2);
    EMUL(&C, &C, &q->T);

    EMUL(&D, &p->Z, &q->Z);
    EADD(&D, &D, &D);

    ESUB(&E, &B, &A);
    ESUB(&F, &D, &C);
    EADD(&G, &D, &C);
    EADD(&H, &B, &A);

    EMUL(&r->X, &E, &F);
    EMUL(&r->Y, &G, &H);
    EMUL(&r->T, &E, &H);
    EMUL(&r->Z, &F, &G);
}

/* dbl-2008-hwcd, a = -1. */
static void ed_dbl(edp_t *r, const edp_t *p)
{
    bn_t A, B, C, D, E, F, G, H, t;

    EMUL(&A, &p->X, &p->X);
    EMUL(&B, &p->Y, &p->Y);
    EMUL(&C, &p->Z, &p->Z);
    EADD(&C, &C, &C);

    ESUB(&D, &g_ed.zero, &A);          /* D = a*A = -A */

    EADD(&t, &p->X, &p->Y);
    EMUL(&E, &t, &t);
    ESUB(&E, &E, &A);
    ESUB(&E, &E, &B);

    EADD(&G, &D, &B);
    ESUB(&F, &G, &C);
    ESUB(&H, &D, &B);

    EMUL(&r->X, &E, &F);
    EMUL(&r->Y, &G, &H);
    EMUL(&r->T, &E, &H);
    EMUL(&r->Z, &F, &G);
}

static void ed_mul(edp_t *r, const edp_t *p, const bn_t *k)
{
    edp_t acc;
    unsigned bits = bn_bits(k);
    unsigned i;

    ed_identity(&acc);
    for (i = bits; i-- > 0; ) {
        ed_dbl(&acc, &acc);
        if (bn_bit(k, i)) {
            edp_t t;
            ed_add(&t, &acc, p);
            acc = t;
        }
    }
    *r = acc;
}

/* Little-endian 32-byte load, as Ed25519 encodes everything. */
static int bn_from_le32(bn_t *a, const uint8_t in[32])
{
    uint8_t be[32];
    int i;
    for (i = 0; i < 32; i++)
        be[i] = in[31 - i];
    return bn_from_bytes(a, be, 32);
}

static void bn_to_le32(const bn_t *a, uint8_t out[32])
{
    uint8_t be[32];
    int i;
    bn_to_bytes(a, be, 32);
    for (i = 0; i < 32; i++)
        out[i] = be[31 - i];
}

/*
 * Point decompression (RFC 8032 section 5.1.3).
 *   x^2 = (y^2 - 1) / (d*y^2 + 1)
 *   x   = (u*v^3) * (u*v^7)^((p-5)/8)
 */
static int ed_decompress(edp_t *p, const uint8_t enc[32])
{
    bn_t y, u, v, v3, v7, x, t, chk, exp;
    unsigned sign = (unsigned)(enc[31] >> 7);
    uint8_t buf[32];

    memcpy(buf, enc, 32);
    buf[31] &= 0x7F;
    if (bn_from_le32(&y, buf) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (bn_cmp(&y, &g_ed.fp.m) >= 0)
        return ELPIS_EFORMAT;             /* non-canonical encoding */

    mont_to(&y, &y, &g_ed.fp);

    EMUL(&u, &y, &y);                     /* y^2         */
    EMUL(&v, &g_ed.d, &u);
    EADD(&v, &v, &g_ed.one);              /* v = d*y^2 + 1 */
    ESUB(&u, &u, &g_ed.one);              /* u = y^2 - 1   */

    EMUL(&v3, &v, &v);
    EMUL(&v3, &v3, &v);                   /* v^3 */
    EMUL(&v7, &v3, &v3);
    EMUL(&v7, &v7, &v);                   /* v^7 */

    EMUL(&t, &u, &v7);
    /* t^((p-5)/8), computed in plain form to reuse bn_modexp. */
    {
        bn_t tp, five, e, res;
        mont_from(&tp, &t, &g_ed.fp);
        bn_set_u32(&five, 5);
        bn_sub(&e, &g_ed.fp.m, &five);
        {
            unsigned i;
            for (i = 0; i < 3; i++) {     /* divide by 8 */
                unsigned j;
                for (j = 0; j + 1u < e.n; j++)
                    e.d[j] = (e.d[j] >> 1) | (e.d[j + 1] << 31);
                if (e.n)
                    e.d[e.n - 1] >>= 1;
                bn_trim(&e);
            }
        }
        bn_modexp(&res, &tp, &e, &g_ed.fp);
        mont_to(&exp, &res, &g_ed.fp);
    }

    EMUL(&x, &u, &v3);
    EMUL(&x, &x, &exp);

    /* Check v*x^2 == u, else multiply by sqrt(-1) and check again. */
    EMUL(&chk, &x, &x);
    EMUL(&chk, &chk, &v);
    if (bn_cmp(&chk, &u) != 0) {
        bn_t nu;
        ESUB(&nu, &g_ed.zero, &u);
        if (bn_cmp(&chk, &nu) != 0)
            return ELPIS_EFORMAT;          /* not a curve point */
        EMUL(&x, &x, &g_ed.sqrtm1);
    }

    /* Match the requested sign of x. */
    {
        bn_t xp;
        mont_from(&xp, &x, &g_ed.fp);
        if (bn_is_zero(&xp) && sign)
            return ELPIS_EFORMAT;          /* x = 0 with sign set is invalid */
        if ((unsigned)(xp.n ? (xp.d[0] & 1u) : 0u) != sign)
            ESUB(&x, &g_ed.zero, &x);
    }

    p->X = x;
    p->Y = y;
    p->Z = g_ed.one;
    EMUL(&p->T, &x, &y);
    return ELPIS_OK;
}

/* Compress back to the 32-byte encoding so two points can be compared. */
static void ed_compress(const edp_t *p, uint8_t out[32])
{
    bn_t zinv, x, yv, zp;

    mont_from(&zp, &p->Z, &g_ed.fp);
    bn_modinv_prime(&zinv, &zp, &g_ed.fp);
    mont_to(&zinv, &zinv, &g_ed.fp);

    EMUL(&x, &p->X, &zinv);
    EMUL(&yv, &p->Y, &zinv);
    mont_from(&x, &x, &g_ed.fp);
    mont_from(&yv, &yv, &g_ed.fp);

    bn_to_le32(&yv, out);
    out[31] = (uint8_t)(out[31] | (((x.n ? x.d[0] : 0u) & 1u) << 7));
}

/* A SHA-512 digest is little-endian here and the bignum layer is big-endian,
 * so the bytes turn over before the reduction mod L. */
static int hash_to_scalar(const uint8_t digest[64], bn_t *out)
{
    uint8_t be[64];
    bn_t t;
    int i;

    for (i = 0; i < 64; i++)
        be[i] = digest[63 - i];
    if (bn_from_bytes(&t, be, 64) != ELPIS_OK)
        return ELPIS_ERR;
    bn_mod(out, &t, &g_ed.fl.m);
    return ELPIS_OK;
}

int elpis_ed25519_verify(const uint8_t pk[32], const uint8_t *m, size_t mlen,
                         const uint8_t sig[64])
{
    edp_t A, R, sB, hA, rhs;
    bn_t S, h;
    uint8_t digest[64];
    uint8_t lhs_enc[32], rhs_enc[32];
    elpis_sha512_t sh;

    pthread_once(&g_ed_once, ed_init);
    if (!g_ed.ready)
        return 0;

    /* S must be canonical and below the group order (RFC 8032 section 8.4). */
    if (bn_from_le32(&S, sig + 32) != ELPIS_OK)
        return 0;
    if (bn_cmp(&S, &g_ed.fl.m) >= 0)
        return 0;

    if (ed_decompress(&A, pk) != ELPIS_OK)
        return 0;
    if (ed_decompress(&R, sig) != ELPIS_OK)
        return 0;

    elpis_sha512_init(&sh);
    elpis_sha512_update(&sh, sig, 32);
    elpis_sha512_update(&sh, pk, 32);
    elpis_sha512_update(&sh, m, mlen);
    elpis_sha512_final(&sh, digest);

    if (hash_to_scalar(digest, &h) != ELPIS_OK)
        return 0;

    ed_mul(&sB, &g_ed.B, &S);
    ed_mul(&hA, &A, &h);
    ed_add(&rhs, &R, &hA);

    ed_compress(&sB, lhs_enc);
    ed_compress(&rhs, rhs_enc);

    return elpis_ct_memcmp(lhs_enc, rhs_enc, 32) == 0;
}

#ifdef ELPIS_ED25519_SIGN
/*
 * Signing lives behind a build flag and is never compiled into the resolver.
 * A DNS resolver has no reason to hold an Ed25519 signing routine: it checks
 * signatures, it does not make them.  The licence issuing tool and the test
 * binary define ELPIS_ED25519_SIGN; bin/elpis does not, so none of this is in
 * the binary you deploy.
 */
static int ed_secret_scalar(const uint8_t sk[32], bn_t *a, uint8_t prefix[32])
{
    uint8_t h[64];

    elpis_sha512(sk, 32, h);
    h[0]  = (uint8_t)(h[0]  & 248);       /* clamp, RFC 8032 section 5.1.5 */
    h[31] = (uint8_t)((h[31] & 63) | 64);
    memcpy(prefix, h + 32, 32);
    return bn_from_le32(a, h);
}

int elpis_ed25519_pubkey(const uint8_t sk[32], uint8_t pk[32])
{
    bn_t a;
    edp_t A;
    uint8_t prefix[32];

    pthread_once(&g_ed_once, ed_init);
    if (!g_ed.ready)
        return ELPIS_ERR;
    if (ed_secret_scalar(sk, &a, prefix) != ELPIS_OK)
        return ELPIS_ERR;
    ed_mul(&A, &g_ed.B, &a);
    ed_compress(&A, pk);
    return ELPIS_OK;
}

int elpis_ed25519_sign(const uint8_t sk[32], const uint8_t *m, size_t mlen,
                       uint8_t sig[64])
{
    bn_t a, r, k, S, t;
    edp_t R, A;
    uint8_t prefix[32], pk[32], digest[64];
    elpis_sha512_t sh;

    pthread_once(&g_ed_once, ed_init);
    if (!g_ed.ready)
        return ELPIS_ERR;
    if (ed_secret_scalar(sk, &a, prefix) != ELPIS_OK)
        return ELPIS_ERR;

    ed_mul(&A, &g_ed.B, &a);
    ed_compress(&A, pk);

    /* r = SHA512(prefix || M) mod L -- deterministic, so no RNG is needed
     * and a bad one cannot leak the key the way it does with ECDSA. */
    elpis_sha512_init(&sh);
    elpis_sha512_update(&sh, prefix, 32);
    elpis_sha512_update(&sh, m, mlen);
    elpis_sha512_final(&sh, digest);
    if (hash_to_scalar(digest, &r) != ELPIS_OK)
        return ELPIS_ERR;

    ed_mul(&R, &g_ed.B, &r);
    ed_compress(&R, sig);

    /* k = SHA512(R || A || M) mod L */
    elpis_sha512_init(&sh);
    elpis_sha512_update(&sh, sig, 32);
    elpis_sha512_update(&sh, pk, 32);
    elpis_sha512_update(&sh, m, mlen);
    elpis_sha512_final(&sh, digest);
    if (hash_to_scalar(digest, &k) != ELPIS_OK)
        return ELPIS_ERR;

    /* S = (r + k*a) mod L */
    bn_mul(&t, &k, &a);
    bn_mod(&t, &t, &g_ed.fl.m);
    bn_addmod(&S, &t, &r, &g_ed.fl.m);
    bn_to_le32(&S, sig + 32);
    return ELPIS_OK;
}
#endif /* ELPIS_ED25519_SIGN */
