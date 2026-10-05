/*
 * aead.c -- the TLS 1.3 record ciphers: ChaCha20-Poly1305 (RFC 8439) and
 * AES-128-GCM (NIST SP 800-38D), behind one interface.
 *
 * Opening checks the tag before it decrypts anything, so a forged record
 * never produces plaintext, and an in-place open that fails leaves the
 * ciphertext as it was.
 */
#include "elpis/tlscrypto.h"
#include "elpis/simd.h"
#include "aes.h"

/*
 * Set only by the self-test, to check the portable AES against AES-NI.
 * Workers read it on every AES init, and nothing in the resolver writes it,
 * so they never race.
 */
static int g_aes_soft_only;

static int aes_hw(void)
{
#if defined(ELPIS_ARCH_X86)
    const elpis_cpu_t *cpu = elpis_cpu();
    return !g_aes_soft_only && cpu->aes && cpu->pclmul && cpu->ssse3;
#else
    return 0;
#endif
}

void elpis_aes_use_hw(int on)
{
    g_aes_soft_only = !on;
}

const char *elpis_aes_backend(void)
{
    return aes_hw() ? "aes-ni" : "portable";
}

size_t elpis_aead_key_len(int suite)
{
    switch (suite) {
    case ELPIS_AEAD_CHACHA20_POLY1305: return 32;
    case ELPIS_AEAD_AES128_GCM:        return 16;
    default:                           return 0;
    }
}

int elpis_aead_init(elpis_aead_t *a, int suite, const uint8_t *key,
                    size_t keylen)
{
    static const uint8_t zero[16];

    if (elpis_aead_key_len(suite) == 0 || keylen != elpis_aead_key_len(suite))
        return -1;

    memset(a, 0, sizeof *a);
    a->suite = suite;
    if (suite == ELPIS_AEAD_CHACHA20_POLY1305) {
        memcpy(a->key, key, 32);
        return 0;
    }

    a->hw = aes_hw();
#if defined(ELPIS_ARCH_X86)
    if (a->hw) {
        elpis_aes_ni_expand(a->rk, key);
        elpis_aes_ni_encrypt(a->rk, zero, a->h);
        return 0;
    }
#endif
    elpis_aes_soft_expand(a->rk, key);
    elpis_aes_soft_encrypt(a->rk, zero, a->h);
    return 0;
}

void elpis_aead_wipe(elpis_aead_t *a)
{
    elpis_wipe(a, sizeof *a);
}

/* ---- ChaCha20-Poly1305 ---------------------------------------------- */

static void poly_pad16(elpis_poly1305_t *p, size_t n)
{
    static const uint8_t zero[16];
    if (n & 15u)
        elpis_poly1305_update(p, zero, 16u - (n & 15u));
}

/* The tag over aad and ciphertext, keyed from block 0 of the keystream. */
static void chacha_tag(const elpis_aead_t *a, const uint8_t nonce[12],
                       const uint8_t *aad, size_t aadlen,
                       const uint8_t *ct, size_t n, uint8_t tag[16])
{
    static const uint8_t zero[32];
    uint8_t otk[32], lens[16];
    elpis_poly1305_t p;

    elpis_chacha20_xor(a->key, 0, nonce, zero, otk, sizeof otk);
    elpis_poly1305_init(&p, otk);
    elpis_poly1305_update(&p, aad, aadlen);
    poly_pad16(&p, aadlen);
    elpis_poly1305_update(&p, ct, n);
    poly_pad16(&p, n);
    elpis_put64le(lens, (uint64_t)aadlen);
    elpis_put64le(lens + 8, (uint64_t)n);
    elpis_poly1305_update(&p, lens, sizeof lens);
    elpis_poly1305_final(&p, tag);
    elpis_wipe(otk, sizeof otk);
}

/* ---- AES-128-GCM ---------------------------------------------------- */

static void aes_encrypt(const elpis_aead_t *a, const uint8_t in[16],
                        uint8_t out[16])
{
#if defined(ELPIS_ARCH_X86)
    if (a->hw) {
        elpis_aes_ni_encrypt(a->rk, in, out);
        return;
    }
#endif
    elpis_aes_soft_encrypt(a->rk, in, out);
}

static void aes_ctr(const elpis_aead_t *a, const uint8_t ctr[16],
                    const uint8_t *in, uint8_t *out, size_t n)
{
#if defined(ELPIS_ARCH_X86)
    if (a->hw) {
        elpis_aes_ni_ctr(a->rk, ctr, in, out, n);
        return;
    }
#endif
    elpis_aes_soft_ctr(a->rk, ctr, in, out, n);
}

static void ghash(const elpis_aead_t *a, uint8_t y[16], const uint8_t *data,
                  size_t n)
{
#if defined(ELPIS_ARCH_X86)
    if (a->hw) {
        elpis_ghash_ni(a->h, y, data, n);
        return;
    }
#endif
    elpis_ghash_soft(a->h, y, data, n);
}

/* J0 for a 96-bit IV: IV || 0x00000001.  Data blocks start at J0 + 1. */
static void gcm_j0(uint8_t j0[16], const uint8_t nonce[12])
{
    memcpy(j0, nonce, 12);
    elpis_put32(j0 + 12, 1);
}

static void gcm_tag(const elpis_aead_t *a, const uint8_t j0[16],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t n, uint8_t tag[16])
{
    uint8_t y[16], lens[16], ek[16];
    int i;

    memset(y, 0, sizeof y);
    ghash(a, y, aad, aadlen);
    ghash(a, y, ct, n);
    elpis_put64(lens, (uint64_t)aadlen * 8u);
    elpis_put64(lens + 8, (uint64_t)n * 8u);
    ghash(a, y, lens, sizeof lens);

    aes_encrypt(a, j0, ek);
    for (i = 0; i < 16; i++)
        tag[i] = (uint8_t)(y[i] ^ ek[i]);
    elpis_wipe(ek, sizeof ek);
}

/* ---- the interface -------------------------------------------------- */

void elpis_aead_seal(const elpis_aead_t *a, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t n, uint8_t *out,
                     uint8_t tag[16])
{
    if (a->suite == ELPIS_AEAD_CHACHA20_POLY1305) {
        elpis_chacha20_xor(a->key, 1, nonce, in, out, n);
        chacha_tag(a, nonce, aad, aadlen, out, n, tag);
    } else {
        uint8_t j0[16], ctr[16];

        gcm_j0(j0, nonce);
        memcpy(ctr, j0, 16);
        elpis_put32(ctr + 12, 2);
        aes_ctr(a, ctr, in, out, n);
        gcm_tag(a, j0, aad, aadlen, out, n, tag);
    }
}

int elpis_aead_open(const elpis_aead_t *a, const uint8_t nonce[12],
                    const uint8_t *aad, size_t aadlen,
                    const uint8_t *in, size_t n, const uint8_t tag[16],
                    uint8_t *out)
{
    uint8_t want[16];
    int bad;

    if (a->suite == ELPIS_AEAD_CHACHA20_POLY1305) {
        chacha_tag(a, nonce, aad, aadlen, in, n, want);
        bad = elpis_ct_memcmp(want, tag, 16);
        if (!bad)
            elpis_chacha20_xor(a->key, 1, nonce, in, out, n);
    } else {
        uint8_t j0[16], ctr[16];

        gcm_j0(j0, nonce);
        gcm_tag(a, j0, aad, aadlen, in, n, want);
        bad = elpis_ct_memcmp(want, tag, 16);
        if (!bad) {
            memcpy(ctr, j0, 16);
            elpis_put32(ctr + 12, 2);
            aes_ctr(a, ctr, in, out, n);
        }
    }
    elpis_wipe(want, sizeof want);
    return bad ? -1 : 0;
}
