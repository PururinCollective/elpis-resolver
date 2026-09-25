/*
 * noise.c -- Noise_NNpsk0_25519_ChaChaPoly_SHA256, for the mesh.
 *
 * Only this one pattern, written out step by step from the Noise spec
 * (revision 34) rather than driven by a general pattern interpreter: two
 * messages are easier to read as code than as a table.  See elpis/noise.h.
 */
#include "elpis/noise.h"
#include "elpis/crypto.h"
#include "elpis/util.h"

static const char k_protocol[] = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";

/* ------------------------------------------------------------------ */
/* CipherState                                                         */
/* ------------------------------------------------------------------ */

/* 32 bits of zeros, then the counter little-endian: the ChaChaPoly rule. */
static void cs_nonce(uint64_t n, uint8_t nonce[12])
{
    unsigned i;

    memset(nonce, 0, 4);
    for (i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(n >> (8 * i));
}

static void cs_set(elpis_noise_cs_t *cs, const uint8_t k[32])
{
    memcpy(cs->k, k, 32);
    cs->n = 0;
    cs->has_key = 1;
}

static void cs_encrypt(elpis_noise_cs_t *cs, const uint8_t *ad, size_t adlen,
                       const uint8_t *pt, size_t n, uint8_t *out)
{
    uint8_t nonce[12];

    cs_nonce(cs->n++, nonce);
    elpis_aead_seal(cs->k, nonce, ad, adlen, pt, n, out);
}

static int cs_decrypt(elpis_noise_cs_t *cs, const uint8_t *ad, size_t adlen,
                      const uint8_t *ct, size_t n, uint8_t *out)
{
    uint8_t nonce[12];

    cs_nonce(cs->n, nonce);
    if (elpis_aead_open(cs->k, nonce, ad, adlen, ct, n, out) != ELPIS_OK)
        return ELPIS_ERR;
    cs->n++;                    /* only a message that opened moves it on */
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* SymmetricState                                                      */
/* ------------------------------------------------------------------ */

static void mix_hash(elpis_noise_hs_t *hs, const uint8_t *d, size_t n)
{
    elpis_sha256_t c;

    elpis_sha256_init(&c);
    elpis_sha256_update(&c, hs->h, 32);
    elpis_sha256_update(&c, d, n);
    elpis_sha256_final(&c, hs->h);
}

/* HKDF as Noise defines it: the chaining key as the salt, up to three
 * outputs, each the HMAC of the one before and a counter byte. */
static void hkdf(const uint8_t ck[32], const uint8_t *ikm, size_t n,
                 uint8_t o1[32], uint8_t o2[32], uint8_t *o3)
{
    uint8_t tk[32], buf[33];

    elpis_hmac_sha256(ck, 32, ikm, n, tk);
    buf[0] = 1;
    elpis_hmac_sha256(tk, 32, buf, 1, o1);
    memcpy(buf, o1, 32);
    buf[32] = 2;
    elpis_hmac_sha256(tk, 32, buf, 33, o2);
    if (o3 != NULL) {
        memcpy(buf, o2, 32);
        buf[32] = 3;
        elpis_hmac_sha256(tk, 32, buf, 33, o3);
    }
    elpis_memzero(tk, sizeof tk);
    elpis_memzero(buf, sizeof buf);
}

static void mix_key(elpis_noise_hs_t *hs, const uint8_t *ikm, size_t n)
{
    uint8_t ck[32], k[32];

    hkdf(hs->ck, ikm, n, ck, k, NULL);
    memcpy(hs->ck, ck, 32);
    cs_set(&hs->cs, k);
    elpis_memzero(ck, sizeof ck);
    elpis_memzero(k, sizeof k);
}

static void mix_key_and_hash(elpis_noise_hs_t *hs, const uint8_t *ikm, size_t n)
{
    uint8_t ck[32], th[32], k[32];

    hkdf(hs->ck, ikm, n, ck, th, k);
    memcpy(hs->ck, ck, 32);
    mix_hash(hs, th, 32);
    cs_set(&hs->cs, k);
    elpis_memzero(ck, sizeof ck);
    elpis_memzero(th, sizeof th);
    elpis_memzero(k, sizeof k);
}

/* Every payload in this pattern goes under a key: the PSK sets one first. */
static void encrypt_and_hash(elpis_noise_hs_t *hs, const uint8_t *pt, size_t n,
                             uint8_t *out)
{
    cs_encrypt(&hs->cs, hs->h, 32, pt, n, out);
    mix_hash(hs, out, n + ELPIS_NOISE_TAG);
}

static int decrypt_and_hash(elpis_noise_hs_t *hs, const uint8_t *ct, size_t n,
                            uint8_t *out)
{
    if (cs_decrypt(&hs->cs, hs->h, 32, ct, n, out) != ELPIS_OK)
        return ELPIS_ERR;
    mix_hash(hs, ct, n);
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* HandshakeState                                                      */
/* ------------------------------------------------------------------ */

void elpis_noise_init(elpis_noise_hs_t *hs, int initiator,
                      const uint8_t psk[ELPIS_NOISE_KEY],
                      const uint8_t *prologue, size_t prologue_len)
{
    memset(hs, 0, sizeof *hs);
    /* The name is longer than a hash, so it is hashed rather than padded. */
    elpis_sha256(k_protocol, sizeof k_protocol - 1u, hs->h);
    memcpy(hs->ck, hs->h, 32);
    mix_hash(hs, prologue, prologue_len);
    memcpy(hs->psk, psk, ELPIS_NOISE_KEY);
    hs->initiator = initiator ? 1u : 0u;
}

void elpis_noise_set_ephemeral(elpis_noise_hs_t *hs, const uint8_t priv[32])
{
    memcpy(hs->e_priv, priv, 32);
    elpis_x25519_base(hs->e_pub, hs->e_priv);
    hs->have_e = 1;
}

/* The "e" token, on the writing side: with a PSK it is mixed into the key
 * as well as the hash, so message 1's payload depends on it. */
static void token_e_write(elpis_noise_hs_t *hs, uint8_t *out)
{
    if (!hs->have_e) {
        elpis_random_bytes(hs->e_priv, 32);
        elpis_x25519_base(hs->e_pub, hs->e_priv);
        hs->have_e = 1;
    }
    memcpy(out, hs->e_pub, 32);
    mix_hash(hs, hs->e_pub, 32);
    mix_key(hs, hs->e_pub, 32);
}

static void token_e_read(elpis_noise_hs_t *hs, const uint8_t *in)
{
    memcpy(hs->re, in, 32);
    mix_hash(hs, hs->re, 32);
    mix_key(hs, hs->re, 32);
}

static int token_ee(elpis_noise_hs_t *hs)
{
    uint8_t shared[32];
    int rc;

    rc = elpis_x25519(shared, hs->e_priv, hs->re);
    if (rc == ELPIS_OK)
        mix_key(hs, shared, 32);
    elpis_memzero(shared, sizeof shared);
    return rc;
}

int elpis_noise_write(elpis_noise_hs_t *hs, const uint8_t *payload,
                      size_t plen, uint8_t *out, size_t cap, size_t *outlen)
{
    /* The initiator writes message 1, the responder message 2. */
    if (hs->step != (hs->initiator ? 0u : 1u) ||
        cap < plen + ELPIS_NOISE_HS_OVERHEAD)
        return ELPIS_ERR;

    if (hs->step == 0) {
        mix_key_and_hash(hs, hs->psk, ELPIS_NOISE_KEY);     /* psk */
        token_e_write(hs, out);                              /* e   */
    } else {
        token_e_write(hs, out);                              /* e   */
        if (token_ee(hs) != ELPIS_OK)                        /* ee  */
            return ELPIS_ERR;
    }
    encrypt_and_hash(hs, payload, plen, out + 32);
    *outlen = plen + ELPIS_NOISE_HS_OVERHEAD;
    hs->step++;
    return ELPIS_OK;
}

int elpis_noise_read(elpis_noise_hs_t *hs, const uint8_t *msg, size_t len,
                     uint8_t *payload, size_t cap, size_t *plen)
{
    if (hs->step != (hs->initiator ? 1u : 0u) ||
        len < ELPIS_NOISE_HS_OVERHEAD ||
        cap < len - ELPIS_NOISE_HS_OVERHEAD)
        return ELPIS_ERR;

    if (hs->step == 0) {
        mix_key_and_hash(hs, hs->psk, ELPIS_NOISE_KEY);     /* psk */
        token_e_read(hs, msg);                               /* e   */
    } else {
        token_e_read(hs, msg);                               /* e   */
        if (token_ee(hs) != ELPIS_OK)                        /* ee  */
            return ELPIS_ERR;
    }
    if (decrypt_and_hash(hs, msg + 32, len - 32, payload) != ELPIS_OK)
        return ELPIS_ERR;
    *plen = len - ELPIS_NOISE_HS_OVERHEAD;
    hs->step++;
    return ELPIS_OK;
}

void elpis_noise_split(elpis_noise_hs_t *hs, elpis_noise_cs_t *send,
                       elpis_noise_cs_t *recv)
{
    static const uint8_t none[1] = { 0 };
    uint8_t k1[32], k2[32];

    hkdf(hs->ck, none, 0, k1, k2, NULL);        /* zero-length input */
    /* The first key carries initiator to responder. */
    cs_set(hs->initiator ? send : recv, k1);
    cs_set(hs->initiator ? recv : send, k2);
    elpis_memzero(k1, sizeof k1);
    elpis_memzero(k2, sizeof k2);
    elpis_noise_wipe(hs);
}

void elpis_noise_encrypt(elpis_noise_cs_t *cs, const uint8_t *pt, size_t n,
                         uint8_t *out)
{
    cs_encrypt(cs, NULL, 0, pt, n, out);
}

int elpis_noise_decrypt(elpis_noise_cs_t *cs, const uint8_t *ct, size_t n,
                        uint8_t *out)
{
    return cs_decrypt(cs, NULL, 0, ct, n, out);
}

void elpis_noise_wipe(elpis_noise_hs_t *hs)
{
    elpis_memzero(hs, sizeof *hs);
}
