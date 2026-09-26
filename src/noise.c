/*
 * noise.c -- the mesh handshakes: Noise NNpsk0 and XXpsk0, over X25519,
 * ChaChaPoly and SHA256.
 *
 * Only those two patterns, from the Noise spec (revision 34), each a short
 * table of tokens per message.  See elpis/noise.h.
 */
#include "elpis/noise.h"
#include "elpis/crypto.h"
#include "elpis/util.h"

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

enum { T_END, T_PSK, T_E, T_S, T_EE, T_ES, T_SE };

/* The patterns, one row of tokens per message; the initiator writes the
 * even-numbered messages. */
static const uint8_t k_nn[2][5] = {
    { T_PSK, T_E, T_END },
    { T_E, T_EE, T_END }
};
static const uint8_t k_xx[3][5] = {
    { T_PSK, T_E, T_END },
    { T_E, T_EE, T_S, T_ES, T_END },
    { T_S, T_SE, T_END }
};

static const uint8_t *tokens(const elpis_noise_hs_t *hs)
{
    if (hs->pattern == ELPIS_NOISE_XX_PSK0)
        return hs->step < 3 ? k_xx[hs->step] : NULL;
    return hs->step < 2 ? k_nn[hs->step] : NULL;
}

/* Whose turn: the initiator's on even steps. */
static int my_turn(const elpis_noise_hs_t *hs)
{
    return tokens(hs) != NULL && ((hs->step & 1u) == 0) == (hs->initiator != 0);
}

/* The bytes a message's tokens add, and the payload's tag. */
static size_t tokens_len(const uint8_t *t)
{
    size_t n = ELPIS_NOISE_TAG;
    for (; *t != T_END; t++)
        n += *t == T_E ? 32u : *t == T_S ? 32u + ELPIS_NOISE_TAG : 0u;
    return n;
}

size_t elpis_noise_overhead(const elpis_noise_hs_t *hs)
{
    return my_turn(hs) ? tokens_len(tokens(hs)) : 0;
}

void elpis_noise_init(elpis_noise_hs_t *hs, unsigned pattern, int initiator,
                      const uint8_t psk[ELPIS_NOISE_KEY],
                      const uint8_t *prologue, size_t prologue_len)
{
    static const char k_nn_name[] = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
    static const char k_xx_name[] = "Noise_XXpsk0_25519_ChaChaPoly_SHA256";
    const char *name = pattern == ELPIS_NOISE_XX_PSK0 ? k_xx_name : k_nn_name;

    memset(hs, 0, sizeof *hs);
    /* The name is longer than a hash, so it is hashed rather than padded. */
    elpis_sha256(name, strlen(name), hs->h);
    memcpy(hs->ck, hs->h, 32);
    mix_hash(hs, prologue, prologue_len);
    memcpy(hs->psk, psk, ELPIS_NOISE_KEY);
    hs->pattern = pattern;
    hs->initiator = initiator ? 1u : 0u;
}

void elpis_noise_set_ephemeral(elpis_noise_hs_t *hs, const uint8_t priv[32])
{
    memcpy(hs->e_priv, priv, 32);
    elpis_x25519_base(hs->e_pub, hs->e_priv);
    hs->have_e = 1;
}

void elpis_noise_set_static(elpis_noise_hs_t *hs, const uint8_t priv[32])
{
    memcpy(hs->s_priv, priv, 32);
    elpis_x25519_base(hs->s_pub, hs->s_priv);
    hs->have_s = 1;
}

const uint8_t *elpis_noise_remote_static(const elpis_noise_hs_t *hs)
{
    return hs->have_rs ? hs->rs : NULL;
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

static int mix_dh(elpis_noise_hs_t *hs, const uint8_t priv[32],
                  const uint8_t pub[32])
{
    uint8_t shared[32];
    int rc;

    rc = elpis_x25519(shared, priv, pub);
    if (rc == ELPIS_OK)
        mix_key(hs, shared, 32);
    elpis_memzero(shared, sizeof shared);
    return rc;
}

/* ee, es, se: which keys meet depends on which side this is. */
static int token_dh(elpis_noise_hs_t *hs, uint8_t t)
{
    switch (t) {
    case T_EE:
        return mix_dh(hs, hs->e_priv, hs->re);
    case T_ES:
        return hs->initiator ? mix_dh(hs, hs->e_priv, hs->rs)
                             : mix_dh(hs, hs->s_priv, hs->re);
    case T_SE:
        return hs->initiator ? mix_dh(hs, hs->s_priv, hs->re)
                             : mix_dh(hs, hs->e_priv, hs->rs);
    default:
        return ELPIS_ERR;
    }
}

int elpis_noise_write(elpis_noise_hs_t *hs, const uint8_t *payload,
                      size_t plen, uint8_t *out, size_t cap, size_t *outlen)
{
    const uint8_t *t = tokens(hs);
    size_t off = 0;

    if (!my_turn(hs) || cap < plen + tokens_len(t))
        return ELPIS_ERR;
    for (; *t != T_END; t++) {
        switch (*t) {
        case T_PSK:
            mix_key_and_hash(hs, hs->psk, ELPIS_NOISE_KEY);
            break;
        case T_E:
            token_e_write(hs, out + off);
            off += 32;
            break;
        case T_S:
            if (!hs->have_s)
                return ELPIS_ERR;
            encrypt_and_hash(hs, hs->s_pub, 32, out + off);
            off += 32 + ELPIS_NOISE_TAG;
            break;
        default:
            if (token_dh(hs, *t) != ELPIS_OK)
                return ELPIS_ERR;
            break;
        }
    }
    encrypt_and_hash(hs, payload, plen, out + off);
    *outlen = off + plen + ELPIS_NOISE_TAG;
    hs->step++;
    return ELPIS_OK;
}

int elpis_noise_read(elpis_noise_hs_t *hs, const uint8_t *msg, size_t len,
                     uint8_t *payload, size_t cap, size_t *plen)
{
    const uint8_t *t = tokens(hs);
    size_t off = 0, over;

    if (t == NULL || my_turn(hs))
        return ELPIS_ERR;
    over = tokens_len(t);
    if (len < over || cap < len - over)
        return ELPIS_ERR;
    for (; *t != T_END; t++) {
        switch (*t) {
        case T_PSK:
            mix_key_and_hash(hs, hs->psk, ELPIS_NOISE_KEY);
            break;
        case T_E:
            token_e_read(hs, msg + off);
            off += 32;
            break;
        case T_S:
            if (decrypt_and_hash(hs, msg + off, 32 + ELPIS_NOISE_TAG,
                                 hs->rs) != ELPIS_OK)
                return ELPIS_ERR;
            hs->have_rs = 1;
            off += 32 + ELPIS_NOISE_TAG;
            break;
        default:
            if (token_dh(hs, *t) != ELPIS_OK)
                return ELPIS_ERR;
            break;
        }
    }
    if (decrypt_and_hash(hs, msg + off, len - off, payload) != ELPIS_OK)
        return ELPIS_ERR;
    *plen = len - over;
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
