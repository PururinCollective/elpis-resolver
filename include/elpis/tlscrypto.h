/*
 * elpis/tlscrypto.h -- the primitives a TLS 1.3 client needs.
 *
 * crypto.h is for checking signatures over public data.  These are not: they
 * hold session keys and an ephemeral private key, so everything here runs in
 * constant time -- no branch and no memory index depends on a secret -- and
 * wipes what it has finished with.
 *
 * The set is what opportunistic DNS over TLS to authoritative servers
 * (RFC 9539) needs and no more: X25519 for the key exchange, HKDF-SHA-256 for
 * the TLS 1.3 key schedule, and the two record ciphers a client offers --
 * ChaCha20-Poly1305 first, AES-128-GCM for a server that will not do it.
 * AES runs on AES-NI and PCLMULQDQ where the CPU has them, and otherwise on
 * a portable constant-time version that is slow but correct.
 */
#ifndef ELPIS_TLSCRYPTO_H
#define ELPIS_TLSCRYPTO_H

#include "elpis/common.h"

/* ---- HKDF-SHA-256 (RFC 5869) -------------------------------------- */
void elpis_hkdf_extract(const uint8_t *salt, size_t saltlen,
                        const uint8_t *ikm, size_t ikmlen, uint8_t prk[32]);
/* 0, or -1 when `outlen` is over the 255 * 32 bytes HKDF can produce. */
int  elpis_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                       size_t infolen, uint8_t *out, size_t outlen);
/*
 * TLS 1.3's HKDF-Expand-Label (RFC 8446 section 7.1): `label` without the
 * "tls13 " prefix, which this adds.  -1 when the label, the context or the
 * length will not fit the HkdfLabel structure.
 */
int  elpis_hkdf_expand_label(const uint8_t secret[32], const char *label,
                             const uint8_t *ctx, size_t ctxlen,
                             uint8_t *out, size_t outlen);

/* ---- X25519 (RFC 7748) -------------------------------------------- */
/*
 * out = scalar * point, the scalar clamped as RFC 7748 says.  Returns 0, or
 * -1 when the result is all zeros: the peer sent a point of small order, and
 * RFC 8446 section 7.4.2 says to abort the handshake.
 */
int  elpis_x25519(uint8_t out[32], const uint8_t scalar[32],
                  const uint8_t point[32]);
/* The public key for a private scalar: scalar * 9. */
void elpis_x25519_base(uint8_t pub[32], const uint8_t scalar[32]);

/* ---- ChaCha20 and Poly1305 (RFC 8439) ----------------------------- */
/* One block of the keystream from a full 16-word state.  rand.c uses it too. */
void elpis_chacha20_block(const uint32_t in[16], uint8_t out[64]);
/* out = in XOR keystream(key, nonce), starting at block `counter`.  In place
 * is fine. */
void elpis_chacha20_xor(const uint8_t key[32], uint32_t counter,
                        const uint8_t nonce[12], const uint8_t *in,
                        uint8_t *out, size_t n);

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    unsigned n;
} elpis_poly1305_t;

void elpis_poly1305_init(elpis_poly1305_t *p, const uint8_t key[32]);
void elpis_poly1305_update(elpis_poly1305_t *p, const uint8_t *m, size_t n);
/* Writes the tag and wipes the state. */
void elpis_poly1305_final(elpis_poly1305_t *p, uint8_t tag[16]);

/* ---- AEAD: the TLS 1.3 record ciphers ----------------------------- */
#define ELPIS_AEAD_CHACHA20_POLY1305 1
#define ELPIS_AEAD_AES128_GCM        2

#define ELPIS_AEAD_NONCE_LEN 12
#define ELPIS_AEAD_TAG_LEN   16

typedef struct {
    int     suite;
    int     hw;          /* AES on AES-NI and PCLMULQDQ */
    uint8_t key[32];     /* ChaCha20 key                */
    uint8_t rk[176];     /* AES-128 round keys          */
    uint8_t h[16];       /* GHASH key: AES(K, 0^128)    */
} elpis_aead_t;

/* Key length for a suite, or 0 for one this does not know. */
size_t elpis_aead_key_len(int suite);
/* 0, or -1 for an unknown suite or a key of the wrong length. */
int  elpis_aead_init(elpis_aead_t *a, int suite, const uint8_t *key,
                     size_t keylen);
/* Encrypts n bytes to `out` (in place is fine) and writes the 16-byte tag. */
void elpis_aead_seal(const elpis_aead_t *a, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t n, uint8_t *out,
                     uint8_t tag[16]);
/*
 * Checks the tag first and decrypts only if it holds: 0 with the plaintext in
 * `out`, or -1 with `out` untouched.  In place is fine, and on failure the
 * ciphertext is still there.
 */
int  elpis_aead_open(const elpis_aead_t *a, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, size_t n, const uint8_t tag[16],
                     uint8_t *out);
void elpis_aead_wipe(elpis_aead_t *a);

/* "aes-ni" or "portable": what elpis_aead_init picks for AES-128-GCM. */
const char *elpis_aes_backend(void);
/* For the self-test: 0 makes later inits use the portable AES even where
 * AES-NI is there, so the two can be checked against each other. */
void elpis_aes_use_hw(int on);

#endif /* ELPIS_TLSCRYPTO_H */
