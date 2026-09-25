/*
 * elpis/crypto.h -- the verification primitives DNSSEC needs, and the
 * cipher and key agreement the mesh needs.
 *
 * Everything here is self-contained so the binary links statically without
 * OpenSSL.  For DNSSEC the resolver only ever verifies: no signing and no
 * long-term private keys.  (Ed25519 signing exists for the licence issuing
 * tool, behind ELPIS_ED25519_SIGN, and is not compiled into bin/elpis.)
 * Those inputs are public data, so the verification routines are written
 * for clarity and bounds safety rather than constant time -- with one
 * exception, the final signature comparisons, which use a constant-time
 * compare out of habit rather than necessity.  The mesh primitives at the
 * end hold secrets and are constant time; they agree keys and encrypt, and
 * sign nothing.
 */
#ifndef ELPIS_CRYPTO_H
#define ELPIS_CRYPTO_H

#include "elpis/common.h"

/* ---- SHA-1 (RFC 3110, still required for DS digest type 1) -------- */
typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t  buf[64];
    unsigned n;
} elpis_sha1_t;

void elpis_sha1_init(elpis_sha1_t *c);
void elpis_sha1_update(elpis_sha1_t *c, const void *p, size_t n);
void elpis_sha1_final(elpis_sha1_t *c, uint8_t out[20]);
void elpis_sha1(const void *p, size_t n, uint8_t out[20]);

/* ---- SHA-224/256 -------------------------------------------------- */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    unsigned n;
    unsigned outlen;
} elpis_sha256_t;

void elpis_sha256_init(elpis_sha256_t *c);
void elpis_sha256_update(elpis_sha256_t *c, const void *p, size_t n);
void elpis_sha256_final(elpis_sha256_t *c, uint8_t *out);
void elpis_sha256(const void *p, size_t n, uint8_t out[32]);

/* HMAC-SHA-256 (RFC 2104) and PBKDF2 (RFC 8018), for the status page's
 * password only.  Nothing in the resolver's own protocol work uses them. */
void elpis_hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen, uint8_t out[32]);
void elpis_pbkdf2_sha256(const char *pass, size_t passlen,
                         const uint8_t *salt, size_t saltlen,
                         uint32_t iters, uint8_t *out, size_t outlen);

/* ---- SHA-384/512 -------------------------------------------------- */
typedef struct {
    uint64_t h[8];
    uint64_t lenlo, lenhi;
    uint8_t  buf[128];
    unsigned n;
    unsigned outlen;
} elpis_sha512_t;

void elpis_sha512_init(elpis_sha512_t *c);
void elpis_sha384_init(elpis_sha512_t *c);
void elpis_sha512_update(elpis_sha512_t *c, const void *p, size_t n);
void elpis_sha512_final(elpis_sha512_t *c, uint8_t *out);
void elpis_sha512(const void *p, size_t n, uint8_t out[64]);
void elpis_sha384(const void *p, size_t n, uint8_t out[48]);

/* Dispatch by DNSSEC digest / hash identifier. */
#define ELPIS_HASH_SHA1   1
#define ELPIS_HASH_SHA256 2
#define ELPIS_HASH_SHA384 3
#define ELPIS_HASH_SHA512 4
size_t elpis_hash_len(int alg);
int    elpis_hash(int alg, const void *p, size_t n, uint8_t *out);

/* ---- Keccak: SHA3 and SHAKE (needed by ML-DSA) -------------------- */
typedef struct {
    uint64_t st[25];
    unsigned rate;      /* bytes absorbed per permutation */
    unsigned pos;
    uint8_t  pad;
    uint8_t  squeezing;
} elpis_keccak_t;

void elpis_keccak_init(elpis_keccak_t *c, unsigned rate, uint8_t pad);
void elpis_keccak_absorb(elpis_keccak_t *c, const void *p, size_t n);
void elpis_keccak_squeeze(elpis_keccak_t *c, uint8_t *out, size_t n);

void elpis_shake128_init(elpis_keccak_t *c);
void elpis_shake256_init(elpis_keccak_t *c);
void elpis_shake256(const void *p, size_t n, uint8_t *out, size_t outlen);
void elpis_sha3_256(const void *p, size_t n, uint8_t out[32]);
void elpis_sha3_512(const void *p, size_t n, uint8_t out[64]);

/* ---- RSA (RFC 3110 / RFC 5702) ------------------------------------ */
/*
 * `key` is the DNSKEY rdata public key: exponent length prefix, exponent,
 * then modulus.  `hash_alg` is one of ELPIS_HASH_*.  Returns 1 on a valid
 * PKCS#1 v1.5 signature, 0 otherwise.
 */
int elpis_rsa_verify(const uint8_t *key, size_t keylen,
                     const uint8_t *sig, size_t siglen,
                     const uint8_t *hash, size_t hashlen, int hash_alg);

/* ---- ECDSA (RFC 6605) --------------------------------------------- */
#define ELPIS_CURVE_P256 1
#define ELPIS_CURVE_P384 2

/*
 * `pub` is the uncompressed point without the 0x04 prefix, as DNSKEY carries
 * it (64 bytes for P-256, 96 for P-384).  `sig` is r||s, fixed width.
 */
int elpis_ecdsa_verify(int curve, const uint8_t *pub, size_t publen,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *hash, size_t hashlen);

/* ---- Ed25519 (RFC 8080) ------------------------------------------- */
#ifdef ELPIS_ED25519_SIGN
/* Signing is compiled only into the licence tool and the tests -- never into
 * the resolver, which has no business holding a signing routine. */
int elpis_ed25519_pubkey(const uint8_t sk[32], uint8_t pk[32]);
int elpis_ed25519_sign(const uint8_t sk[32], const uint8_t *m, size_t mlen,
                       uint8_t sig[64]);
#endif

int elpis_ed25519_verify(const uint8_t pk[32], const uint8_t *m, size_t mlen,
                         const uint8_t sig[64]);

/* ---- ML-DSA (FIPS 204) -------------------------------------------- */
#define ELPIS_MLDSA44_PK_BYTES  1312
#define ELPIS_MLDSA44_SIG_BYTES 2420
#define ELPIS_MLDSA65_PK_BYTES  1952
#define ELPIS_MLDSA65_SIG_BYTES 3309
#define ELPIS_MLDSA87_PK_BYTES  2592
#define ELPIS_MLDSA87_SIG_BYTES 4627

#define ELPIS_MLDSA_44 44
#define ELPIS_MLDSA_65 65
#define ELPIS_MLDSA_87 87

/*
 * Pure ML-DSA verification (FIPS 204 Algorithm 3, ML-DSA.Verify) with the
 * empty context string, which is what draft-ietf-dnsop-dnssec-mldsa uses.
 * Returns 1 when the signature is valid.
 */
int elpis_mldsa_verify(int variant, const uint8_t *pk, size_t pklen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *sig, size_t siglen);

size_t elpis_mldsa_pk_bytes(int variant);
size_t elpis_mldsa_sig_bytes(int variant);

/* ---- randomness ---------------------------------------------------- */
void     elpis_random_init(void);
void     elpis_random_reseed(void);

/* ---- secrets: the mesh (x25519.c, chachapoly.c) --------------------- */
/*
 * Everything above verifies public data.  These are the exception: the mesh
 * keeps a pre-shared key and makes session keys, so they run in constant
 * time, and what held a secret is wiped with elpis_memzero().
 */
void elpis_memzero(void *p, size_t n);
/* 1 when equal; takes the same time wherever the first difference is. */
int  elpis_ct_eq(const void *a, const void *b, size_t n);

/* RFC 7748.  ELPIS_ERR when the result is all zeros (a low-order point). */
int  elpis_x25519(uint8_t out[32], const uint8_t scalar[32],
                  const uint8_t point[32]);
int  elpis_x25519_base(uint8_t pub[32], const uint8_t secret[32]);

/* RFC 8439. */
void elpis_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                        uint32_t counter, const uint8_t *in, uint8_t *out,
                        size_t n);
void elpis_poly1305(const uint8_t key[32], const uint8_t *m, size_t n,
                    uint8_t tag[16]);
/* `out` gets ptlen + 16 bytes: the ciphertext, then the tag. */
void elpis_aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *pt, size_t ptlen, uint8_t *out);
/* `out` gets ctlen - 16 bytes, and only when the tag is right. */
int  elpis_aead_open(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *ad, size_t adlen,
                     const uint8_t *ct, size_t ctlen, uint8_t *out);

#endif /* ELPIS_CRYPTO_H */
