/*
 * aes.h -- AES-128 and GHASH, the two halves of AES-128-GCM, in two builds:
 * portable C, and AES-NI with PCLMULQDQ on x86.  Internal to src/crypto;
 * aead.c picks one at init and the rest of the tree sees only elpis_aead_*.
 *
 * Both take the same round-key layout -- eleven 16-byte round keys in FIPS
 * 197 byte order -- and the same GHASH convention: y is the running 16-byte
 * hash, `data` is absorbed in 16-byte blocks with a short last block padded
 * with zeros.
 */
#ifndef ELPIS_CRYPTO_AES_H
#define ELPIS_CRYPTO_AES_H

#include "elpis/common.h"

void elpis_aes_soft_expand(uint8_t rk[176], const uint8_t key[16]);
void elpis_aes_soft_encrypt(const uint8_t rk[176], const uint8_t in[16],
                            uint8_t out[16]);
/* CTR mode: block i is encrypted from `ctr` with its last 32 bits + i. */
void elpis_aes_soft_ctr(const uint8_t rk[176], const uint8_t ctr[16],
                        const uint8_t *in, uint8_t *out, size_t n);
void elpis_ghash_soft(const uint8_t h[16], uint8_t y[16],
                      const uint8_t *data, size_t n);

#if defined(ELPIS_ARCH_X86)
void elpis_aes_ni_expand(uint8_t rk[176], const uint8_t key[16]);
void elpis_aes_ni_encrypt(const uint8_t rk[176], const uint8_t in[16],
                          uint8_t out[16]);
void elpis_aes_ni_ctr(const uint8_t rk[176], const uint8_t ctr[16],
                      const uint8_t *in, uint8_t *out, size_t n);
void elpis_ghash_ni(const uint8_t h[16], uint8_t y[16],
                    const uint8_t *data, size_t n);
#endif

#endif /* ELPIS_CRYPTO_AES_H */
