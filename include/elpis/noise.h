/*
 * elpis/noise.h -- the mesh handshake: Noise_NNpsk0_25519_ChaChaPoly_SHA256.
 *
 * Two messages, then a key each way:
 *
 *   -> psk, e        the initiator's ephemeral key, under a key from the PSK
 *   <- e, ee         the responder's, and a Diffie-Hellman between the two
 *
 * Knowing the pre-shared key is the whole of the authentication: every
 * instance one operator runs holds the same one, and a peer without it
 * cannot complete message 1.  The session keys come from both the ephemeral
 * Diffie-Hellman, for forward secrecy, and the PSK, which Noise mixes into
 * the chaining key.  That second part is the post-quantum hedge: an attacker
 * who records a session and later breaks X25519 with a quantum computer still
 * has to know the PSK to get at the keys.
 *
 * Nothing is signed.  Pure state, no I/O; mesh.c moves the bytes.
 */
#ifndef ELPIS_NOISE_H
#define ELPIS_NOISE_H

#include "elpis/common.h"

#define ELPIS_NOISE_KEY  32
#define ELPIS_NOISE_TAG  16
/* What each handshake message adds to its payload: an ephemeral key and a
 * tag. */
#define ELPIS_NOISE_HS_OVERHEAD (32 + ELPIS_NOISE_TAG)

typedef struct {
    uint8_t  k[ELPIS_NOISE_KEY];
    uint64_t n;
    int      has_key;
} elpis_noise_cs_t;

typedef struct {
    elpis_noise_cs_t cs;
    uint8_t  ck[32];
    uint8_t  h[32];
    uint8_t  e_priv[32], e_pub[32];
    uint8_t  re[32];
    uint8_t  psk[ELPIS_NOISE_KEY];
    unsigned initiator : 1;
    unsigned have_e    : 1;
    unsigned step;              /* handshake messages done, 0..2 */
} elpis_noise_hs_t;

void elpis_noise_init(elpis_noise_hs_t *hs, int initiator,
                      const uint8_t psk[ELPIS_NOISE_KEY],
                      const uint8_t *prologue, size_t prologue_len);
/* A fixed ephemeral key instead of a random one: for the test vectors. */
void elpis_noise_set_ephemeral(elpis_noise_hs_t *hs, const uint8_t priv[32]);

/*
 * Write this side's next handshake message, carrying `payload`; `out` needs
 * plen + ELPIS_NOISE_HS_OVERHEAD bytes.  Read the other side's, and get its
 * payload back in `payload` (len - ELPIS_NOISE_HS_OVERHEAD bytes).  Either
 * returns ELPIS_ERR out of turn or on anything that does not check out, and
 * the handshake is then dead.
 */
int  elpis_noise_write(elpis_noise_hs_t *hs, const uint8_t *payload,
                       size_t plen, uint8_t *out, size_t cap, size_t *outlen);
int  elpis_noise_read(elpis_noise_hs_t *hs, const uint8_t *msg, size_t len,
                      uint8_t *payload, size_t cap, size_t *plen);
ELPIS_INLINE int elpis_noise_done(const elpis_noise_hs_t *hs)
{
    return hs->step == 2;
}

/* After both messages: this side's sending and receiving keys.  The
 * handshake state is wiped. */
void elpis_noise_split(elpis_noise_hs_t *hs, elpis_noise_cs_t *send,
                       elpis_noise_cs_t *recv);

/* Transport.  `out` needs n + ELPIS_NOISE_TAG bytes to encrypt into, and
 * n - ELPIS_NOISE_TAG to decrypt into.  Messages must be opened in the order
 * they were sealed: each uses the next nonce. */
void elpis_noise_encrypt(elpis_noise_cs_t *cs, const uint8_t *pt, size_t n,
                         uint8_t *out);
int  elpis_noise_decrypt(elpis_noise_cs_t *cs, const uint8_t *ct, size_t n,
                         uint8_t *out);

void elpis_noise_wipe(elpis_noise_hs_t *hs);

#endif /* ELPIS_NOISE_H */
