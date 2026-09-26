/*
 * elpis/noise.h -- the mesh handshakes, from the Noise protocol framework.
 *
 * Noise_NNpsk0_25519_ChaChaPoly_SHA256: two messages, then a key each way.
 *
 *   -> psk, e        the initiator's ephemeral key, under a key from the PSK
 *   <- e, ee         the responder's, and a Diffie-Hellman between the two
 *
 * Noise_XXpsk0_25519_ChaChaPoly_SHA256, for a mesh that requires licensed
 * instances: the same start, and then each side's static key, encrypted,
 * with a Diffie-Hellman that only the holder of its private half can do.
 *
 *   -> psk, e
 *   <- e, ee, s, es
 *   -> s, se
 *
 * In both, a peer without the pre-shared key cannot complete message 1:
 * every instance one operator runs holds the same one.  In NN that is the
 * whole of the authentication; in XX each side also proves it holds the
 * private half of its static key, which mesh.c checks against a certificate
 * from the licence issuer.  The session keys come from both the ephemeral
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
/* What each NN handshake message adds to its payload: an ephemeral key and
 * a tag.  XX messages add more; ask elpis_noise_overhead(). */
#define ELPIS_NOISE_HS_OVERHEAD (32 + ELPIS_NOISE_TAG)

#define ELPIS_NOISE_NN_PSK0 0
#define ELPIS_NOISE_XX_PSK0 1

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
    uint8_t  s_priv[32], s_pub[32];
    uint8_t  re[32], rs[32];
    uint8_t  psk[ELPIS_NOISE_KEY];
    unsigned pattern;
    unsigned initiator : 1;
    unsigned have_e    : 1;
    unsigned have_s    : 1;
    unsigned have_rs   : 1;
    unsigned step;              /* handshake messages done */
} elpis_noise_hs_t;

void elpis_noise_init(elpis_noise_hs_t *hs, unsigned pattern, int initiator,
                      const uint8_t psk[ELPIS_NOISE_KEY],
                      const uint8_t *prologue, size_t prologue_len);
/* A fixed ephemeral key instead of a random one: for the test vectors. */
void elpis_noise_set_ephemeral(elpis_noise_hs_t *hs, const uint8_t priv[32]);
/* XX: this side's static key. */
void elpis_noise_set_static(elpis_noise_hs_t *hs, const uint8_t priv[32]);
/* XX: the other side's static key, once the message carrying it is read;
 * NULL before. */
const uint8_t *elpis_noise_remote_static(const elpis_noise_hs_t *hs);
/* What this side's next message adds to its payload, 0 when it is not this
 * side's turn. */
size_t elpis_noise_overhead(const elpis_noise_hs_t *hs);

/*
 * Write this side's next handshake message, carrying `payload`; `out` needs
 * plen + elpis_noise_overhead() bytes.  Read the other side's, and get its
 * payload back in `payload`.  Either returns ELPIS_ERR out of turn or on
 * anything that does not check out, and the handshake is then dead.
 */
int  elpis_noise_write(elpis_noise_hs_t *hs, const uint8_t *payload,
                       size_t plen, uint8_t *out, size_t cap, size_t *outlen);
int  elpis_noise_read(elpis_noise_hs_t *hs, const uint8_t *msg, size_t len,
                      uint8_t *payload, size_t cap, size_t *plen);
ELPIS_INLINE int elpis_noise_done(const elpis_noise_hs_t *hs)
{
    return hs->step == (hs->pattern == ELPIS_NOISE_XX_PSK0 ? 3u : 2u);
}

/* After the last message: this side's sending and receiving keys.  The
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
