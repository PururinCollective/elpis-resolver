/*
 * chacha20.c -- the ChaCha20 stream cipher (RFC 8439).
 *
 * The block function serves two masters: rand.c draws the resolver's random
 * numbers from it, and the TLS record layer encrypts with it.  It is add,
 * rotate and xor on 32-bit words and nothing else, so it runs in constant
 * time as written.
 */
#include "elpis/tlscrypto.h"

#define QR(a, b, c, d)                              \
    do {                                            \
        a += b; d ^= a; d = elpis_rotl32(d, 16);    \
        c += d; b ^= c; b = elpis_rotl32(b, 12);    \
        a += b; d ^= a; d = elpis_rotl32(d, 8);     \
        c += d; b ^= c; b = elpis_rotl32(b, 7);     \
    } while (0)

void elpis_chacha20_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;

    memcpy(x, in, sizeof x);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    /* ChaCha serialises little-endian. */
    for (i = 0; i < 16; i++)
        elpis_put32le(out + i * 4, x[i] + in[i]);
}

void elpis_chacha20_xor(const uint8_t key[32], uint32_t counter,
                        const uint8_t nonce[12], const uint8_t *in,
                        uint8_t *out, size_t n)
{
    uint32_t st[16];
    uint8_t ks[64];
    int i;

    st[0] = 0x61707865u;
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    for (i = 0; i < 8; i++)
        st[4 + i] = elpis_get32le(key + i * 4);
    st[12] = counter;
    for (i = 0; i < 3; i++)
        st[13 + i] = elpis_get32le(nonce + i * 4);

    while (n > 0) {
        size_t take = n < sizeof ks ? n : sizeof ks;
        size_t j;

        elpis_chacha20_block(st, ks);
        for (j = 0; j < take; j++)
            out[j] = (uint8_t)(in[j] ^ ks[j]);
        st[12]++;
        in  += take;
        out += take;
        n   -= take;
    }
    elpis_wipe(st, sizeof st);
    elpis_wipe(ks, sizeof ks);
}
