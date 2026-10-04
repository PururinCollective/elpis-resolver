/*
 * hkdf.c -- HKDF-SHA-256 (RFC 5869) and TLS 1.3's HKDF-Expand-Label.
 *
 * Every TLS 1.3 secret comes out of these: handshake and traffic secrets,
 * then each record key and IV.  HMAC is built here on the streaming SHA-256
 * rather than through elpis_hmac_sha256(), because HKDF's message is three
 * pieces (previous block, info, counter) and this avoids gluing them into a
 * buffer of whatever size the info happens to be.
 */
#include "elpis/tlscrypto.h"
#include "elpis/crypto.h"

typedef struct {
    elpis_sha256_t inner, outer;
} hmac_t;

static void hmac_init(hmac_t *h, const uint8_t *key, size_t keylen)
{
    uint8_t k[64], pad[64];
    unsigned i;

    memset(k, 0, sizeof k);
    if (keylen > sizeof k)
        elpis_sha256(key, keylen, k);
    else if (keylen > 0)
        memcpy(k, key, keylen);

    for (i = 0; i < sizeof k; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36u);
    elpis_sha256_init(&h->inner);
    elpis_sha256_update(&h->inner, pad, sizeof pad);

    for (i = 0; i < sizeof k; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5cu);
    elpis_sha256_init(&h->outer);
    elpis_sha256_update(&h->outer, pad, sizeof pad);

    elpis_wipe(k, sizeof k);
    elpis_wipe(pad, sizeof pad);
}

static void hmac_final(hmac_t *h, uint8_t out[32])
{
    uint8_t inner[32];

    elpis_sha256_final(&h->inner, inner);
    elpis_sha256_update(&h->outer, inner, sizeof inner);
    elpis_sha256_final(&h->outer, out);
    elpis_wipe(inner, sizeof inner);
    elpis_wipe(h, sizeof *h);
}

void elpis_hkdf_extract(const uint8_t *salt, size_t saltlen,
                        const uint8_t *ikm, size_t ikmlen, uint8_t prk[32])
{
    hmac_t h;

    /* No salt means HashLen zeros, and HMAC pads a short key with zeros
     * anyway, so an empty key gives the same result. */
    hmac_init(&h, salt, saltlen);
    if (ikmlen > 0)
        elpis_sha256_update(&h.inner, ikm, ikmlen);
    hmac_final(&h, prk);
}

int elpis_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                      size_t infolen, uint8_t *out, size_t outlen)
{
    uint8_t t[32];
    uint8_t ctr = 0;
    size_t done = 0;

    if (outlen > 255u * 32u)
        return -1;

    while (done < outlen) {
        hmac_t h;
        size_t take;

        hmac_init(&h, prk, 32);
        if (ctr > 0)
            elpis_sha256_update(&h.inner, t, sizeof t);
        if (infolen > 0)                /* info may be NULL when empty */
            elpis_sha256_update(&h.inner, info, infolen);
        ctr++;
        elpis_sha256_update(&h.inner, &ctr, 1);
        hmac_final(&h, t);

        take = outlen - done < sizeof t ? outlen - done : sizeof t;
        memcpy(out + done, t, take);
        done += take;
    }
    elpis_wipe(t, sizeof t);
    return 0;
}

int elpis_hkdf_expand_label(const uint8_t secret[32], const char *label,
                            const uint8_t *ctx, size_t ctxlen,
                            uint8_t *out, size_t outlen)
{
    /*
     * struct {
     *     uint16 length;
     *     opaque label<7..255> = "tls13 " + Label;
     *     opaque context<0..255>;
     * } HkdfLabel;
     */
    static const char prefix[] = "tls13 ";
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t llen = strlen(label), plen = sizeof prefix - 1u, n = 0;
    int rc;

    if (outlen > 0xffffu || plen + llen > 255u || ctxlen > 255u)
        return -1;

    elpis_put16(info, (uint16_t)outlen);
    n = 2;
    info[n++] = (uint8_t)(plen + llen);
    memcpy(info + n, prefix, plen);
    n += plen;
    memcpy(info + n, label, llen);
    n += llen;
    info[n++] = (uint8_t)ctxlen;
    if (ctxlen > 0)
        memcpy(info + n, ctx, ctxlen);
    n += ctxlen;

    rc = elpis_hkdf_expand(secret, info, n, out, outlen);
    elpis_wipe(info, n);
    return rc;
}
