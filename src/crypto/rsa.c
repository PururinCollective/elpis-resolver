/*
 * rsa.c -- RSASSA-PKCS1-v1_5 verification for DNSSEC algorithms 5, 7, 8, 10.
 */
#include "elpis/crypto.h"
#include "bn.h"

/*
 * DNSKEY RSA public key encoding, RFC 3110 section 2:
 *   len == 0  : the next two octets hold the exponent length
 *   otherwise : `len` is the exponent length
 * followed by the exponent then the modulus.
 */
static int rsa_parse(const uint8_t *key, size_t keylen, bn_t *n, bn_t *e)
{
    size_t elen, off;

    if (keylen < 3)
        return ELPIS_EFORMAT;

    if (key[0] == 0) {
        elen = (size_t)elpis_get16(key + 1);
        off  = 3;
    } else {
        elen = key[0];
        off  = 1;
    }
    if (elen == 0 || off + elen >= keylen)
        return ELPIS_EFORMAT;

    if (bn_from_bytes(e, key + off, elen) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (bn_from_bytes(n, key + off + elen, keylen - off - elen) != ELPIS_OK)
        return ELPIS_EFORMAT;

    if (bn_is_zero(n) || bn_is_zero(e))
        return ELPIS_EFORMAT;
    /* RFC 8624: refuse keys below 1024 bits and above 4096. */
    if (bn_bits(n) < 1024u || bn_bits(n) > 4096u)
        return ELPIS_EFORMAT;
    if ((n->d[0] & 1u) == 0)
        return ELPIS_EFORMAT;
    return ELPIS_OK;
}

/* DigestInfo DER prefixes from RFC 8017 section 9.2, note 1. */
static const uint8_t di_sha1[] = {
    0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14
};
static const uint8_t di_sha256[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,
    0x05,0x00,0x04,0x20
};
static const uint8_t di_sha384[] = {
    0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,
    0x05,0x00,0x04,0x30
};
static const uint8_t di_sha512[] = {
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,
    0x05,0x00,0x04,0x40
};

static const uint8_t *digest_info(int alg, size_t *len)
{
    switch (alg) {
    case ELPIS_HASH_SHA1:   *len = sizeof di_sha1;   return di_sha1;
    case ELPIS_HASH_SHA256: *len = sizeof di_sha256; return di_sha256;
    case ELPIS_HASH_SHA384: *len = sizeof di_sha384; return di_sha384;
    case ELPIS_HASH_SHA512: *len = sizeof di_sha512; return di_sha512;
    default:                *len = 0;                return NULL;
    }
}

int elpis_rsa_verify(const uint8_t *key, size_t keylen,
                     const uint8_t *sig, size_t siglen,
                     const uint8_t *hash, size_t hashlen, int hash_alg)
{
    bn_t n, e, s, m;
    mont_t ctx;
    uint8_t em[BN_MAX_LIMBS * 4];
    const uint8_t *di;
    size_t dilen, k, i, pslen;

    if (rsa_parse(key, keylen, &n, &e) != ELPIS_OK)
        return 0;

    k = (bn_bits(&n) + 7u) / 8u;
    if (siglen != k || k > sizeof em)
        return 0;                       /* RFC 8017: lengths must match */

    di = digest_info(hash_alg, &dilen);
    if (di == NULL || hashlen != elpis_hash_len(hash_alg))
        return 0;
    /* 0x00 0x01 | PS (>= 8 octets of 0xFF) | 0x00 | DigestInfo | hash */
    if (k < dilen + hashlen + 11u)
        return 0;

    if (bn_from_bytes(&s, sig, siglen) != ELPIS_OK)
        return 0;
    if (bn_cmp(&s, &n) >= 0)
        return 0;                       /* signature out of range */

    if (mont_init(&ctx, &n) != ELPIS_OK)
        return 0;
    bn_modexp(&m, &s, &e, &ctx);

    if (bn_to_bytes(&m, em, k) != ELPIS_OK)
        return 0;

    /* Strict EMSA-PKCS1-v1_5 check; no BER slack, no length guessing. */
    if (em[0] != 0x00 || em[1] != 0x01)
        return 0;
    pslen = k - 3u - dilen - hashlen;
    if (pslen < 8u)
        return 0;
    for (i = 2; i < 2 + pslen; i++)
        if (em[i] != 0xFF)
            return 0;
    if (em[2 + pslen] != 0x00)
        return 0;
    if (memcmp(em + 3 + pslen, di, dilen) != 0)
        return 0;
    if (elpis_ct_memcmp(em + 3 + pslen + dilen, hash, hashlen) != 0)
        return 0;

    return 1;
}
