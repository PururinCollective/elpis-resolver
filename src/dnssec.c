/*
 * dnssec.c -- signature verification and the validation state machine.
 *
 * Verification follows RFC 4034 section 3.1.8.1 exactly: the signed data is
 * the RRSIG RDATA up to but not including the signature, followed by the
 * RRset in canonical form -- owner name downcased and fully expanded, records
 * sorted by their canonical RDATA, duplicates removed, and the original TTL
 * from the RRSIG rather than whatever TTL arrived on the wire.
 *
 * Getting any one of those wrong produces a validator that works on most
 * zones and fails mysteriously on a few, so each step is spelled out below
 * rather than folded together.
 */
#include "elpis/dnssec.h"
#include "elpis/resolver.h"
#include "elpis/crypto.h"
#include "elpis/rdata.h"
#include "elpis/log.h"
#include "elpis/util.h"

/* ================================================================== */
/* Algorithm policy                                                    */
/* ================================================================== */

int elpis_alg_hash(const elpis_conf_t *c, uint8_t alg)
{
    if (alg == c->alg_mldsa44 || alg == c->alg_mldsa65 || alg == c->alg_mldsa87)
        return 0;                       /* signs the message directly */

    switch (alg) {
    case ELPIS_ALG_RSASHA1:
    case ELPIS_ALG_RSASHA1_NSEC3_SHA1: return ELPIS_HASH_SHA1;
    case ELPIS_ALG_RSASHA256:          return ELPIS_HASH_SHA256;
    case ELPIS_ALG_RSASHA512:          return ELPIS_HASH_SHA512;
    case ELPIS_ALG_ECDSAP256SHA256:    return ELPIS_HASH_SHA256;
    case ELPIS_ALG_ECDSAP384SHA384:    return ELPIS_HASH_SHA384;
    case ELPIS_ALG_ED25519:            return 0;
    default:                           return -1;
    }
}

int elpis_alg_supported(const elpis_conf_t *c, uint8_t alg)
{
    if (alg == c->alg_mldsa44 || alg == c->alg_mldsa65 || alg == c->alg_mldsa87)
        return 1;
    switch (alg) {
    case ELPIS_ALG_RSASHA1:
    case ELPIS_ALG_RSASHA1_NSEC3_SHA1:
    case ELPIS_ALG_RSASHA256:
    case ELPIS_ALG_RSASHA512:
    case ELPIS_ALG_ECDSAP256SHA256:
    case ELPIS_ALG_ECDSAP384SHA384:
    case ELPIS_ALG_ED25519:
        return 1;
    /*
     * RFC 8624 says MUST NOT for these.  A zone signed only with RSAMD5 or
     * DSA is treated as insecure rather than bogus, which is the outcome the
     * RFC asks for: no false alarm, no false trust.
     */
    default:
        return 0;
    }
}

int elpis_digest_supported(uint8_t digest_type)
{
    return digest_type == ELPIS_DS_SHA256 ||
           digest_type == ELPIS_DS_SHA384 ||
           digest_type == ELPIS_DS_SHA1;
}

static int ds_hash_alg(uint8_t digest_type)
{
    switch (digest_type) {
    case ELPIS_DS_SHA1:   return ELPIS_HASH_SHA1;
    case ELPIS_DS_SHA256: return ELPIS_HASH_SHA256;
    case ELPIS_DS_SHA384: return ELPIS_HASH_SHA384;
    default:              return -1;
    }
}

/* ================================================================== */
/* Key tags and DS matching                                            */
/* ================================================================== */

uint16_t elpis_dnskey_tag(const uint8_t *rdata, size_t len)
{
    uint32_t ac = 0;
    size_t i;

    /* RFC 4034 appendix B.1: algorithm 1 uses a different rule. */
    if (len >= 4 && rdata[3] == ELPIS_ALG_RSAMD5) {
        if (len < 7)
            return 0;
        return (uint16_t)((rdata[len - 3] << 8) | rdata[len - 2]);
    }
    for (i = 0; i < len; i++)
        ac += (i & 1u) ? rdata[i] : ((uint32_t)rdata[i] << 8);
    ac += (ac >> 16) & 0xFFFFu;
    return (uint16_t)(ac & 0xFFFFu);
}

int elpis_ds_matches(const elpis_name_t *owner,
                     const uint8_t *dnskey, size_t keylen,
                     const uint8_t *ds, size_t dslen)
{
    uint16_t ds_tag;
    uint8_t  ds_alg, ds_dt;
    uint8_t  digest[64];
    int halg;
    size_t hlen;
    elpis_name_t canon;

    if (dslen < 5 || keylen < 4)
        return 0;
    ds_tag = elpis_get16(ds);
    ds_alg = ds[2];
    ds_dt  = ds[3];

    if (ds_alg != dnskey[3])
        return 0;
    if (elpis_dnskey_tag(dnskey, keylen) != ds_tag)
        return 0;

    halg = ds_hash_alg(ds_dt);
    if (halg < 0)
        return 0;
    hlen = elpis_hash_len(halg);
    if (dslen - 4u != hlen)
        return 0;

    /* digest = H(canonical owner name | DNSKEY RDATA) */
    canon = *owner;
    elpis_name_lower(&canon);

    switch (halg) {
    case ELPIS_HASH_SHA1: {
        elpis_sha1_t c;
        elpis_sha1_init(&c);
        elpis_sha1_update(&c, canon.d, canon.len);
        elpis_sha1_update(&c, dnskey, keylen);
        elpis_sha1_final(&c, digest);
        break;
    }
    case ELPIS_HASH_SHA256: {
        elpis_sha256_t c;
        elpis_sha256_init(&c);
        elpis_sha256_update(&c, canon.d, canon.len);
        elpis_sha256_update(&c, dnskey, keylen);
        elpis_sha256_final(&c, digest);
        break;
    }
    case ELPIS_HASH_SHA384: {
        elpis_sha512_t c;
        elpis_sha384_init(&c);
        elpis_sha512_update(&c, canon.d, canon.len);
        elpis_sha512_update(&c, dnskey, keylen);
        elpis_sha512_final(&c, digest);
        break;
    }
    default:
        return 0;
    }

    return elpis_ct_memcmp(digest, ds + 4, hlen) == 0;
}

/* ================================================================== */
/* Canonical RRset serialisation                                       */
/* ================================================================== */

#define SIGNBUF_MAX (512u * 1024u)

static ELPIS_TLS uint8_t *g_signbuf;

static uint8_t *signbuf(void)
{
    if (g_signbuf == NULL)
        g_signbuf = (uint8_t *)elpis_malloc(SIGNBUF_MAX);
    return g_signbuf;
}

typedef struct {
    const uint8_t *rd;
    uint16_t       len;
} rditem_t;

static int rd_cmp(const rditem_t *a, const rditem_t *b)
{
    unsigned n = a->len < b->len ? a->len : b->len;
    int c = memcmp(a->rd, b->rd, n);
    if (c != 0)
        return c;
    if (a->len == b->len)
        return 0;
    return a->len < b->len ? -1 : 1;
}

static void rd_sort(rditem_t *v, unsigned n)
{
    unsigned i, j;
    /* Insertion sort: an RRset has tens of records at most. */
    for (i = 1; i < n; i++) {
        rditem_t t = v[i];
        j = i;
        while (j > 0 && rd_cmp(&v[j - 1], &t) > 0) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = t;
    }
}

/*
 * Build the exact byte string that was signed.  Returns its length, or 0 when
 * it would not fit.
 */
static size_t build_signed_data(const elpis_name_t *owner, uint16_t type,
                                uint16_t klass,
                                const uint8_t *const *rd, const uint16_t *rdlen,
                                unsigned count,
                                const uint8_t *sig, size_t siglen,
                                size_t signer_len, uint8_t *out, size_t cap)
{
    size_t o = 0;
    uint32_t orig_ttl;
    uint8_t  labels;
    elpis_name_t canon;
    rditem_t items[ELPIS_RRSET_MAX_RR];
    unsigned i, n = 0;

    if (siglen < 18 + signer_len)
        return 0;

    /* RRSIG RDATA without the signature field. */
    if (o + 18 + signer_len > cap)
        return 0;
    memcpy(out, sig, 18 + signer_len);
    /* The signer name inside the RRSIG is canonicalised too. */
    {
        elpis_name_t sn;
        size_t used;
        if (elpis_name_parse_nocomp(&sn, sig + 18, signer_len, &used) != ELPIS_OK)
            return 0;
        elpis_name_lower(&sn);
        memcpy(out + 18, sn.d, sn.len);
    }
    o = 18 + signer_len;

    orig_ttl = elpis_get32(sig + 4);
    labels   = sig[3];

    /*
     * RFC 4035 section 5.3.2: when the RRSIG's label count is smaller than
     * the owner's, the record was synthesised from a wildcard, and the name
     * that was signed is "*." plus that many trailing labels.
     */
    canon = *owner;
    elpis_name_lower(&canon);
    if (labels < canon.labels) {
        elpis_name_t suffix;
        if (elpis_name_suffix(&canon, labels, &suffix) != 0)
            return 0;
        if (elpis_name_prepend(&canon, (const uint8_t *)"*", 1, &suffix) != ELPIS_OK)
            return 0;
    } else if (labels > canon.labels) {
        return 0;                        /* nonsensical label count */
    }

    for (i = 0; i < count && i < ELPIS_ARRAY_LEN(items); i++) {
        items[n].rd  = rd[i];
        items[n].len = rdlen[i];
        n++;
    }
    rd_sort(items, n);

    for (i = 0; i < n; i++) {
        size_t need;
        if (i > 0 && rd_cmp(&items[i - 1], &items[i]) == 0)
            continue;                    /* duplicates are removed */
        need = (size_t)canon.len + 10u + items[i].len;
        if (o + need > cap)
            return 0;
        memcpy(out + o, canon.d, canon.len);
        o += canon.len;
        elpis_put16(out + o, type);      o += 2;
        elpis_put16(out + o, klass);     o += 2;
        elpis_put32(out + o, orig_ttl);  o += 4;
        elpis_put16(out + o, items[i].len); o += 2;
        memcpy(out + o, items[i].rd, items[i].len);
        o += items[i].len;
    }
    return o;
}

/* ================================================================== */
/* Signature verification                                              */
/* ================================================================== */

static int verify_with_key(const elpis_conf_t *c, uint8_t alg,
                           const uint8_t *key, size_t keylen,
                           const uint8_t *data, size_t datalen,
                           const uint8_t *sig, size_t siglen)
{
    int halg = elpis_alg_hash(c, alg);
    uint8_t digest[64];

    if (alg == c->alg_mldsa44)
        return elpis_mldsa_verify(ELPIS_MLDSA_44, key, keylen, data, datalen,
                                  sig, siglen);
    if (alg == c->alg_mldsa65)
        return elpis_mldsa_verify(ELPIS_MLDSA_65, key, keylen, data, datalen,
                                  sig, siglen);
    if (alg == c->alg_mldsa87)
        return elpis_mldsa_verify(ELPIS_MLDSA_87, key, keylen, data, datalen,
                                  sig, siglen);

    if (alg == ELPIS_ALG_ED25519) {
        if (keylen != 32 || siglen != 64)
            return 0;
        return elpis_ed25519_verify(key, data, datalen, sig);
    }

    if (halg <= 0)
        return 0;
    if (elpis_hash(halg, data, datalen, digest) != ELPIS_OK)
        return 0;

    switch (alg) {
    case ELPIS_ALG_RSASHA1:
    case ELPIS_ALG_RSASHA1_NSEC3_SHA1:
    case ELPIS_ALG_RSASHA256:
    case ELPIS_ALG_RSASHA512:
        return elpis_rsa_verify(key, keylen, sig, siglen, digest,
                                elpis_hash_len(halg), halg);
    case ELPIS_ALG_ECDSAP256SHA256:
        return elpis_ecdsa_verify(ELPIS_CURVE_P256, key, keylen, sig, siglen,
                                  digest, elpis_hash_len(halg));
    case ELPIS_ALG_ECDSAP384SHA384:
        return elpis_ecdsa_verify(ELPIS_CURVE_P384, key, keylen, sig, siglen,
                                  digest, elpis_hash_len(halg));
    default:
        return 0;
    }
}

int elpis_rrsig_verify(const elpis_conf_t *conf,
                       const elpis_name_t *owner, uint16_t type, uint16_t klass,
                       const uint8_t *const *rd, const uint16_t *rdlen,
                       unsigned count,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *key, size_t keylen,
                       int64_t now, int *ede)
{
    elpis_name_t signer;
    size_t signer_len, datalen;
    uint8_t *buf;
    uint16_t covered, keytag;
    uint8_t alg;
    int64_t incep, expire;

    if (siglen < 19 || keylen < 5)
        return ELPIS_ENOTFOUND;

    covered = elpis_get16(sig);
    alg     = sig[2];
    expire  = (int64_t)elpis_get32(sig + 8);
    incep   = (int64_t)elpis_get32(sig + 12);
    keytag  = elpis_get16(sig + 16);

    if (covered != type)
        return ELPIS_ENOTFOUND;
    if (alg != key[3])
        return ELPIS_ENOTFOUND;
    if (elpis_dnskey_tag(key, keylen) != keytag)
        return ELPIS_ENOTFOUND;

    /* The key must be a zone key and must not be revoked (RFC 5011). */
    {
        uint16_t flags = elpis_get16(key);
        if (!(flags & ELPIS_DNSKEY_ZONE)) {
            if (ede) *ede = ELPIS_EDE_NO_ZONE_KEY_BIT;
            return ELPIS_ENOTFOUND;
        }
        if (flags & ELPIS_DNSKEY_REVOKE)
            return ELPIS_ENOTFOUND;
        if (key[2] != 3)
            return ELPIS_ENOTFOUND;      /* protocol field is always 3 */
    }

    if (!elpis_alg_supported(conf, alg)) {
        if (ede) *ede = ELPIS_EDE_UNSUPPORTED_DNSKEY;
        return ELPIS_ENOTFOUND;
    }

    {
        size_t used;
        if (elpis_name_parse_nocomp(&signer, sig + 18, siglen - 18, &used) != ELPIS_OK)
            return ELPIS_EBOGUS;
        signer_len = used;
    }

    /*
     * RFC 4034 section 3.1.5: the serial-number arithmetic of RFC 1982 makes
     * these comparisons wrap safely around 2038.
     */
    {
        int32_t d_exp = (int32_t)((uint32_t)expire - (uint32_t)now);
        int32_t d_inc = (int32_t)((uint32_t)now - (uint32_t)incep);
        if (d_exp + (int32_t)conf->sig_skew < 0) {
            if (ede) *ede = ELPIS_EDE_SIGNATURE_EXPIRED;
            return ELPIS_EBOGUS;
        }
        if (d_inc + (int32_t)conf->sig_skew < 0) {
            if (ede) *ede = ELPIS_EDE_SIGNATURE_NOT_YET;
            return ELPIS_EBOGUS;
        }
    }

    buf = signbuf();
    if (buf == NULL)
        return ELPIS_ENOMEM;

    datalen = build_signed_data(owner, type, klass, rd, rdlen, count,
                                sig, siglen, signer_len, buf, SIGNBUF_MAX);
    if (datalen == 0)
        return ELPIS_EBOGUS;

    if (verify_with_key(conf, alg, key + 4, keylen - 4, buf, datalen,
                        sig + 18 + signer_len, siglen - 18 - signer_len))
        return ELPIS_OK;

    if (ede) *ede = ELPIS_EDE_DNSSEC_BOGUS;
    return ELPIS_EBOGUS;
}

int elpis_rrset_validate(const elpis_conf_t *conf,
                         const elpis_rrset_buf_t *set,
                         const elpis_rrset_buf_t *keys,
                         int64_t now, elpis_name_t *wildcard_out, int *ede)
{
    const uint8_t *rd[ELPIS_RRSET_MAX_RR];
    uint16_t rl[ELPIS_RRSET_MAX_RR];
    unsigned i, j;
    int saw_sig = 0;

    if (set->count == 0)
        return ELPIS_EBOGUS;
    if (set->sigcount == 0) {
        if (ede) *ede = ELPIS_EDE_RRSIGS_MISSING;
        return ELPIS_ENOTFOUND;
    }

    for (i = 0; i < set->count; i++) {
        rd[i] = set->data + set->off[i];
        rl[i] = set->len[i];
    }

    for (i = 0; i < set->sigcount; i++) {
        const uint8_t *sig = set->data + set->off[set->count + i];
        uint16_t siglen = set->len[set->count + i];

        if (siglen < 19)
            continue;
        saw_sig = 1;

        for (j = 0; j < keys->count; j++) {
            const uint8_t *key = keys->data + keys->off[j];
            uint16_t keylen = keys->len[j];
            int rc = elpis_rrsig_verify(conf, &set->name, set->type, set->klass,
                                        rd, rl, set->count, sig, siglen,
                                        key, keylen, now, ede);
            if (rc == ELPIS_OK) {
                if (wildcard_out != NULL) {
                    uint8_t labels = sig[3];
                    if (labels < set->name.labels) {
                        elpis_name_t suffix;
                        if (elpis_name_suffix(&set->name, labels, &suffix) == 0)
                            elpis_name_prepend(wildcard_out,
                                               (const uint8_t *)"*", 1, &suffix);
                    } else {
                        wildcard_out->len = 0;
                    }
                }
                return ELPIS_OK;
            }
        }
    }

    if (ede && *ede < 0)
        *ede = saw_sig ? ELPIS_EDE_DNSSEC_BOGUS : ELPIS_EDE_RRSIGS_MISSING;
    return ELPIS_EBOGUS;
}

int elpis_dnskey_validate_ds(const elpis_conf_t *conf,
                             const elpis_rrset_buf_t *keys,
                             const elpis_rrset_buf_t *ds,
                             int64_t now, int *ede)
{
    unsigned i, j;
    int any_supported = 0;

    /*
     * At least one DS must match a DNSKEY, and that DNSKEY must then verify
     * the whole DNSKEY RRset's own signature.  Checking the DS alone is not
     * enough: it only authenticates one key, not the set.
     */
    for (i = 0; i < ds->count; i++) {
        const uint8_t *dsr = ds->data + ds->off[i];
        uint16_t dslen = ds->len[i];

        if (dslen < 5)
            continue;
        if (!elpis_digest_supported(dsr[3]))
            continue;
        if (!elpis_alg_supported(conf, dsr[2]))
            continue;
        any_supported = 1;

        for (j = 0; j < keys->count; j++) {
            const uint8_t *key = keys->data + keys->off[j];
            uint16_t keylen = keys->len[j];

            if (!elpis_ds_matches(&keys->name, key, keylen, dsr, dslen))
                continue;
            /* This key is authenticated; use it on the DNSKEY RRset itself. */
            {
                elpis_rrset_buf_t one;
                int rc;
                memset(&one, 0, sizeof one);
                one.name = keys->name;
                one.type = ELPIS_T_DNSKEY;
                one.klass = keys->klass;
                one.count = 1;
                one.off[0] = 0;
                one.len[0] = keylen;
                memcpy(one.data, key, keylen);
                rc = elpis_rrset_validate(conf, keys, &one, now, NULL, ede);
                if (rc == ELPIS_OK)
                    return ELPIS_OK;
            }
        }
    }

    if (!any_supported) {
        /*
         * Every DS uses an algorithm or digest we do not implement.  RFC 4035
         * says treat the zone as unsigned rather than broken.
         */
        if (ede) *ede = ELPIS_EDE_UNSUPPORTED_DS_DIGEST;
        return ELPIS_ENOTFOUND;
    }
    if (ede && *ede < 0)
        *ede = ELPIS_EDE_DNSKEY_MISSING;
    return ELPIS_EBOGUS;
}

int elpis_dnskey_validate_ta(const elpis_conf_t *conf,
                             const elpis_ta_store_t *store,
                             const elpis_rrset_buf_t *keys,
                             int64_t now, int *ede)
{
    const elpis_ta_t *tas[16];
    unsigned n, i, j;
    int any_supported = 0;

    n = elpis_ta_for(store, &keys->name, tas, (unsigned)ELPIS_ARRAY_LEN(tas));
    if (n == 0) {
        if (ede) *ede = ELPIS_EDE_DNSKEY_MISSING;
        return ELPIS_ENOTFOUND;
    }

    for (i = 0; i < n; i++) {
        uint8_t dsr[4 + 64];
        if (!elpis_digest_supported(tas[i]->digest_type))
            continue;
        if (!elpis_alg_supported(conf, tas[i]->alg))
            continue;
        any_supported = 1;

        elpis_put16(dsr, tas[i]->keytag);
        dsr[2] = tas[i]->alg;
        dsr[3] = tas[i]->digest_type;
        memcpy(dsr + 4, tas[i]->digest, tas[i]->digest_len);

        for (j = 0; j < keys->count; j++) {
            const uint8_t *key = keys->data + keys->off[j];
            uint16_t keylen = keys->len[j];
            if (!elpis_ds_matches(&keys->name, key, keylen, dsr,
                                  (size_t)tas[i]->digest_len + 4u))
                continue;
            {
                elpis_rrset_buf_t one;
                memset(&one, 0, sizeof one);
                one.name  = keys->name;
                one.type  = ELPIS_T_DNSKEY;
                one.klass = keys->klass;
                one.count = 1;
                one.off[0] = 0;
                one.len[0] = keylen;
                memcpy(one.data, key, keylen);
                if (elpis_rrset_validate(conf, keys, &one, now, NULL, ede) == ELPIS_OK)
                    return ELPIS_OK;
            }
        }
    }

    if (!any_supported) {
        if (ede) *ede = ELPIS_EDE_UNSUPPORTED_DS_DIGEST;
        return ELPIS_ENOTFOUND;
    }
    if (ede && *ede < 0)
        *ede = ELPIS_EDE_DNSKEY_MISSING;
    return ELPIS_EBOGUS;
}

/* ================================================================== */
/* The validation state machine                                        */
/* ================================================================== */

/*
 * Validation needs data the resolver may not have yet -- DNSKEY and DS
 * records up the chain -- so it runs as a state machine that can suspend on a
 * child lookup and resume when it lands.  elpis_val_start() returns 0 once it
 * has a verdict and non-zero while it is waiting.
 *
 * One answer can legitimately carry records signed by several different
 * zones: a CNAME chain that crosses a zone boundary is signed by the zone
 * that held each link.  The machine therefore walks a chain of trust per
 * distinct signer and records a verdict per RRset, rather than assuming the
 * whole message came from one place.
 */

enum {
    VS_START = 0,
    VS_ANCHOR_KEYS,
    VS_DESCEND,
    VS_VERIFY,
    VS_TALLY
};

#define VAL_MAX_SIGNERS 12
#define VAL_MAX_SETS    256

#define SS_UNKNOWN  0
#define SS_SECURE   1
#define SS_INSECURE 2
#define SS_BOGUS    3

typedef struct {
    int               stage;
    elpis_name_t      signers[VAL_MAX_SIGNERS];
    /*
     * A signers[] entry is normally a zone that signed something here.  An
     * entry may additionally -- or instead -- be a zone we walk the chain to
     * purely to find out whether it is signed at all, because some RRset it
     * serves arrived with no signature.  That is the only way to tell an
     * unsigned zone from one whose signatures were stripped in flight.
     */
    uint8_t           probe[VAL_MAX_SIGNERS];
    unsigned          nsigners, si;

    elpis_name_t      anchor;     /* trust anchor covering signers[si]   */
    elpis_name_t      cur;        /* deepest zone with validated keys    */
    elpis_name_t      walk;       /* how far down we have probed for DS  */
    elpis_name_t      pending;    /* name of the outstanding lookup      */
    uint16_t          pending_type;
    unsigned          waiting : 1;
    unsigned          pending_tries;
    unsigned          steps;

    uint8_t           status[VAL_MAX_SETS];   /* per leading record index */
    elpis_rrset_buf_t keys;
} val_t;

static void val_run(elpis_task_t *t);

void elpis_val_free(elpis_task_t *t)
{
    if (t->val != NULL) {
        elpis_free(t->val);
        t->val = NULL;
    }
}

static int val_cached(elpis_task_t *t, const elpis_name_t *n, uint16_t type,
                      elpis_rrset_buf_t *out)
{
    return elpis_rcache_get(t->w->ctx->rcache, n, type, ELPIS_CLASS_IN,
                            elpis_cached_now_s(), 0, out) == ELPIS_OK;
}

static void val_child_done(elpis_task_t *child, void *ctxp)
{
    elpis_task_t *p = child->parent;
    val_t *v;

    (void)ctxp;
    if (p == NULL)
        return;                         /* the parent went away first */
    if (p->nchild)
        p->nchild--;

    v = (val_t *)p->val;
    if (v == NULL)
        return;                         /* the verdict is already in */
    v->waiting = 0;

    val_run(p);

    if (p->val != NULL && ((val_t *)p->val)->waiting)
        return;                         /* suspended on the next link */
    if (p->state == ELPIS_TS_VALIDATE) {
        p->state = ELPIS_TS_FINISH;
        elpis_task_step(p);
    }
}

/* Returns 1 when the data is in hand, 0 when a lookup was launched. */
static int val_need(elpis_task_t *t, const elpis_name_t *n, uint16_t type,
                    elpis_rrset_buf_t *out)
{
    val_t *v = (val_t *)t->val;

    if (val_cached(t, n, type, out)) {
        v->pending_tries = 0;
        return 1;
    }
    /*
     * The child ran and left nothing behind.  One retry, because the usual
     * cause is a timeout on a cold cache rather than a missing record -- but
     * only one, or a zone that genuinely has no DNSKEY becomes a loop.
     */
    if (v->pending_type == type && elpis_name_eq(&v->pending, n)) {
        if (v->pending_tries >= 2) {
            elpis_rrset_buf_init(out, n, type, ELPIS_CLASS_IN, 0);
            return 1;
        }
    } else {
        v->pending_tries = 0;
    }

    v->pending = *n;
    v->pending_type = type;
    v->pending_tries++;
    v->waiting = 1;
    v->steps++;
    if (elpis_task_child(t, n, type, val_child_done, NULL) == NULL) {
        v->waiting = 0;
        elpis_rrset_buf_init(out, n, type, ELPIS_CLASS_IN, 0);
        return 1;
    }
    return 0;
}

static void val_done(elpis_task_t *t, elpis_sec_t sec, int ede)
{
    t->sec = sec;
    if (ede >= 0 && t->ede < 0)
        t->ede = ede;
    if (sec == ELPIS_SEC_SECURE)
        elpis_stat_inc(&t->w->stats.dnssec_secure, 1);
    else if (sec == ELPIS_SEC_INSECURE)
        elpis_stat_inc(&t->w->stats.dnssec_insecure, 1);
    else if (sec == ELPIS_SEC_BOGUS)
        elpis_stat_inc(&t->w->stats.dnssec_bogus, 1);
    elpis_val_free(t);
}

/* ------------------------------------------------------------------ */
/* RRset grouping                                                      */
/* ------------------------------------------------------------------ */

/*
 * Whether this record's RRset has to carry a signature.
 *
 * Answer data does.  So do the SOA and NSEC/NSEC3 records that prove a
 * negative answer.  Delegation NS records and glue in the authority and
 * additional sections do not: the parent side of a zone cut is unsigned by
 * design, and demanding a signature there would make every referral bogus.
 */
static int set_must_be_signed(const elpis_task_t *t, const elpis_trr_t *rr)
{
    if (rr->type == ELPIS_T_RRSIG || rr->type == ELPIS_T_OPT)
        return 0;
    if (rr->section == (uint8_t)ELPIS_SEC_ANSWER)
        return 1;
    if (rr->section == (uint8_t)ELPIS_SEC_AUTHORITY)
        return rr->type == ELPIS_T_SOA || rr->type == ELPIS_T_NSEC ||
               rr->type == ELPIS_T_NSEC3;
    (void)t;
    return 0;
}

/* Is index `i` the first record of its (owner, type) group? */
static int set_leader(const elpis_task_t *t, unsigned i)
{
    elpis_name_t a, b;
    unsigned j;

    if (elpis_trr_get_name(&t->ans, i, &a) != ELPIS_OK)
        return 0;
    for (j = 0; j < i; j++) {
        if (t->ans.rr[j].type != t->ans.rr[i].type ||
            t->ans.rr[j].klass != t->ans.rr[i].klass)
            continue;
        if (elpis_trr_get_name(&t->ans, j, &b) != ELPIS_OK)
            continue;
        if (elpis_name_eq(&a, &b))
            return 0;
    }
    return 1;
}

/* Gather the RRset led by index `i`, plus the RRSIGs that cover it. */
static int build_set(elpis_task_t *t, unsigned i, elpis_rrset_buf_t *set)
{
    const elpis_trr_t *rr = &t->ans.rr[i];
    elpis_name_t owner, o2;
    unsigned j;

    if (elpis_trr_get_name(&t->ans, i, &owner) != ELPIS_OK)
        return 0;
    elpis_rrset_buf_init(set, &owner, rr->type, rr->klass, rr->ttl);

    /*
     * Two passes: all the data, then all the signatures.  The buffer stores
     * signatures after the records they cover, so an interleaved single pass
     * would drop any data record that came after the first RRSIG.
     */
    for (j = 0; j < t->ans.n; j++) {
        const elpis_trr_t *r2 = &t->ans.rr[j];
        if (r2->klass != rr->klass || r2->type != rr->type)
            continue;
        if (elpis_trr_get_name(&t->ans, j, &o2) != ELPIS_OK)
            continue;
        if (!elpis_name_eq(&o2, &owner))
            continue;
        elpis_rrset_buf_add(set, elpis_trr_rd(&t->ans, j), r2->rdlen);
        if (r2->ttl < set->ttl)
            set->ttl = r2->ttl;
    }
    for (j = 0; j < t->ans.n; j++) {
        const elpis_trr_t *r2 = &t->ans.rr[j];
        if (r2->klass != rr->klass || r2->type != ELPIS_T_RRSIG)
            continue;
        if (r2->rdlen < 19 || elpis_get16(elpis_trr_rd(&t->ans, j)) != rr->type)
            continue;
        if (elpis_trr_get_name(&t->ans, j, &o2) != ELPIS_OK)
            continue;
        if (!elpis_name_eq(&o2, &owner))
            continue;
        elpis_rrset_buf_add_sig(set, elpis_trr_rd(&t->ans, j), r2->rdlen);
    }
    return set->count > 0;
}

/* The signer of the RRset led by index `i`, if it has one. */
static int set_signer(elpis_task_t *t, unsigned i, elpis_name_t *out)
{
    const elpis_trr_t *rr = &t->ans.rr[i];
    elpis_name_t owner, o2;
    unsigned j;

    if (elpis_trr_get_name(&t->ans, i, &owner) != ELPIS_OK)
        return 0;

    for (j = 0; j < t->ans.n; j++) {
        const elpis_trr_t *r2 = &t->ans.rr[j];
        size_t used;
        if (r2->type != ELPIS_T_RRSIG || r2->rdlen < 19)
            continue;
        if (elpis_get16(elpis_trr_rd(&t->ans, j)) != rr->type)
            continue;
        if (elpis_trr_get_name(&t->ans, j, &o2) != ELPIS_OK)
            continue;
        if (!elpis_name_eq(&o2, &owner))
            continue;
        if (elpis_name_parse_nocomp(out, elpis_trr_rd(&t->ans, j) + 18,
                                    r2->rdlen - 18u, &used) != ELPIS_OK)
            continue;
        elpis_name_lower(out);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Denial of existence                                                 */
/* ------------------------------------------------------------------ */

/*
 * Signatures only prove the NSEC/NSEC3 records are genuine.  Replaying a
 * genuine record from elsewhere in the zone would otherwise turn any name
 * into an NXDOMAIN, so the proof has to be checked against the question.
 */
static int check_denial(elpis_task_t *t, const elpis_name_t *zone)
{
    elpis_denial_rr_t rrs[32];
    unsigned n = 0;
    unsigned i;
    int have_nsec3 = 0, have_nsec = 0;
    int answered = 0;

    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        if (rr->section == (uint8_t)ELPIS_SEC_ANSWER &&
            rr->type != ELPIS_T_RRSIG)
            answered = 1;
        if (rr->section != (uint8_t)ELPIS_SEC_AUTHORITY)
            continue;
        if (rr->type != ELPIS_T_NSEC && rr->type != ELPIS_T_NSEC3)
            continue;
        if (n >= ELPIS_ARRAY_LEN(rrs))
            break;
        if (elpis_trr_get_name(&t->ans, i, &rrs[n].owner) != ELPIS_OK)
            continue;
        rrs[n].rd    = elpis_trr_rd(&t->ans, i);
        rrs[n].rdlen = rr->rdlen;
        if (rr->type == ELPIS_T_NSEC3) have_nsec3 = 1;
        else                            have_nsec  = 1;
        n++;
    }

    if (answered)
        return 1;                       /* not a negative answer */
    if (n == 0) {
        /*
         * A signed zone must supply a proof.  Without one there is no way to
         * tell an honest empty answer from a suppressed one -- but a cached
         * negative entry legitimately has no NSEC attached, so only insist
         * when hardening is on and the data came off the wire.
         */
        return (t->w->ctx->conf.harden_dnssec_stripped && !t->from_cache) ? 0 : 1;
    }

    if (t->rcode == ELPIS_RC_NXDOMAIN) {
        if (have_nsec3 && elpis_nsec3_proves_nxdomain(rrs, n, &t->qname, zone))
            return 1;
        if (have_nsec && elpis_nsec_proves_nxdomain(rrs, n, &t->qname))
            return 1;
        return 0;
    }
    if (t->qtype == ELPIS_T_DS) {
        if (have_nsec3 && elpis_nsec3_proves_no_ds(rrs, n, &t->qname, zone))
            return 1;
        if (have_nsec && elpis_nsec_proves_no_ds(rrs, n, &t->qname))
            return 1;
        return 0;
    }
    if (have_nsec3 && elpis_nsec3_proves_nodata(rrs, n, &t->qname, t->qtype, zone))
        return 1;
    if (have_nsec && elpis_nsec_proves_nodata(rrs, n, &t->qname, t->qtype))
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* The machine                                                         */
/* ------------------------------------------------------------------ */

static void collect_signers(elpis_task_t *t, val_t *v)
{
    unsigned i, j;

    v->nsigners = 0;
    for (i = 0; i < t->ans.n && i < VAL_MAX_SETS; i++) {
        elpis_name_t sn;
        int dup = 0;

        if (!set_must_be_signed(t, &t->ans.rr[i]) || !set_leader(t, i))
            continue;
        if (!set_signer(t, i, &sn))
            continue;
        for (j = 0; j < v->nsigners; j++)
            if (elpis_name_eq(&v->signers[j], &sn)) { dup = 1; break; }
        if (dup || v->nsigners >= VAL_MAX_SIGNERS)
            continue;
        v->signers[v->nsigners++] = sn;
    }
}

/*
 * Which zone served the RRset led by record `i`?
 *
 * For an RRset that arrived with no signature at all, this is the question
 * that separates "the zone is not signed" from "someone stripped the
 * signatures".  Comparing against the other RRsets in the same message cannot
 * answer it: a CNAME crossing a zone cut legitimately puts a signed set and an
 * unsigned set side by side, while a wholly stripped answer has nothing signed
 * left to compare against.
 *
 * The answer has to be exact.  Guessing from the deepest cached delegation is
 * not good enough -- the cache holds the cuts we happen to have walked, so a
 * name in an unsigned zone we have not visited reads as belonging to its
 * signed grandparent, and a legitimate answer gets called forged.  So the
 * resolver stamps each record with the zone that produced it, and a record
 * that carries no stamp is one we decline to judge.
 */
static int serving_zone(elpis_task_t *t, unsigned i, elpis_name_t *out)
{
    elpis_name_t owner;
    unsigned labels = t->ans.rr[i].zone_labels;

    if (labels == 0)
        return 0;
    if (elpis_trr_get_name(&t->ans, i, &owner) != ELPIS_OK)
        return 0;
    if (labels > owner.labels)
        return 0;
    return elpis_name_suffix(&owner, labels, out) == 0;
}

/* Does this leading record have no signature, in a place that needs one? */
static int set_is_unsigned(elpis_task_t *t, unsigned i)
{
    elpis_name_t sn;
    return set_must_be_signed(t, &t->ans.rr[i]) && set_leader(t, i) &&
           !set_signer(t, i, &sn);
}

/*
 * Add the zones behind unsigned RRsets to the list of chains to walk.
 *
 * These are not signers -- nothing here signed anything -- but each one still
 * needs the descent, because whether it turns out to be signed is precisely
 * what decides between an insecure answer and a forged one.
 */
static void collect_unsigned_zones(elpis_task_t *t, val_t *v)
{
    unsigned i, j;

    for (i = 0; i < t->ans.n && i < VAL_MAX_SETS; i++) {
        elpis_name_t zone;
        int dup = 0;

        if (!set_is_unsigned(t, i))
            continue;
        if (!serving_zone(t, i, &zone))
            continue;

        for (j = 0; j < v->nsigners; j++)
            if (elpis_name_eq(&v->signers[j], &zone)) {
                v->probe[j] = 1;    /* also signs here: walk it once, do both */
                dup = 1;
                break;
            }
        if (dup || v->nsigners >= VAL_MAX_SIGNERS)
            continue;
        v->probe[v->nsigners]     = 1;
        v->signers[v->nsigners++] = zone;
    }
}

/*
 * Settle the unsigned RRsets served by the zone we just walked to.
 *
 * Reaching that zone with validated keys means it is signed, so an RRset of
 * its own that carries no signature is an answer somebody tampered with.
 * Falling short of it means the chain went insecure on the way down, which is
 * the ordinary case of a CNAME pointing into an unsigned zone.
 */
static void classify_unsigned_for_current(elpis_task_t *t, val_t *v, int reached)
{
    unsigned i;

    for (i = 0; i < t->ans.n && i < VAL_MAX_SETS; i++) {
        elpis_name_t zone;

        if (v->status[i] != SS_UNKNOWN || !set_is_unsigned(t, i))
            continue;
        if (!serving_zone(t, i, &zone) ||
            !elpis_name_eq(&zone, &v->signers[v->si]))
            continue;

        if (reached && t->w->ctx->conf.harden_dnssec_stripped) {
            v->status[i] = SS_BOGUS;
            if (t->ede < 0)
                t->ede = ELPIS_EDE_RRSIGS_MISSING;
        } else {
            v->status[i] = SS_INSECURE;
        }
    }
}

/* Validate every RRset signed by the zone we currently hold keys for. */
static void verify_for_current(elpis_task_t *t, val_t *v)
{
    elpis_worker_t *w = t->w;
    elpis_rrset_buf_t *set = w->rrbuf;
    int64_t now = elpis_wall_s();
    unsigned i;

    for (i = 0; i < t->ans.n && i < VAL_MAX_SETS; i++) {
        elpis_name_t sn;
        int ede = -1;
        int rc;

        if (v->status[i] != SS_UNKNOWN)
            continue;
        if (!set_must_be_signed(t, &t->ans.rr[i]) || !set_leader(t, i))
            continue;
        if (!set_signer(t, i, &sn) || !elpis_name_eq(&sn, &v->signers[v->si]))
            continue;
        if (!build_set(t, i, set))
            continue;

        rc = elpis_rrset_validate(&w->ctx->conf, set, &v->keys, now, NULL, &ede);
        if (rc == ELPIS_OK) {
            v->status[i] = SS_SECURE;
            /*
             * Write the verdict back into the RRset cache, so a later hit on
             * the same data carries AD without walking the chain again.
             */
            set->sec = (uint8_t)ELPIS_SEC_SECURE;
            elpis_rcache_put_buf(w->ctx->rcache, set, w->ctx->conf.serve_stale, 0);
        } else {
            v->status[i] = SS_BOGUS;
            if (t->ede < 0)
                t->ede = (ede >= 0) ? ede : ELPIS_EDE_DNSSEC_BOGUS;
        }
    }
}

/* Everything still signed by this signer is insecure: the chain fell short. */
static void mark_insecure_for_current(elpis_task_t *t, val_t *v)
{
    elpis_worker_t *w = t->w;
    elpis_rrset_buf_t *set = w->rrbuf;
    unsigned i;

    for (i = 0; i < t->ans.n && i < VAL_MAX_SETS; i++) {
        elpis_name_t sn;
        if (v->status[i] != SS_UNKNOWN)
            continue;
        if (!set_must_be_signed(t, &t->ans.rr[i]) || !set_leader(t, i))
            continue;
        if (!set_signer(t, i, &sn) || !elpis_name_eq(&sn, &v->signers[v->si]))
            continue;
        v->status[i] = SS_INSECURE;

        /*
         * Record the verdict, exactly as the secure path does.  Leaving it
         * unchecked meant the answer was re-validated from the trust anchor
         * downwards every time it was served from the RRset cache -- a full
         * chain walk, on data already known to be insecure, for the majority
         * of the internet that is not signed at all.  It cost CPU in
         * proportion to traffic and said nothing in the log.
         */
        if (build_set(t, i, set)) {
            set->sec = (uint8_t)ELPIS_SEC_INSECURE;
            elpis_rcache_put_buf(w->ctx->rcache, set, w->ctx->conf.serve_stale, 0);
        }
    }
}

static void tally(elpis_task_t *t, val_t *v)
{
    unsigned i;
    unsigned nsecure = 0, ninsecure = 0, nbogus = 0;

    /*
     * Every RRset has been settled on its own merits by now, including the
     * ones that arrived without a signature: each was traced back to the zone
     * that serves it and judged against whether that zone is signed.  Counting
     * unsigned sets against the signed ones in the same message -- as this
     * used to -- cannot work in either direction.  A CNAME leaving a signed
     * zone for an unsigned one legitimately puts both side by side, and calling
     * that forged took out a large slice of the CDN-hosted internet; while an
     * answer with every signature stripped has nothing signed left to be
     * suspicious of, and calling that merely unsigned let the attack through.
     */
    for (i = 0; i < t->ans.n && i < VAL_MAX_SETS; i++) {
        if (!set_must_be_signed(t, &t->ans.rr[i]) || !set_leader(t, i))
            continue;
        switch (v->status[i]) {
        case SS_SECURE: nsecure++;   break;
        case SS_BOGUS:  nbogus++;    break;
        default:
            /*
             * Either proven insecure, or a set whose serving zone we could not
             * place at all -- and an unplaceable zone is one we cannot claim is
             * signed, so it counts the same way.
             */
            ninsecure++;
            break;
        }
    }

    if (nbogus > 0) {
        val_done(t, ELPIS_SEC_BOGUS,
                 t->ede >= 0 ? t->ede : ELPIS_EDE_DNSSEC_BOGUS);
        return;
    }
    if (ninsecure > 0 || nsecure == 0) {
        val_done(t, ELPIS_SEC_INSECURE, -1);
        return;
    }

    if (!check_denial(t, v->nsigners ? &v->signers[0] : &t->qname)) {
        val_done(t, ELPIS_SEC_BOGUS, ELPIS_EDE_NSEC_MISSING);
        return;
    }
    val_done(t, ELPIS_SEC_SECURE, -1);
}

static void val_run(elpis_task_t *t)
{
    val_t *v = (val_t *)t->val;
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_rrset_buf_t *scratch = w->rrbuf;
    int64_t now = elpis_wall_s();
    int ede = -1;
    unsigned guard = 0;

    if (v == NULL)
        return;

    while (++guard < 128) {
        switch (v->stage) {

        case VS_START: {
            const elpis_name_t *anchor;

            collect_signers(t, v);
            collect_unsigned_zones(t, v);
            if (v->nsigners == 0) {
                /*
                 * Nothing is signed.  Decide between "the zone is unsigned"
                 * and "someone removed the signatures" by walking the chain
                 * for the query name itself.
                 */
                v->signers[0] = t->have_deleg ? t->deleg.zone : t->qname;
                v->nsigners = 1;
            }
            v->si = 0;
            anchor = elpis_ta_closest(w->ctx->ta, &v->signers[0]);
            if (anchor == NULL) {
                val_done(t, ELPIS_SEC_INDETERMINATE, -1);
                return;
            }
            v->anchor = *anchor;
            v->cur    = *anchor;
            v->walk   = *anchor;
            v->stage  = VS_ANCHOR_KEYS;
            continue;
        }

        case VS_ANCHOR_KEYS: {
            int rc;
            if (!val_need(t, &v->cur, ELPIS_T_DNSKEY, &v->keys))
                return;
            if (v->keys.count == 0 || !elpis_name_eq(&v->keys.name, &v->cur)) {
                /*
                 * We could not fetch the trust anchor's DNSKEY set.  That is a
                 * failure to validate, not a detection of tampering: the
                 * client still gets SERVFAIL, but calling it bogus would be a
                 * lie in the logs and in the statistics.
                 */
                t->val_unavailable = 1;
                val_done(t, ELPIS_SEC_INDETERMINATE, ELPIS_EDE_NOT_READY);
                return;
            }
            rc = elpis_dnskey_validate_ta(c, w->ctx->ta, &v->keys, now, &ede);
            if (rc == ELPIS_ENOTFOUND) {
                mark_insecure_for_current(t, v);
                v->stage = VS_VERIFY;
                continue;
            }
            if (rc != ELPIS_OK) {
                val_done(t, ELPIS_SEC_BOGUS, ede);
                return;
            }
            v->stage = VS_DESCEND;
            continue;
        }

        case VS_DESCEND: {
            const elpis_name_t *signer = &v->signers[v->si];
            elpis_name_t next;

            if (v->walk.labels >= signer->labels) {
                v->stage = VS_VERIFY;
                continue;
            }
            if (elpis_name_suffix(signer, v->walk.labels + 1u, &next) != 0) {
                v->stage = VS_VERIFY;
                continue;
            }

            if (!val_need(t, &next, ELPIS_T_DS, scratch))
                return;

            if (scratch->count == 0 ||
                (scratch->flags & (ELPIS_RRF_NXDOMAIN | ELPIS_RRF_NODATA)) ||
                !elpis_name_eq(&scratch->name, &next)) {
                /*
                 * No DS here: either this name is not a zone cut, or it is an
                 * unsigned delegation.  Either way the deepest validated keys
                 * stay what they are; keep walking.
                 */
                v->walk = next;
                continue;
            }

            if (elpis_rrset_validate(c, scratch, &v->keys, now, NULL, &ede) != ELPIS_OK) {
                val_done(t, ELPIS_SEC_BOGUS, ede);
                return;
            }

            {
                static ELPIS_TLS elpis_rrset_buf_t ds_hold;
                int rc;

                ds_hold = *scratch;
                if (!val_need(t, &next, ELPIS_T_DNSKEY, scratch))
                    return;
                if (scratch->count == 0) {
                    /* DS says this zone is signed but its DNSKEY is
                     * unreachable: unverifiable, not forged. */
                    t->val_unavailable = 1;
                    val_done(t, ELPIS_SEC_INDETERMINATE, ELPIS_EDE_DNSKEY_MISSING);
                    return;
                }
                rc = elpis_dnskey_validate_ds(c, scratch, &ds_hold, now, &ede);
                if (rc == ELPIS_ENOTFOUND) {
                    mark_insecure_for_current(t, v);
                    v->stage = VS_VERIFY;
                    continue;
                }
                if (rc != ELPIS_OK) {
                    val_done(t, ELPIS_SEC_BOGUS, ede);
                    return;
                }
                v->keys = *scratch;
            }
            v->cur  = next;
            v->walk = next;
            continue;
        }

        case VS_VERIFY: {
            int reached = elpis_name_eq(&v->cur, &v->signers[v->si]);

            if (reached)
                verify_for_current(t, v);
            else
                mark_insecure_for_current(t, v);
            if (v->probe[v->si])
                classify_unsigned_for_current(t, v, reached);

            v->si++;
            if (v->si < v->nsigners) {
                const elpis_name_t *anchor =
                    elpis_ta_closest(w->ctx->ta, &v->signers[v->si]);
                if (anchor == NULL) {
                    mark_insecure_for_current(t, v);
                    if (v->probe[v->si])
                        classify_unsigned_for_current(t, v, 0);
                    v->stage = VS_VERIFY;   /* falls through to the next one */
                    continue;
                }
                v->anchor = *anchor;
                v->cur    = *anchor;
                v->walk   = *anchor;
                v->stage  = VS_ANCHOR_KEYS;
                continue;
            }
            v->stage = VS_TALLY;
            continue;
        }

        case VS_TALLY:
            tally(t, v);
            return;

        default:
            val_done(t, ELPIS_SEC_INDETERMINATE, -1);
            return;
        }
    }

    val_done(t, ELPIS_SEC_BOGUS, ELPIS_EDE_OTHER);
}

int elpis_val_start(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;

    if (!c->dnssec) {
        t->sec = ELPIS_SEC_UNCHECKED;
        return 0;
    }
    /*
     * The chain walk fetches DNSKEY and DS itself and checks them against the
     * anchor, so those lookups must not re-enter the validator.
     */
    if (t->qtype == ELPIS_T_DNSKEY || t->qtype == ELPIS_T_DS ||
        t->qclass != ELPIS_CLASS_IN) {
        t->sec = ELPIS_SEC_UNCHECKED;
        return 0;
    }
    if (t->depth >= ELPIS_MAX_DEPTH - 1u) {
        t->sec = ELPIS_SEC_UNCHECKED;
        return 0;
    }
    if (t->client_cd && t->depth == 0) {
        t->sec = ELPIS_SEC_UNCHECKED;
        return 0;
    }
    /*
     * Priming and TLD warming produce delegation hints, not answers, and
     * validating them at startup would triple the chain lookups and crowd out
     * queries that do have a client.  Client-driven prefetches are different:
     * they replace a cache entry that will be served, so they are validated
     * like any other resolution.
     */
    if (t->warming) {
        t->sec = ELPIS_SEC_UNCHECKED;
        return 0;
    }
    if (t->rcode == ELPIS_RC_SERVFAIL) {
        t->sec = ELPIS_SEC_UNCHECKED;
        return 0;
    }

    if (t->val == NULL) {
        val_t *v = (val_t *)elpis_calloc(1, sizeof *v);
        if (v == NULL) {
            t->sec = ELPIS_SEC_UNCHECKED;
            return 0;
        }
        t->val = v;
    }

    val_run(t);

    if (t->val != NULL && ((val_t *)t->val)->waiting)
        return 1;                      /* suspended on a child lookup */
    return 0;
}
