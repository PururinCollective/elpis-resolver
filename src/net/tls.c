/*
 * tls.c -- a TLS 1.3 client (RFC 8446), just enough for DNS over TLS.
 *
 * The handshake, one flight each way:
 *
 *   ClientHello            ->
 *                          <-  ServerHello
 *                              {EncryptedExtensions}
 *                              {CertificateRequest}   (rare; answered empty)
 *                              {Certificate}          (hashed, not checked)
 *                              {CertificateVerify}    (hashed, not checked)
 *                              {Finished}             (verified)
 *   [ChangeCipherSpec]
 *   {Certificate}          ->  (empty, only if requested)
 *   {Finished}             ->
 *
 * Everything the server sends after its ServerHello is encrypted, and the
 * engine works one record at a time: records are joined from whatever the
 * socket delivered, decrypted in place, and their handshake messages joined
 * again across records.  Anything malformed, out of order or over a limit
 * ends the connection with an alert; the caller falls back to plain DNS.
 */
#include "elpis/tls.h"
#include "elpis/util.h"

/* Record content types */
#define CT_CCS    20
#define CT_ALERT  21
#define CT_HS     22
#define CT_APP    23

/* Handshake message types */
#define HT_CLIENT_HELLO   1
#define HT_SERVER_HELLO   2
#define HT_NEW_TICKET     4
#define HT_ENC_EXT        8
#define HT_CERT          11
#define HT_CERT_REQ      13
#define HT_CERT_VERIFY   15
#define HT_FINISHED      20
#define HT_KEY_UPDATE    24

/* Alerts */
#define AL_CLOSE_NOTIFY        0
#define AL_UNEXPECTED         10
#define AL_BAD_RECORD_MAC     20
#define AL_RECORD_OVERFLOW    22
#define AL_HANDSHAKE_FAILURE  40
#define AL_ILLEGAL_PARAMETER  47
#define AL_DECODE_ERROR       50
#define AL_DECRYPT_ERROR      51
#define AL_PROTOCOL_VERSION   70
#define AL_INTERNAL_ERROR     80
#define AL_USER_CANCELED      90
#define AL_MISSING_EXTENSION 109
#define AL_UNSUPPORTED_EXT   110
#define AL_NONE              255     /* fail without sending one */

/* Extensions */
#define EXT_SERVER_NAME        0
#define EXT_SUPPORTED_GROUPS  10
#define EXT_SIG_ALGS          13
#define EXT_ALPN              16
#define EXT_SUPPORTED_VERS    43
#define EXT_KEY_SHARE         51

#define GROUP_X25519      0x001d
#define TLS13             0x0304

#define SUITE_AES128GCM   0x1301
#define SUITE_CHACHA      0x1303

/* Where the handshake is. */
enum {
    HS_WAIT_SH = 0,
    HS_WAIT_EE,
    HS_WAIT_CERT_CR,
    HS_WAIT_CERT,
    HS_WAIT_CV,
    HS_WAIT_FIN,
    HS_DONE
};

/* What a server sets its random to when it sends a HelloRetryRequest:
 * SHA-256("HelloRetryRequest"). */
static const uint8_t hrr_random[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
    0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
};

/* Offered only so a server with any certificate carries on; nothing here
 * checks the signature (see tls.h). */
static const uint16_t sig_algs[] = {
    0x0403, 0x0503, 0x0603,             /* ecdsa_secp256r1/384r1/521r1     */
    0x0807, 0x0808,                     /* ed25519, ed448                  */
    0x0804, 0x0805, 0x0806,             /* rsa_pss_rsae_sha256/384/512     */
    0x0809, 0x080a, 0x080b,             /* rsa_pss_pss_sha256/384/512      */
    0x0401, 0x0501, 0x0601              /* rsa_pkcs1_sha256/384/512        */
};

/* What the out queue may hold: a megabyte of queries plus record overhead. */
#define OUT_LIMIT (ELPIS_TLS_MAX_APPBUF + 64u * 1024u)

static const uint8_t zeros32[32];

/* ------------------------------------------------------------------ */
/* Buffers                                                             */
/* ------------------------------------------------------------------ */

/* Room for n more bytes at the end, moving the live bytes down first.
 * Returns where they go, or NULL with *e set. */
static uint8_t *buf_grow(elpis_tls_buf_t *b, size_t n, size_t limit,
                         elpis_tls_err_t *e)
{
    uint8_t *at;

    if (b->off > 0) {
        memmove(b->p, b->p + b->off, b->len - b->off);
        b->len -= b->off;
        b->off = 0;
    }
    if (n > limit || b->len > limit - n) {
        *e = ELPIS_TLS_E_TOOBIG;
        return NULL;
    }
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 512u;
        uint8_t *np;
        while (cap < b->len + n)
            cap *= 2u;
        if (cap > limit)
            cap = limit;
        np = (uint8_t *)elpis_realloc(b->p, cap);
        if (np == NULL) {
            *e = ELPIS_TLS_E_NOMEM;
            return NULL;
        }
        b->p = np;
        b->cap = cap;
    }
    at = b->p + b->len;
    b->len += n;
    return at;
}

static elpis_tls_err_t buf_put(elpis_tls_buf_t *b, const uint8_t *p, size_t n,
                               size_t limit)
{
    elpis_tls_err_t e = ELPIS_TLS_OK;
    uint8_t *at;

    if (n == 0)                         /* b->p may still be NULL */
        return ELPIS_TLS_OK;
    at = buf_grow(b, n, limit, &e);
    if (at != NULL)
        memcpy(at, p, n);
    return e;
}

static size_t buf_live(const elpis_tls_buf_t *b)
{
    return b->len - b->off;
}

static void buf_release(elpis_tls_buf_t *b)
{
    if (b->p != NULL) {
        elpis_wipe(b->p, b->cap);
        elpis_free(b->p);
    }
    memset(b, 0, sizeof *b);
}

/* ------------------------------------------------------------------ */
/* Reading messages                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    size_t         n;
    int            bad;     /* ran past the end; sticky */
} rd_t;

static rd_t rd_make(const uint8_t *p, size_t n)
{
    rd_t r;
    r.p = p;
    r.n = n;
    r.bad = 0;
    return r;
}

static const uint8_t *rd_bytes(rd_t *r, size_t n)
{
    const uint8_t *p = r->p;
    if (r->bad || n > r->n) {
        r->bad = 1;
        return NULL;
    }
    r->p += n;
    r->n -= n;
    return p;
}

static unsigned rd_u8(rd_t *r)
{
    const uint8_t *p = rd_bytes(r, 1);
    return p ? p[0] : 0u;
}

static unsigned rd_u16(rd_t *r)
{
    const uint8_t *p = rd_bytes(r, 2);
    return p ? elpis_get16(p) : 0u;
}

static size_t rd_u24(rd_t *r)
{
    const uint8_t *p = rd_bytes(r, 3);
    return p ? ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2] : 0u;
}

/* The next n bytes as a reader of their own. */
static rd_t rd_sub(rd_t *r, size_t n)
{
    const uint8_t *p = rd_bytes(r, n);
    rd_t s = rd_make(p, p ? n : 0);
    s.bad = p == NULL;
    return s;
}

static void put24(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

static void transcript_hash(const elpis_tls_t *t, uint8_t out[32])
{
    elpis_sha256_t c = t->transcript;
    elpis_sha256_final(&c, out);
    elpis_wipe(&c, sizeof c);
}

static void transcript_add(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    elpis_sha256_update(&t->transcript, msg, n);
}

/* Derive-Secret(secret, label, transcript so far). */
static void derive(const elpis_tls_t *t, const uint8_t secret[32],
                   const char *label, uint8_t out[32])
{
    uint8_t th[32];
    transcript_hash(t, th);
    elpis_hkdf_expand_label(secret, label, th, 32, out, 32);
}

/* Derive-Secret(secret, "derived", ""), the step between the stages. */
static void derived(const uint8_t secret[32], uint8_t out[32])
{
    uint8_t empty[32];
    elpis_sha256("", 0, empty);
    elpis_hkdf_expand_label(secret, "derived", empty, 32, out, 32);
}

static int aead_of(uint16_t suite)
{
    return suite == SUITE_CHACHA ? ELPIS_AEAD_CHACHA20_POLY1305
                                 : ELPIS_AEAD_AES128_GCM;
}

/* The record key and IV for one direction from its traffic secret. */
static void set_keys(elpis_tls_t *t, int write, const uint8_t secret[32])
{
    uint8_t key[32];
    int aead = aead_of(t->suite);
    size_t kl = elpis_aead_key_len(aead);

    elpis_hkdf_expand_label(secret, "key", NULL, 0, key, kl);
    if (write) {
        elpis_hkdf_expand_label(secret, "iv", NULL, 0, t->wr_iv, 12);
        elpis_aead_init(&t->wr, aead, key, kl);
        t->wr_seq = 0;
        t->wr_on = 1;
    } else {
        elpis_hkdf_expand_label(secret, "iv", NULL, 0, t->rd_iv, 12);
        elpis_aead_init(&t->rd, aead, key, kl);
        t->rd_seq = 0;
        t->rd_on = 1;
    }
    elpis_wipe(key, sizeof key);
}

/* The per-record nonce: the IV with the sequence number xored into its
 * last eight bytes. */
static void make_nonce(uint8_t out[12], const uint8_t iv[12], uint64_t seq)
{
    int i;
    memcpy(out, iv, 12);
    for (i = 0; i < 8; i++)
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

static void wipe_secrets(elpis_tls_t *t)
{
    elpis_wipe(t->priv, sizeof t->priv);
    elpis_wipe(t->hs_secret, sizeof t->hs_secret);
    elpis_wipe(t->c_secret, sizeof t->c_secret);
    elpis_wipe(t->s_secret, sizeof t->s_secret);
}

/* ------------------------------------------------------------------ */
/* Writing records                                                     */
/* ------------------------------------------------------------------ */

/* A record in the clear, whatever the keys: the ClientHello, a CCS, an
 * alert before there are keys. */
static elpis_tls_err_t put_plain(elpis_tls_t *t, uint8_t type, uint8_t minor,
                                 const uint8_t *p, size_t n)
{
    elpis_tls_err_t e = ELPIS_TLS_OK;
    uint8_t *r = buf_grow(&t->out, 5 + n, OUT_LIMIT, &e);
    if (r == NULL)
        return e;
    r[0] = type;
    r[1] = 3;
    r[2] = minor;
    elpis_put16(r + 3, (uint16_t)n);
    memcpy(r + 5, p, n);
    return ELPIS_TLS_OK;
}

/* Content of `type`, encrypted once there are write keys, split into
 * records of at most 2^14 bytes. */
static elpis_tls_err_t put_record(elpis_tls_t *t, uint8_t type,
                                  const uint8_t *p, size_t n)
{
    do {
        size_t take = n > ELPIS_TLS_MAX_PLAIN ? ELPIS_TLS_MAX_PLAIN : n;
        elpis_tls_err_t e = ELPIS_TLS_OK;

        if (t->wr_on) {
            size_t clen = take + 1u + ELPIS_AEAD_TAG_LEN;
            uint8_t nonce[12];
            uint8_t *r = buf_grow(&t->out, 5 + clen, OUT_LIMIT, &e);
            if (r == NULL)
                return e;
            r[0] = CT_APP;
            r[1] = 3;
            r[2] = 3;
            elpis_put16(r + 3, (uint16_t)clen);
            memcpy(r + 5, p, take);
            r[5 + take] = type;
            make_nonce(nonce, t->wr_iv, t->wr_seq++);
            elpis_aead_seal(&t->wr, nonce, r, 5, r + 5, take + 1u, r + 5,
                            r + 5 + take + 1u);
        } else {
            e = put_plain(t, type, 3, p, take);
            if (e != ELPIS_TLS_OK)
                return e;
        }
        p += take;
        n -= take;
    } while (n > 0);
    return ELPIS_TLS_OK;
}

/* End the connection: note why, queue an alert unless told not to, and
 * forget every key once the alert is sealed. */
static void fail(elpis_tls_t *t, elpis_tls_err_t why, uint8_t alert)
{
    if (t->state == ELPIS_TLS_FAILED || t->state == ELPIS_TLS_CLOSED)
        return;
    t->state = ELPIS_TLS_FAILED;
    t->err = why;
    if (alert != AL_NONE) {
        uint8_t a[2];
        a[0] = 2;                       /* fatal */
        a[1] = alert;
        t->alert = alert;
        (void)put_record(t, CT_ALERT, a, 2);
    }
    wipe_secrets(t);
    elpis_aead_wipe(&t->rd);
    elpis_aead_wipe(&t->wr);
    t->rd_on = t->wr_on = 0;
}

static void fail_buf(elpis_tls_t *t, elpis_tls_err_t e)
{
    fail(t, e, e == ELPIS_TLS_E_NOMEM ? AL_INTERNAL_ERROR : AL_RECORD_OVERFLOW);
}

/* ------------------------------------------------------------------ */
/* The handshake                                                       */
/* ------------------------------------------------------------------ */

static void on_server_hello(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    rd_t r = rd_make(msg + 4, n - 4), ext;
    const uint8_t *random, *sid, *share = NULL;
    unsigned version, sid_len, suite, comp;
    int have_version = 0;
    uint8_t shared[32];

    version = rd_u16(&r);
    random  = rd_bytes(&r, 32);
    sid_len = rd_u8(&r);
    sid     = rd_bytes(&r, sid_len);
    suite   = rd_u16(&r);
    comp    = rd_u8(&r);
    if (r.bad) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    if (memcmp(random, hrr_random, 32) == 0) {
        fail(t, ELPIS_TLS_E_HRR, AL_HANDSHAKE_FAILURE);
        return;
    }
    /* A TLS 1.2 ServerHello can have no extensions at all. */
    if (r.n == 0) {
        fail(t, ELPIS_TLS_E_VERSION, AL_PROTOCOL_VERSION);
        return;
    }
    ext = rd_sub(&r, rd_u16(&r));
    if (ext.bad || r.n != 0) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    while (ext.n > 0) {
        unsigned type = rd_u16(&ext);
        rd_t d = rd_sub(&ext, rd_u16(&ext));

        if (ext.bad) {
            fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
            return;
        }
        switch (type) {
        case EXT_SUPPORTED_VERS:
            if (rd_u16(&d) != TLS13 || d.bad || d.n != 0) {
                fail(t, ELPIS_TLS_E_VERSION, AL_PROTOCOL_VERSION);
                return;
            }
            have_version = 1;
            break;
        case EXT_KEY_SHARE: {
            unsigned group = rd_u16(&d);
            size_t klen = rd_u16(&d);
            share = rd_bytes(&d, klen);
            if (d.bad || d.n != 0) {
                fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
                return;
            }
            if (group != GROUP_X25519 || klen != 32) {
                fail(t, ELPIS_TLS_E_PARAM, AL_ILLEGAL_PARAMETER);
                return;
            }
            break;
        }
        default:
            /* Including pre_shared_key: we offered none. */
            fail(t, ELPIS_TLS_E_PARAM, AL_UNSUPPORTED_EXT);
            return;
        }
    }

    if (!have_version || version != 0x0303) {
        fail(t, ELPIS_TLS_E_VERSION, AL_PROTOCOL_VERSION);
        return;
    }
    if (sid_len != t->sid_len || (sid_len > 0 && memcmp(sid, t->sid, sid_len) != 0) ||
        (suite != SUITE_AES128GCM && suite != SUITE_CHACHA) || comp != 0) {
        fail(t, ELPIS_TLS_E_PARAM, AL_ILLEGAL_PARAMETER);
        return;
    }
    if (share == NULL) {
        fail(t, ELPIS_TLS_E_PARAM, AL_MISSING_EXTENSION);
        return;
    }
    if (elpis_x25519(shared, t->priv, share) != 0) {
        elpis_wipe(shared, sizeof shared);
        fail(t, ELPIS_TLS_E_PARAM, AL_ILLEGAL_PARAMETER);
        return;
    }
    elpis_wipe(t->priv, sizeof t->priv);
    t->suite = (uint16_t)suite;

    transcript_add(t, msg, n);
    {
        uint8_t early[32], salt[32];
        elpis_hkdf_extract(zeros32, 32, zeros32, 32, early);
        derived(early, salt);
        elpis_hkdf_extract(salt, 32, shared, 32, t->hs_secret);
        elpis_wipe(early, sizeof early);
        elpis_wipe(salt, sizeof salt);
    }
    elpis_wipe(shared, sizeof shared);
    derive(t, t->hs_secret, "c hs traffic", t->c_secret);
    derive(t, t->hs_secret, "s hs traffic", t->s_secret);
    set_keys(t, 0, t->s_secret);
    set_keys(t, 1, t->c_secret);
    t->hs = HS_WAIT_EE;
}

static void on_encrypted_extensions(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    rd_t r = rd_make(msg + 4, n - 4);
    rd_t ext = rd_sub(&r, rd_u16(&r));

    if (ext.bad || r.n != 0) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    while (ext.n > 0) {
        unsigned type = rd_u16(&ext);
        rd_t d = rd_sub(&ext, rd_u16(&ext));

        if (ext.bad) {
            fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
            return;
        }
        if (type == EXT_ALPN) {
            rd_t list;
            const uint8_t *name;
            size_t nlen;

            if (t->alpn[0] == '\0') {
                fail(t, ELPIS_TLS_E_PARAM, AL_UNSUPPORTED_EXT);
                return;
            }
            list = rd_sub(&d, rd_u16(&d));
            nlen = rd_u8(&list);
            name = rd_bytes(&list, nlen);
            if (list.bad || list.n != 0 || d.bad || d.n != 0) {
                fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
                return;
            }
            if (nlen != strlen(t->alpn) || memcmp(name, t->alpn, nlen) != 0) {
                fail(t, ELPIS_TLS_E_ALPN, AL_ILLEGAL_PARAMETER);
                return;
            }
            t->alpn_ok = 1;
        }
        /* Anything else -- server_name, supported_groups, record limits --
         * changes nothing for us. */
    }
    t->hs = HS_WAIT_CERT_CR;
}

static void on_cert_request(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    rd_t r = rd_make(msg + 4, n - 4);
    size_t clen = rd_u8(&r);
    const uint8_t *ctx = rd_bytes(&r, clen);

    (void)rd_sub(&r, rd_u16(&r));
    if (r.bad || r.n != 0) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    memcpy(t->cr_ctx, ctx, clen);
    t->cr_ctx_len = (uint8_t)clen;
    t->cert_req = 1;
    t->hs = HS_WAIT_CERT;
}

/* The outline of a Certificate or CertificateVerify, nothing more. */
static int cert_shape_ok(const uint8_t *msg, size_t n, int verify)
{
    rd_t r = rd_make(msg + 4, n - 4);
    if (verify) {
        (void)rd_u16(&r);
        (void)rd_sub(&r, rd_u16(&r));
    } else {
        (void)rd_sub(&r, rd_u8(&r));
        (void)rd_sub(&r, rd_u24(&r));
    }
    return !r.bad && r.n == 0;
}

static void on_finished(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    uint8_t fk[32], th[32], want[32], master[32], salt[32], c_ap[32], s_ap[32];
    uint8_t m[4 + 32];
    elpis_tls_err_t e;

    if (n != 4 + 32) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    elpis_hkdf_expand_label(t->s_secret, "finished", NULL, 0, fk, 32);
    transcript_hash(t, th);
    elpis_hmac_sha256(fk, 32, th, 32, want);
    if (elpis_ct_memcmp(want, msg + 4, 32) != 0) {
        fail(t, ELPIS_TLS_E_FINISHED, AL_DECRYPT_ERROR);
        return;
    }
    transcript_add(t, msg, n);

    /* The application secrets hang off the transcript up to here. */
    derived(t->hs_secret, salt);
    elpis_hkdf_extract(salt, 32, zeros32, 32, master);
    derive(t, master, "c ap traffic", c_ap);
    derive(t, master, "s ap traffic", s_ap);

    /* Our flight, under the client handshake key. */
    if (t->compat) {
        static const uint8_t one = 1;
        e = put_plain(t, CT_CCS, 3, &one, 1);
        if (e != ELPIS_TLS_OK)
            goto fail_buf;
    }
    if (t->cert_req) {
        uint8_t c[4 + 1 + 255 + 3];
        size_t cl = 4u + 1u + t->cr_ctx_len + 3u;
        c[0] = HT_CERT;
        put24(c + 1, cl - 4);
        c[4] = t->cr_ctx_len;
        memcpy(c + 5, t->cr_ctx, t->cr_ctx_len);
        put24(c + 5 + t->cr_ctx_len, 0);     /* no certificates */
        transcript_add(t, c, cl);
        e = put_record(t, CT_HS, c, cl);
        if (e != ELPIS_TLS_OK)
            goto fail_buf;
    }
    elpis_hkdf_expand_label(t->c_secret, "finished", NULL, 0, fk, 32);
    transcript_hash(t, th);
    m[0] = HT_FINISHED;
    put24(m + 1, 32);
    elpis_hmac_sha256(fk, 32, th, 32, m + 4);
    transcript_add(t, m, sizeof m);
    e = put_record(t, CT_HS, m, sizeof m);
    if (e != ELPIS_TLS_OK)
        goto fail_buf;

    memcpy(t->c_secret, c_ap, 32);
    memcpy(t->s_secret, s_ap, 32);
    set_keys(t, 0, t->s_secret);
    set_keys(t, 1, t->c_secret);
    elpis_wipe(t->hs_secret, sizeof t->hs_secret);
    t->hs = HS_DONE;
    t->state = ELPIS_TLS_OPEN;
    goto out;

fail_buf:
    fail_buf(t, e);
out:
    elpis_wipe(fk, sizeof fk);
    elpis_wipe(master, sizeof master);
    elpis_wipe(salt, sizeof salt);
    elpis_wipe(c_ap, sizeof c_ap);
    elpis_wipe(s_ap, sizeof s_ap);
}

/* KeyUpdate (RFC 8446 4.6.3): the server's next key, and ours too when it
 * asks. */
static void on_key_update(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    uint8_t next[32];

    if (n != 5 || msg[4] > 1) {
        fail(t, n != 5 ? ELPIS_TLS_E_DECODE : ELPIS_TLS_E_PARAM,
             n != 5 ? AL_DECODE_ERROR : AL_ILLEGAL_PARAMETER);
        return;
    }
    elpis_hkdf_expand_label(t->s_secret, "traffic upd", NULL, 0, next, 32);
    memcpy(t->s_secret, next, 32);
    set_keys(t, 0, t->s_secret);

    if (msg[4] == 1 && !t->sent_close) {
        static const uint8_t ku[5] = { HT_KEY_UPDATE, 0, 0, 1, 0 };
        elpis_tls_err_t e = put_record(t, CT_HS, ku, sizeof ku);
        if (e != ELPIS_TLS_OK) {
            fail_buf(t, e);
            return;
        }
        elpis_hkdf_expand_label(t->c_secret, "traffic upd", NULL, 0, next, 32);
        memcpy(t->c_secret, next, 32);
        set_keys(t, 1, t->c_secret);
    }
    elpis_wipe(next, sizeof next);
}

/* One whole handshake message, header included. */
static void on_message(elpis_tls_t *t, const uint8_t *msg, size_t n)
{
    unsigned type = msg[0];

    switch (t->hs) {
    case HS_WAIT_SH:
        if (type != HT_SERVER_HELLO)
            break;
        on_server_hello(t, msg, n);
        return;
    case HS_WAIT_EE:
        if (type != HT_ENC_EXT)
            break;
        transcript_add(t, msg, n);
        on_encrypted_extensions(t, msg, n);
        return;
    case HS_WAIT_CERT_CR:
        if (type == HT_CERT_REQ) {
            transcript_add(t, msg, n);
            on_cert_request(t, msg, n);
            return;
        }
        /* fall through */
    case HS_WAIT_CERT:
        if (type != HT_CERT)
            break;
        if (!cert_shape_ok(msg, n, 0)) {
            fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
            return;
        }
        transcript_add(t, msg, n);
        t->hs = HS_WAIT_CV;
        return;
    case HS_WAIT_CV:
        if (type != HT_CERT_VERIFY)
            break;
        if (!cert_shape_ok(msg, n, 1)) {
            fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
            return;
        }
        transcript_add(t, msg, n);
        t->hs = HS_WAIT_FIN;
        return;
    case HS_WAIT_FIN:
        if (type != HT_FINISHED)
            break;
        on_finished(t, msg, n);
        return;
    case HS_DONE:
        if (type == HT_NEW_TICKET)
            return;                     /* no resumption yet */
        if (type == HT_KEY_UPDATE) {
            on_key_update(t, msg, n);
            return;
        }
        break;
    default:
        break;
    }
    fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
}

/* Handshake bytes from a record: join them into messages and act on each.
 * The keys change after the ServerHello and the Finished, and a message
 * may not straddle that, so nothing may be left over then. */
static void on_handshake(elpis_tls_t *t, const uint8_t *p, size_t n)
{
    elpis_tls_err_t e;

    if (n == 0) {
        fail(t, ELPIS_TLS_E_DECODE, AL_UNEXPECTED);
        return;
    }
    e = buf_put(&t->hsbuf, p, n, ELPIS_TLS_MAX_HSMSG + 4u + ELPIS_TLS_MAX_PLAIN);
    if (e != ELPIS_TLS_OK) {
        fail_buf(t, e);
        return;
    }
    while (t->state == ELPIS_TLS_HANDSHAKE || t->state == ELPIS_TLS_OPEN) {
        size_t live = buf_live(&t->hsbuf), mlen;
        const uint8_t *m = t->hsbuf.p + t->hsbuf.off;
        unsigned before = t->hs;

        if (live < 4)
            break;
        mlen = ((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3];
        if (mlen > ELPIS_TLS_MAX_HSMSG) {
            fail(t, ELPIS_TLS_E_TOOBIG, AL_DECODE_ERROR);
            return;
        }
        if (live < 4 + mlen)
            break;
        t->hsbuf.off += 4 + mlen;
        on_message(t, m, 4 + mlen);

        if ((before == HS_WAIT_SH || before == HS_WAIT_FIN) &&
            t->hs != before && buf_live(&t->hsbuf) != 0) {
            fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
            return;
        }
    }
    if (t->hsbuf.off == t->hsbuf.len)
        t->hsbuf.off = t->hsbuf.len = 0;
}

static void on_alert(elpis_tls_t *t, const uint8_t *p, size_t n)
{
    if (n != 2) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    if (p[1] == AL_USER_CANCELED)
        return;                         /* a close_notify follows */
    if (p[1] == AL_CLOSE_NOTIFY && t->hs == HS_DONE) {
        t->state = ELPIS_TLS_CLOSED;
        return;
    }
    fail(t, ELPIS_TLS_E_ALERT, AL_NONE);
    t->alert = p[1];
}

/* A record's content, decrypted or never encrypted. */
static void on_content(elpis_tls_t *t, uint8_t type, const uint8_t *p, size_t n)
{
    /* Handshake messages may not have other records between their parts. */
    if (type != CT_HS && buf_live(&t->hsbuf) != 0) {
        fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        return;
    }
    switch (type) {
    case CT_HS:
        on_handshake(t, p, n);
        break;
    case CT_ALERT:
        on_alert(t, p, n);
        break;
    case CT_APP:
        if (t->hs != HS_DONE) {
            fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        } else {
            elpis_tls_err_t e = buf_put(&t->app, p, n, ELPIS_TLS_MAX_APPBUF);
            if (e != ELPIS_TLS_OK)
                fail(t, e, AL_INTERNAL_ERROR);
        }
        break;
    default:
        fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        break;
    }
}

/* One whole record, header included, in t->rec (decrypted in place). */
static void on_record(elpis_tls_t *t, uint8_t *r, size_t len)
{
    uint8_t type = r[0], nonce[12];
    uint8_t *body = r + 5;
    size_t blen = len - 5, i;

    /* RFC 8446 5: a CCS of one byte 0x01 may arrive any time before the
     * server's Finished, for middleboxes' sake, and is dropped. */
    if (type == CT_CCS) {
        if (t->hs == HS_DONE || blen != 1 || body[0] != 1)
            fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        return;
    }
    /* An alert in the clear: before keys, or from a server that failed
     * before it could encrypt one. */
    if (type == CT_ALERT && (!t->rd_on || t->hs != HS_DONE)) {
        on_alert(t, body, blen);
        return;
    }
    if (!t->rd_on) {
        if (type == CT_HS)
            on_content(t, CT_HS, body, blen);
        else
            fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        return;
    }
    if (type != CT_APP) {
        fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        return;
    }
    if (blen < 1u + ELPIS_AEAD_TAG_LEN) {
        fail(t, ELPIS_TLS_E_DECODE, AL_DECODE_ERROR);
        return;
    }
    make_nonce(nonce, t->rd_iv, t->rd_seq);
    if (elpis_aead_open(&t->rd, nonce, r, 5, body, blen - ELPIS_AEAD_TAG_LEN,
                        body + blen - ELPIS_AEAD_TAG_LEN, body) != 0) {
        fail(t, ELPIS_TLS_E_DECRYPT, AL_BAD_RECORD_MAC);
        return;
    }
    t->rd_seq++;

    /* The real content type is the last non-zero byte; zeros after it are
     * padding. */
    i = blen - ELPIS_AEAD_TAG_LEN;
    while (i > 0 && body[i - 1] == 0)
        i--;
    if (i == 0) {
        fail(t, ELPIS_TLS_E_UNEXPECTED, AL_UNEXPECTED);
        return;
    }
    if (i - 1 > ELPIS_TLS_MAX_PLAIN) {
        fail(t, ELPIS_TLS_E_TOOBIG, AL_RECORD_OVERFLOW);
        return;
    }
    on_content(t, body[i - 1], body, i - 1);
}

/* ------------------------------------------------------------------ */
/* The interface                                                       */
/* ------------------------------------------------------------------ */

static int start(elpis_tls_t *t, const uint8_t *ch, size_t n)
{
    elpis_sha256_init(&t->transcript);
    transcript_add(t, ch, n);
    t->hs = HS_WAIT_SH;
    t->state = ELPIS_TLS_HANDSHAKE;
    /* The first ClientHello's record says TLS 1.0, as RFC 8446 5.1 has it. */
    return put_plain(t, CT_HS, 1, ch, n) == ELPIS_TLS_OK ? 0 : -1;
}

int elpis_tls_init(elpis_tls_t *t, const char *alpn, const char *sni)
{
    uint8_t ch[512], pub[32];
    size_t n = 0, alen = alpn ? strlen(alpn) : 0, slen = sni ? strlen(sni) : 0;
    size_t extat, i;
    int aes_first, rc;

    memset(t, 0, sizeof *t);
    if (alen >= sizeof t->alpn || slen > 253)
        return -1;
    if (alen > 0)
        memcpy(t->alpn, alpn, alen);

    elpis_random_bytes(t->priv, 32);
    elpis_x25519_base(pub, t->priv);
    /* A session id makes this the middlebox compatibility mode of RFC 8446
     * D.4: the server answers it with a CCS, and so do we. */
    t->sid_len = 32;
    elpis_random_bytes(t->sid, 32);
    t->compat = 1;

    ch[n++] = HT_CLIENT_HELLO;
    n += 3;                                     /* length, below */
    elpis_put16(ch + n, 0x0303);  n += 2;
    elpis_random_bytes(ch + n, 32);  n += 32;
    ch[n++] = 32;
    memcpy(ch + n, t->sid, 32);  n += 32;

    /* AES-GCM first only where AES-NI makes it the faster of the two. */
    aes_first = strcmp(elpis_aes_backend(), "aes-ni") == 0;
    elpis_put16(ch + n, 4);  n += 2;
    elpis_put16(ch + n, aes_first ? SUITE_AES128GCM : SUITE_CHACHA);  n += 2;
    elpis_put16(ch + n, aes_first ? SUITE_CHACHA : SUITE_AES128GCM);  n += 2;
    ch[n++] = 1;                                /* compression: null */
    ch[n++] = 0;

    extat = n;
    n += 2;

    elpis_put16(ch + n, EXT_SUPPORTED_VERS);  n += 2;
    elpis_put16(ch + n, 3);  n += 2;
    ch[n++] = 2;
    elpis_put16(ch + n, TLS13);  n += 2;

    elpis_put16(ch + n, EXT_SUPPORTED_GROUPS);  n += 2;
    elpis_put16(ch + n, 4);  n += 2;
    elpis_put16(ch + n, 2);  n += 2;
    elpis_put16(ch + n, GROUP_X25519);  n += 2;

    elpis_put16(ch + n, EXT_KEY_SHARE);  n += 2;
    elpis_put16(ch + n, 2 + 4 + 32);  n += 2;
    elpis_put16(ch + n, 4 + 32);  n += 2;
    elpis_put16(ch + n, GROUP_X25519);  n += 2;
    elpis_put16(ch + n, 32);  n += 2;
    memcpy(ch + n, pub, 32);  n += 32;

    elpis_put16(ch + n, EXT_SIG_ALGS);  n += 2;
    elpis_put16(ch + n, (uint16_t)(2 + 2 * ELPIS_ARRAY_LEN(sig_algs)));  n += 2;
    elpis_put16(ch + n, (uint16_t)(2 * ELPIS_ARRAY_LEN(sig_algs)));  n += 2;
    for (i = 0; i < ELPIS_ARRAY_LEN(sig_algs); i++) {
        elpis_put16(ch + n, sig_algs[i]);
        n += 2;
    }

    if (alen > 0) {
        elpis_put16(ch + n, EXT_ALPN);  n += 2;
        elpis_put16(ch + n, (uint16_t)(2 + 1 + alen));  n += 2;
        elpis_put16(ch + n, (uint16_t)(1 + alen));  n += 2;
        ch[n++] = (uint8_t)alen;
        memcpy(ch + n, alpn, alen);  n += alen;
    }
    if (slen > 0) {
        elpis_put16(ch + n, EXT_SERVER_NAME);  n += 2;
        elpis_put16(ch + n, (uint16_t)(2 + 1 + 2 + slen));  n += 2;
        elpis_put16(ch + n, (uint16_t)(1 + 2 + slen));  n += 2;
        ch[n++] = 0;                            /* host_name */
        elpis_put16(ch + n, (uint16_t)slen);  n += 2;
        memcpy(ch + n, sni, slen);  n += slen;
    }

    elpis_put16(ch + extat, (uint16_t)(n - extat - 2));
    put24(ch + 1, n - 4);

    rc = start(t, ch, n);
    elpis_wipe(pub, sizeof pub);
    if (rc != 0)
        elpis_tls_free(t);
    return rc;
}

void elpis_tls_free(elpis_tls_t *t)
{
    buf_release(&t->rec);
    buf_release(&t->hsbuf);
    buf_release(&t->out);
    buf_release(&t->app);
    elpis_wipe(t, sizeof *t);
}

size_t elpis_tls_out(const elpis_tls_t *t, const uint8_t **p)
{
    size_t n = buf_live(&t->out);
    *p = n > 0 ? t->out.p + t->out.off : NULL;
    return n;
}

void elpis_tls_out_done(elpis_tls_t *t, size_t n)
{
    if (n > buf_live(&t->out))
        n = buf_live(&t->out);
    t->out.off += n;
    if (t->out.off == t->out.len)
        t->out.off = t->out.len = 0;
}

elpis_tls_state_t elpis_tls_feed(elpis_tls_t *t, const uint8_t *in, size_t n)
{
    while (n > 0 &&
           (t->state == ELPIS_TLS_HANDSHAKE || t->state == ELPIS_TLS_OPEN)) {
        size_t want = t->rec.len < 5 ? 5 : 5u + elpis_get16(t->rec.p + 3);
        size_t take = want - t->rec.len;
        elpis_tls_err_t e;

        if (take > n)
            take = n;
        e = buf_put(&t->rec, in, take, 5u + ELPIS_TLS_MAX_RECORD);
        if (e != ELPIS_TLS_OK) {
            fail_buf(t, e);
            break;
        }
        in += take;
        n  -= take;

        if (t->rec.len == 5) {
            uint8_t type = t->rec.p[0];
            size_t len = elpis_get16(t->rec.p + 3);
            /* Not TLS at all -- an HTTP or DNS reply on 853 -- shows here. */
            if (type < CT_CCS || type > CT_APP || t->rec.p[1] != 3) {
                fail(t, ELPIS_TLS_E_DECODE, AL_UNEXPECTED);
                break;
            }
            if (len > ELPIS_TLS_MAX_RECORD) {
                fail(t, ELPIS_TLS_E_TOOBIG, AL_RECORD_OVERFLOW);
                break;
            }
        }
        if (t->rec.len >= 5 && t->rec.len == 5u + elpis_get16(t->rec.p + 3)) {
            on_record(t, t->rec.p, t->rec.len);
            t->rec.len = 0;
        }
    }
    return t->state;
}

int elpis_tls_write(elpis_tls_t *t, const uint8_t *p, size_t n)
{
    size_t records, need;
    elpis_tls_err_t e;

    if (t->state != ELPIS_TLS_OPEN || t->sent_close)
        return -1;
    if (n == 0)
        return 0;
    records = (n + ELPIS_TLS_MAX_PLAIN - 1) / ELPIS_TLS_MAX_PLAIN;
    need = n + records * (5u + 1u + ELPIS_AEAD_TAG_LEN);
    if (need > OUT_LIMIT - buf_live(&t->out))
        return -1;                      /* the caller is not sending */
    e = put_record(t, CT_APP, p, n);
    if (e != ELPIS_TLS_OK) {
        fail_buf(t, e);
        return -1;
    }
    return 0;
}

size_t elpis_tls_pending(const elpis_tls_t *t)
{
    return buf_live(&t->app);
}

size_t elpis_tls_read(elpis_tls_t *t, uint8_t *buf, size_t cap)
{
    size_t n = buf_live(&t->app);
    if (n > cap)
        n = cap;
    if (n > 0)
        memcpy(buf, t->app.p + t->app.off, n);
    t->app.off += n;
    if (t->app.off == t->app.len)
        t->app.off = t->app.len = 0;
    return n;
}

void elpis_tls_close(elpis_tls_t *t)
{
    static const uint8_t cn[2] = { 1, AL_CLOSE_NOTIFY };    /* warning */

    if (t->sent_close || !t->wr_on || t->hs != HS_DONE)
        return;
    t->sent_close = 1;
    (void)put_record(t, CT_ALERT, cn, sizeof cn);
}

void elpis_tls_trim(elpis_tls_t *t)
{
    if (t->rec.len == 0)
        buf_release(&t->rec);
    if (buf_live(&t->hsbuf) == 0)
        buf_release(&t->hsbuf);
    if (buf_live(&t->out) == 0)
        buf_release(&t->out);
    if (buf_live(&t->app) == 0)
        buf_release(&t->app);
}

const char *elpis_tls_err_name(elpis_tls_err_t e)
{
    static const char *const names[ELPIS_TLS_E_COUNT] = {
        "ok", "alert", "hello-retry", "version", "alpn", "decode",
        "unexpected", "decrypt", "finished", "parameter", "too-big", "no-memory"
    };
    return (unsigned)e < ELPIS_TLS_E_COUNT ? names[e] : "?";
}

const char *elpis_tls_suite_name(uint16_t suite)
{
    switch (suite) {
    case SUITE_AES128GCM: return "TLS_AES_128_GCM_SHA256";
    case SUITE_CHACHA:    return "TLS_CHACHA20_POLY1305_SHA256";
    default:              return "none";
    }
}

#ifdef ELPIS_TLS_TESTING
int elpis_tls_init_raw(elpis_tls_t *t, const uint8_t *ch, size_t chlen,
                       const uint8_t priv[32])
{
    memset(t, 0, sizeof *t);
    /* type(1) len(3) version(2) random(32), then the session id. */
    if (chlen < 39 || ch[0] != HT_CLIENT_HELLO || ch[38] > 32 ||
        chlen < 39u + ch[38])
        return -1;
    t->sid_len = ch[38];
    memcpy(t->sid, ch + 39, t->sid_len);
    t->compat = t->sid_len > 0;
    memcpy(t->priv, priv, 32);
    return start(t, ch, chlen);
}

void elpis_tls_test_plain(elpis_tls_t *t, uint8_t type, const uint8_t *p,
                          size_t n)
{
    if (t->state == ELPIS_TLS_HANDSHAKE || t->state == ELPIS_TLS_OPEN)
        on_content(t, type, p, n);
}
#endif
