/*
 * elpis/tls.h -- a TLS 1.3 client for DNS over TLS to authoritative servers.
 *
 * Bytes in, bytes out: the engine owns no socket and never blocks.  The
 * caller sends what elpis_tls_out() has queued, feeds in whatever arrives
 * with elpis_tls_feed(), writes queries with elpis_tls_write() once the state
 * is ELPIS_TLS_OPEN, and takes answers out with elpis_tls_read().
 *
 * It is opportunistic, as RFC 9539 has it: the server's certificate is
 * hashed into the transcript and otherwise ignored, because an NS record
 * names no identity to check it against.  The server's Finished is still
 * verified, which proves both ends derived the same keys.  So this stops a
 * passive watcher, not an active attacker -- who could only push the
 * resolver back to plain DNS anyway.
 *
 * Only what DoT needs: TLS 1.3, X25519, TLS_AES_128_GCM_SHA256 and
 * TLS_CHACHA20_POLY1305_SHA256, ALPN "dot".  No PSK, resumption or 0-RTT yet.
 */
#ifndef ELPIS_TLS_H
#define ELPIS_TLS_H

#include "elpis/common.h"
#include "elpis/crypto.h"
#include "elpis/tlscrypto.h"

typedef enum {
    ELPIS_TLS_HANDSHAKE = 0,
    ELPIS_TLS_OPEN,          /* handshake done: application data flows   */
    ELPIS_TLS_CLOSED,        /* the server sent close_notify              */
    ELPIS_TLS_FAILED         /* see err; an alert may be queued to send   */
} elpis_tls_state_t;

/* Why a connection failed.  The status page counts these. */
typedef enum {
    ELPIS_TLS_OK = 0,
    ELPIS_TLS_E_ALERT,       /* the server sent an alert (in `alert`)     */
    ELPIS_TLS_E_HRR,         /* HelloRetryRequest: it wants another group */
    ELPIS_TLS_E_VERSION,     /* it does not speak TLS 1.3                 */
    ELPIS_TLS_E_ALPN,        /* it chose an ALPN other than ours          */
    ELPIS_TLS_E_DECODE,      /* a malformed record or message             */
    ELPIS_TLS_E_UNEXPECTED,  /* a message out of order                    */
    ELPIS_TLS_E_DECRYPT,     /* a record failed its tag                   */
    ELPIS_TLS_E_FINISHED,    /* its Finished did not verify               */
    ELPIS_TLS_E_PARAM,       /* something we did not offer, or a bad key  */
    ELPIS_TLS_E_TOOBIG,      /* over a record, message or buffer limit    */
    ELPIS_TLS_E_NOMEM,
    ELPIS_TLS_E_COUNT
} elpis_tls_err_t;

/* Limits.  A handshake message is mostly the certificate chain. */
#define ELPIS_TLS_MAX_PLAIN   16384u
#define ELPIS_TLS_MAX_RECORD  (ELPIS_TLS_MAX_PLAIN + 256u)
#define ELPIS_TLS_MAX_HSMSG   65536u
#define ELPIS_TLS_MAX_APPBUF  (1024u * 1024u)

typedef struct {
    uint8_t *p;
    size_t   len, cap, off;     /* live bytes are p[off .. len) */
} elpis_tls_buf_t;

typedef struct {
    elpis_tls_state_t state;
    elpis_tls_err_t   err;
    uint8_t           alert;      /* received, or sent when we failed     */
    uint8_t           hs;         /* where the handshake is (tls.c)       */
    uint16_t          suite;      /* 0x1301 or 0x1303 once chosen         */
    unsigned          compat   : 1;   /* sent a session id: send a CCS     */
    unsigned          cert_req : 1;   /* the server asked for a client cert */
    unsigned          alpn_ok  : 1;   /* the server chose our ALPN          */
    unsigned          rd_on    : 1;
    unsigned          wr_on    : 1;
    unsigned          sent_close : 1; /* our close_notify is queued       */

    char              alpn[16];       /* offered, "" for none              */
    uint8_t           sid[32];
    uint8_t           sid_len;
    uint8_t           priv[32];       /* X25519, wiped once used           */
    uint8_t           cr_ctx[255];    /* CertificateRequest context        */
    uint8_t           cr_ctx_len;

    elpis_sha256_t    transcript;
    uint8_t           hs_secret[32];
    uint8_t           c_secret[32];   /* client traffic secret, current     */
    uint8_t           s_secret[32];   /* server traffic secret, current     */

    elpis_aead_t      rd, wr;
    uint8_t           rd_iv[12], wr_iv[12];
    uint64_t          rd_seq, wr_seq;

    elpis_tls_buf_t   rec;            /* a record coming in                 */
    elpis_tls_buf_t   hsbuf;          /* handshake messages being joined    */
    elpis_tls_buf_t   out;            /* records waiting to be sent         */
    elpis_tls_buf_t   app;            /* decrypted application data         */
} elpis_tls_t;

/*
 * Start a connection: queues the ClientHello.  `alpn` is "dot" for DoT, or
 * NULL to offer none; `sni` is NULL for no server_name.  0, or -1 when out
 * of memory or a name is too long.
 */
int  elpis_tls_init(elpis_tls_t *t, const char *alpn, const char *sni);
/* Wipe every key and free every buffer. */
void elpis_tls_free(elpis_tls_t *t);

/* Bytes waiting to go to the server (*p is NULL when there are none), and
 * how many of them went. */
size_t elpis_tls_out(const elpis_tls_t *t, const uint8_t **p);
void   elpis_tls_out_done(elpis_tls_t *t, size_t n);

/* Bytes from the server, any amount: partial records are kept. */
elpis_tls_state_t elpis_tls_feed(elpis_tls_t *t, const uint8_t *in, size_t n);

/* Application data, only while OPEN.  0, or -1. */
int    elpis_tls_write(elpis_tls_t *t, const uint8_t *p, size_t n);
/* Decrypted bytes waiting, and taking them out. */
size_t elpis_tls_pending(const elpis_tls_t *t);
size_t elpis_tls_read(elpis_tls_t *t, uint8_t *buf, size_t cap);

/* Queue close_notify.  The caller sends it and closes the socket. */
void   elpis_tls_close(elpis_tls_t *t);

/* Release buffers that hold nothing, for a connection sitting idle. */
void   elpis_tls_trim(elpis_tls_t *t);

const char *elpis_tls_err_name(elpis_tls_err_t e);
const char *elpis_tls_suite_name(uint16_t suite);

#ifdef ELPIS_TLS_TESTING
/*
 * For the self-test and the fuzzer only, never in bin/elpis.  init_raw
 * starts from a given ClientHello message and ephemeral key, so a published
 * trace (RFC 8448) can be replayed byte for byte.  test_plain hands the
 * engine a record's content as if it had just been decrypted.
 */
int  elpis_tls_init_raw(elpis_tls_t *t, const uint8_t *ch, size_t chlen,
                        const uint8_t priv[32]);
void elpis_tls_test_plain(elpis_tls_t *t, uint8_t type, const uint8_t *p,
                          size_t n);
#endif

#endif /* ELPIS_TLS_H */
