/*
 * tests/fuzz_tls.c -- libFuzzer harness for the TLS 1.3 client (tls.c).
 *
 * Everything an authoritative server sends on port 853 reaches the engine
 * before anything is trusted.  Most of it is encrypted, and random bytes
 * never get past a tag, so the first byte of each input picks where to aim:
 *
 *   0  raw bytes from the first one: records, alerts, the ServerHello
 *   1  after the RFC 8448 ServerHello, handshake content as if decrypted:
 *      EncryptedExtensions, CertificateRequest, Certificate, Finished
 *   2  after the whole RFC 8448 handshake, content as if decrypted, each
 *      piece with its own type: tickets, KeyUpdate, alerts, data
 *   3  after the whole handshake, raw records again
 *
 * The engine is built with ELPIS_TLS_TESTING for this, as for the self-test.
 *
 *   make fuzz
 *   mkdir -p bin/corpus-tls && cd bin && ./fuzz-tls -max_total_time=300 corpus-tls/
 */
#include "elpis/common.h"
#include "elpis/log.h"
#include "elpis/simd.h"
#include "elpis/tls.h"
#include "rfc8448.h"

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    int hi = -1;
    for (; *h; h++) {
        int v;
        if (*h >= '0' && *h <= '9')      v = *h - '0';
        else if (*h >= 'a' && *h <= 'f') v = *h - 'a' + 10;
        else continue;
        if (hi < 0) { hi = v; continue; }
        if (n < cap) out[n++] = (uint8_t)((hi << 4) | v);
        hi = -1;
    }
    return n;
}

static void drain(elpis_tls_t *t)
{
    const uint8_t *p;
    elpis_tls_out_done(t, elpis_tls_out(t, &p));
}

static void feed_hex(elpis_tls_t *t, const char *hex)
{
    static uint8_t b[1024];
    elpis_tls_feed(t, b, unhex(hex, b, sizeof b));
    drain(t);
}

static int start(elpis_tls_t *t, int stage)
{
    uint8_t ch[256], priv[32];
    size_t n = unhex(rfc8448_client_hello, ch, sizeof ch);

    unhex(rfc8448_client_priv, priv, sizeof priv);
    if (elpis_tls_init_raw(t, ch, n, priv) != 0)
        return -1;
    drain(t);
    if (stage >= 1)
        feed_hex(t, rfc8448_sh_record);
    if (stage >= 2) {
        feed_hex(t, rfc8448_server_flight);
        feed_hex(t, rfc8448_ticket_record);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int inited;
    static uint8_t rd[4096];
    elpis_tls_t t;
    unsigned mode;

    if (!inited) {
        elpis_log_init(ELPIS_LOG_DST_STDERR, NULL, ELPIS_LOG_ERROR);
        elpis_simd_init();
        inited = 1;
    }
    if (size < 1)
        return 0;
    mode = data[0] & 3u;
    data++;
    size--;

    if (start(&t, mode == 0 ? 0 : mode == 1 ? 1 : 2) != 0)
        return 0;

    switch (mode) {
    case 0:
    case 3:
        elpis_tls_feed(&t, data, size);
        break;
    case 1:
        /* [len][bytes] pieces of handshake content */
        while (size > 0) {
            size_t take = data[0];
            data++;
            size--;
            if (take > size)
                take = size;
            elpis_tls_test_plain(&t, 22, data, take);
            data += take;
            size -= take;
        }
        break;
    case 2:
        /* [type][len][bytes] pieces of content */
        while (size >= 2) {
            uint8_t type = data[0];
            size_t take = data[1];
            data += 2;
            size -= 2;
            if (take > size)
                take = size;
            elpis_tls_test_plain(&t, type, data, take);
            data += take;
            size -= take;
        }
        break;
    }

    while (elpis_tls_read(&t, rd, sizeof rd) > 0)
        ;
    (void)elpis_tls_write(&t, (const uint8_t *)"\x00\x0c", 2);
    elpis_tls_close(&t);
    drain(&t);
    elpis_tls_trim(&t);
    elpis_tls_free(&t);
    return 0;
}
