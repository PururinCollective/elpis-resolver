/*
 * elpis/edns.h -- EDNS(0) option assembly and DNS cookies.
 */
#ifndef ELPIS_EDNS_H
#define ELPIS_EDNS_H

#include "elpis/msg.h"
#include "elpis/util.h"

typedef struct {
    uint16_t bufsize;
    unsigned do_bit    : 1;
    unsigned want_nsid : 1;
    unsigned have_cookie : 1;
    unsigned have_keepalive : 1;
    uint8_t  cookie[40];
    uint8_t  cookie_len;
    int      ede_code;          /* -1 for none */
    const char *ede_text;       /* optional, may be NULL */
    uint16_t keepalive;         /* idle timeout, 100 ms units */
    uint16_t pad_to;            /* pad the message to a multiple; 0 = off */
    const char *nsid;           /* server identifier to echo back */
} elpis_edns_t;

void elpis_edns_init(elpis_edns_t *e, uint16_t bufsize, int do_bit);

/* Append the OPT pseudo-record to a message under construction. */
int  elpis_edns_write(elpis_bld_t *b, const elpis_edns_t *e, unsigned rcode);

/* ---- DNS cookies (RFC 7873, RFC 9018) ---------------------------- */
#define ELPIS_COOKIE_SECRET_LEN 16
#define ELPIS_COOKIE_CLIENT_LEN 8
#define ELPIS_COOKIE_SERVER_LEN 16     /* version + reserved + ts + hash */

void elpis_cookie_init(void);
/* Rotate the server secret; the previous one stays valid for one period. */
void elpis_cookie_rotate(void);

/*
 * Build the 24-byte client+server cookie for `client` in response to the
 * 8-byte client cookie `cc`.
 */
void elpis_cookie_server(const uint8_t cc[8], const elpis_addr_t *client,
                         uint8_t out[24]);

/* Returns 1 when `cookie` (len 8..40) carries a server cookie we minted. */
int  elpis_cookie_verify(const uint8_t *cookie, size_t len,
                         const elpis_addr_t *client);

/* Per-upstream client cookie, derived from a process secret and the peer. */
void elpis_cookie_client(const elpis_addr_t *server, uint8_t out[8]);

uint64_t elpis_siphash24(const uint8_t key[16], const uint8_t *m, size_t n);

#endif /* ELPIS_EDNS_H */
