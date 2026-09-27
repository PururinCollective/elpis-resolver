/*
 * cookie.c -- DNS cookies (RFC 7873) with the RFC 9018 interoperable
 * server-cookie construction.
 *
 * Cookies are the cheapest spoofing defence available over plain UDP: an
 * off-path attacker cannot guess the 64-bit server cookie, so a forged
 * response is rejected before it can reach the cache.
 */
#include "elpis/edns.h"
#include "elpis/log.h"
#include "elpis/atomic.h"

#include <pthread.h>

/* ------------------------------------------------------------------ */
/* SipHash-2-4                                                         */
/* ------------------------------------------------------------------ */

#define SIPROUND                                   \
    do {                                           \
        v0 += v1; v1 = elpis_rotl64(v1, 13); v1 ^= v0; v0 = elpis_rotl64(v0, 32); \
        v2 += v3; v3 = elpis_rotl64(v3, 16); v3 ^= v2;                            \
        v0 += v3; v3 = elpis_rotl64(v3, 21); v3 ^= v0;                            \
        v2 += v1; v1 = elpis_rotl64(v1, 17); v1 ^= v2; v2 = elpis_rotl64(v2, 32); \
    } while (0)

/* Little-endian load, as the SipHash reference defines it. */
static uint64_t le64(const uint8_t *p)
{
    return  (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

uint64_t elpis_siphash24(const uint8_t key[16], const uint8_t *m, size_t n)
{
    uint64_t k0 = le64(key), k1 = le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ull ^ k0;
    uint64_t v1 = 0x646f72616e646f6dull ^ k1;
    uint64_t v2 = 0x6c7967656e657261ull ^ k0;
    uint64_t v3 = 0x7465646279746573ull ^ k1;
    uint64_t b  = ((uint64_t)n) << 56;
    size_t left = n & 7u;
    const uint8_t *end = m + n - left;

    for (; m != end; m += 8) {
        uint64_t mi = le64(m);
        v3 ^= mi;
        SIPROUND;
        SIPROUND;
        v0 ^= mi;
    }
    switch (left) {
    case 7: b |= (uint64_t)m[6] << 48; /* fallthrough */
    case 6: b |= (uint64_t)m[5] << 40; /* fallthrough */
    case 5: b |= (uint64_t)m[4] << 32; /* fallthrough */
    case 4: b |= (uint64_t)m[3] << 24; /* fallthrough */
    case 3: b |= (uint64_t)m[2] << 16; /* fallthrough */
    case 2: b |= (uint64_t)m[1] << 8;  /* fallthrough */
    case 1: b |= (uint64_t)m[0];       /* fallthrough */
    case 0: default: break;
    }
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ------------------------------------------------------------------ */
/* Server secrets                                                      */
/* ------------------------------------------------------------------ */

static pthread_rwlock_t g_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint8_t g_secret[2][ELPIS_COOKIE_SECRET_LEN];  /* [0] current, [1] old */
static uint8_t g_client_secret[ELPIS_COOKIE_SECRET_LEN];
static int     g_ready;

void elpis_cookie_init(void)
{
    pthread_rwlock_wrlock(&g_lock);
    if (!g_ready) {
        elpis_random_bytes(g_secret[0], sizeof g_secret[0]);
        memcpy(g_secret[1], g_secret[0], sizeof g_secret[0]);
        elpis_random_bytes(g_client_secret, sizeof g_client_secret);
        g_ready = 1;
    }
    pthread_rwlock_unlock(&g_lock);
}

void elpis_cookie_rotate(void)
{
    pthread_rwlock_wrlock(&g_lock);
    memcpy(g_secret[1], g_secret[0], sizeof g_secret[0]);
    elpis_random_bytes(g_secret[0], sizeof g_secret[0]);
    pthread_rwlock_unlock(&g_lock);
}

/* The client IP, without the port: cookies must survive NAT port changes. */
static size_t addr_bytes(const elpis_addr_t *a, uint8_t out[16])
{
    if (elpis_addr_family(a) == AF_INET) {
        memcpy(out, &a->u.v4.sin_addr, 4);
        return 4;
    }
    if (elpis_addr_family(a) == AF_INET6) {
        memcpy(out, &a->u.v6.sin6_addr, 16);
        return 16;
    }
    memset(out, 0, 16);
    return 0;
}

/*
 * RFC 9018 section 3: the server cookie is
 *   version(1) | reserved(3) | timestamp(4) | hash(8)
 * with the hash taken over client-cookie | version | reserved | timestamp |
 * client-IP using SipHash-2-4 keyed by the server secret.
 */
static void server_cookie_with(const uint8_t secret[ELPIS_COOKIE_SECRET_LEN],
                               const uint8_t cc[8], const elpis_addr_t *client,
                               uint32_t ts, uint8_t out[24])
{
    uint8_t msg[8 + 1 + 3 + 4 + 16];
    uint8_t ip[16];
    size_t iplen, n = 0;
    uint64_t h;

    iplen = addr_bytes(client, ip);

    memcpy(out, cc, 8);
    out[8]  = 1;               /* version */
    out[9]  = 0;
    out[10] = 0;
    out[11] = 0;
    elpis_put32(out + 12, ts);

    memcpy(msg + n, cc, 8);            n += 8;
    memcpy(msg + n, out + 8, 8);       n += 8;   /* version..timestamp */
    memcpy(msg + n, ip, iplen);        n += iplen;

    h = elpis_siphash24(secret, msg, n);
    elpis_put64(out + 16, h);
}

void elpis_cookie_server(const uint8_t cc[8], const elpis_addr_t *client,
                         uint8_t out[24])
{
    uint8_t secret[ELPIS_COOKIE_SECRET_LEN];

    if (!g_ready)
        elpis_cookie_init();
    pthread_rwlock_rdlock(&g_lock);
    memcpy(secret, g_secret[0], sizeof secret);
    pthread_rwlock_unlock(&g_lock);

    server_cookie_with(secret, cc, client, (uint32_t)elpis_wall_s(), out);
}

/* Accept cookies up to an hour old, and up to five minutes into the future
 * to tolerate modest clock skew between the client's view and ours. */
#define COOKIE_MAX_AGE   3600
#define COOKIE_MAX_SKEW  300

int elpis_cookie_verify(const uint8_t *cookie, size_t len,
                        const elpis_addr_t *client)
{
    uint8_t want[24];
    uint8_t secret[2][ELPIS_COOKIE_SECRET_LEN];
    uint32_t ts;
    int64_t now, age;
    int i;

    if (len != 24)
        return 0;                    /* only version 1 is minted here */
    if (cookie[8] != 1)
        return 0;

    ts  = elpis_get32(cookie + 12);
    now = elpis_wall_s();
    age = now - (int64_t)ts;
    if (age > COOKIE_MAX_AGE || age < -COOKIE_MAX_SKEW)
        return 0;

    if (!g_ready)
        elpis_cookie_init();
    pthread_rwlock_rdlock(&g_lock);
    memcpy(secret, g_secret, sizeof secret);
    pthread_rwlock_unlock(&g_lock);

    /* The previous secret stays valid across one rotation. */
    for (i = 0; i < 2; i++) {
        server_cookie_with(secret[i], cookie, client, ts, want);
        if (elpis_ct_memcmp(want + 16, cookie + 16, 8) == 0)
            return 1;
    }
    return 0;
}

void elpis_cookie_client(const elpis_addr_t *server, uint8_t out[8])
{
    uint8_t ip[16];
    size_t iplen;
    uint64_t h;
    uint8_t secret[ELPIS_COOKIE_SECRET_LEN];

    if (!g_ready)
        elpis_cookie_init();
    pthread_rwlock_rdlock(&g_lock);
    memcpy(secret, g_client_secret, sizeof secret);
    pthread_rwlock_unlock(&g_lock);

    iplen = addr_bytes(server, ip);
    h = elpis_siphash24(secret, ip, iplen);
    elpis_put64(out, h);
}
