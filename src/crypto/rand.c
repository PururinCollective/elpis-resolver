/*
 * rand.c -- randomness.
 *
 * DNS needs unpredictable values constantly: transaction IDs, source ports,
 * 0x20 case bits, cookie secrets.  Reading the OS pool for every one of them
 * would be a syscall per outbound query, so the OS seeds a per-thread
 * ChaCha20 stream and that stream serves the fast path.  The state is rekeyed
 * from its own output at intervals, so recovering it does not retroactively
 * expose earlier values.
 */
#include "elpis/crypto.h"
#include "elpis/util.h"
#include "elpis/log.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#if defined(__linux__)
#  include <sys/syscall.h>
#endif

/* ------------------------------------------------------------------ */
/* OS entropy                                                          */
/* ------------------------------------------------------------------ */

static int os_random(void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;

#if defined(__linux__) && defined(SYS_getrandom)
    while (n > 0) {
        long r = syscall(SYS_getrandom, p, n, 0);
        if (r > 0) {
            p += (size_t)r;
            n -= (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        break;               /* fall through to /dev/urandom */
    }
    if (n == 0)
        return ELPIS_OK;
#endif

    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
            return ELPIS_ERR;
        while (n > 0) {
            ssize_t r = read(fd, p, n);
            if (r > 0) {
                p += (size_t)r;
                n -= (size_t)r;
            } else if (r < 0 && errno == EINTR) {
                continue;
            } else {
                close(fd);
                return ELPIS_ERR;
            }
        }
        close(fd);
    }
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* ChaCha20 stream                                                     */
/* ------------------------------------------------------------------ */

#define QR(a, b, c, d)                              \
    do {                                            \
        a += b; d ^= a; d = elpis_rotl32(d, 16);    \
        c += d; b ^= c; b = elpis_rotl32(b, 12);    \
        a += b; d ^= a; d = elpis_rotl32(d, 8);     \
        c += d; b ^= c; b = elpis_rotl32(b, 7);     \
    } while (0)

static void chacha20_block(const uint32_t in[16], uint8_t out[64])
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
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        /* ChaCha serialises little-endian. */
        out[i * 4 + 0] = (uint8_t)v;
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
}

typedef struct {
    uint32_t state[16];
    uint8_t  buf[64];
    unsigned pos;
    uint64_t emitted;
    int      seeded;
} rng_t;

static ELPIS_TLS rng_t g_rng;

/* Rekey after this many bytes so old output cannot be rewound. */
#define RNG_REKEY_BYTES (1024 * 1024)

static void rng_seed_from_os(rng_t *r)
{
    uint8_t seed[40];       /* 32-byte key + 8-byte nonce */
    int i;

    if (os_random(seed, sizeof seed) != ELPIS_OK) {
        /*
         * Without OS entropy we cannot make unpredictable transaction IDs,
         * and a resolver that cannot do that is trivially poisoned.  Refuse
         * rather than pretend.
         */
        elpis_fatal("no OS entropy source available; refusing to run");
        abort();
    }

    r->state[0] = 0x61707865u;
    r->state[1] = 0x3320646eu;
    r->state[2] = 0x79622d32u;
    r->state[3] = 0x6b206574u;
    for (i = 0; i < 8; i++)
        r->state[4 + i] = (uint32_t)seed[i * 4] |
                          ((uint32_t)seed[i * 4 + 1] << 8) |
                          ((uint32_t)seed[i * 4 + 2] << 16) |
                          ((uint32_t)seed[i * 4 + 3] << 24);
    r->state[12] = 0;
    r->state[13] = 0;
    r->state[14] = (uint32_t)seed[32] | ((uint32_t)seed[33] << 8) |
                   ((uint32_t)seed[34] << 16) | ((uint32_t)seed[35] << 24);
    r->state[15] = (uint32_t)seed[36] | ((uint32_t)seed[37] << 8) |
                   ((uint32_t)seed[38] << 16) | ((uint32_t)seed[39] << 24);

    memset(seed, 0, sizeof seed);
    r->pos = sizeof r->buf;     /* force a refill */
    r->emitted = 0;
    r->seeded = 1;
}

/* Replace the key with fresh stream output (forward secrecy). */
static void rng_rekey(rng_t *r)
{
    uint8_t out[64];
    int i;

    r->state[12]++;
    if (r->state[12] == 0)
        r->state[13]++;
    chacha20_block(r->state, out);

    for (i = 0; i < 8; i++)
        r->state[4 + i] = (uint32_t)out[i * 4] |
                          ((uint32_t)out[i * 4 + 1] << 8) |
                          ((uint32_t)out[i * 4 + 2] << 16) |
                          ((uint32_t)out[i * 4 + 3] << 24);
    r->state[12] = 0;
    r->state[13] = 0;
    memset(out, 0, sizeof out);
    r->pos = sizeof r->buf;
    r->emitted = 0;
}

static void rng_refill(rng_t *r)
{
    r->state[12]++;
    if (r->state[12] == 0)
        r->state[13]++;
    chacha20_block(r->state, r->buf);
    r->pos = 0;
}

void elpis_random_bytes(void *buf, size_t n)
{
    rng_t *r = &g_rng;
    uint8_t *p = (uint8_t *)buf;

    if (!r->seeded)
        rng_seed_from_os(r);

    while (n > 0) {
        size_t take;
        if (r->pos >= sizeof r->buf) {
            if (r->emitted >= RNG_REKEY_BYTES)
                rng_rekey(r);
            rng_refill(r);
        }
        take = sizeof r->buf - r->pos;
        if (take > n)
            take = n;
        memcpy(p, r->buf + r->pos, take);
        /* Erase what we hand out so the buffer never holds spent output. */
        memset(r->buf + r->pos, 0, take);
        r->pos += (unsigned)take;
        r->emitted += take;
        p += take;
        n -= take;
    }
}

uint32_t elpis_random_u32(void)
{
    uint32_t v;
    elpis_random_bytes(&v, sizeof v);
    return v;
}

uint32_t elpis_random_below(uint32_t n)
{
    uint32_t limit, v;

    if (n <= 1)
        return 0;
    /* Rejection sampling: discard the biased tail above the largest multiple. */
    limit = (uint32_t)(0xFFFFFFFFu - (0xFFFFFFFFu % n));
    do {
        v = elpis_random_u32();
    } while (v >= limit);
    return v % n;
}

void elpis_random_init(void)
{
    rng_seed_from_os(&g_rng);
}

void elpis_random_reseed(void)
{
    rng_seed_from_os(&g_rng);
}
