/*
 * ratelimit.c -- per-client query rate limiting.
 *
 * Keyed by prefix rather than exact address (/24 for IPv4, /56 for IPv6) so
 * one host behind NAT cannot be singled out, and one host with a /64 cannot
 * evade the limit by walking addresses.  State is per worker: with
 * SO_REUSEPORT a client's packets land consistently on one worker, and a
 * shared table would cost a lock on the busiest path in the program.
 */
#include "elpis/resolver.h"
#include "elpis/simd.h"

#define RL_BUCKETS 4096u

typedef struct {
    uint64_t key;
    uint32_t tokens;      /* scaled by 16 to allow fractional refill */
    uint32_t last_ms;
} rlent_t;

static ELPIS_TLS rlent_t g_client[RL_BUCKETS];
static ELPIS_TLS rlent_t g_resp[RL_BUCKETS];

#define TOKEN_SCALE 16u

static uint64_t prefix_key(const elpis_addr_t *a, uint64_t salt)
{
    uint8_t buf[17];
    size_t n = 0;

    if (elpis_addr_family(a) == AF_INET) {
        memcpy(buf, &a->u.v4.sin_addr, 4);
        buf[3] = 0;                       /* /24 */
        n = 4;
    } else if (elpis_addr_family(a) == AF_INET6) {
        memcpy(buf, &a->u.v6.sin6_addr, 16);
        memset(buf + 7, 0, 9);            /* /56 */
        n = 16;
    } else {
        return salt;
    }
    buf[n++] = (uint8_t)salt;
    return elpis_simd_hash_ci(buf, n, salt);
}

/*
 * Token bucket.  `rate` is queries per second; the bucket holds one second's
 * worth plus a small burst so ordinary bursty clients are not punished.
 */
static int bucket_take(rlent_t *tab, uint64_t key, uint32_t rate)
{
    rlent_t *e = &tab[(unsigned)(key & (RL_BUCKETS - 1u))];
    uint32_t now = (uint32_t)elpis_cached_now_ms();
    uint32_t cap = rate * TOKEN_SCALE * 2u;

    if (rate == 0)
        return 1;

    if (e->key != key) {
        /*
         * Collision or first sight: reset the bucket.  Two prefixes sharing a
         * slot simply share an allowance, which is acceptable for a defence
         * measure and keeps this table fixed size.
         */
        e->key = key;
        e->tokens = cap;
        e->last_ms = now;
    } else {
        uint32_t elapsed = now - e->last_ms;
        if (elapsed > 0) {
            uint64_t add = (uint64_t)elapsed * rate * TOKEN_SCALE / 1000u;
            uint64_t nt = (uint64_t)e->tokens + add;
            e->tokens = (uint32_t)(nt > cap ? cap : nt);
            e->last_ms = now;
        }
    }

    if (e->tokens < TOKEN_SCALE)
        return 0;
    e->tokens -= TOKEN_SCALE;
    return 1;
}

int elpis_ratelimit_client(elpis_worker_t *w, const elpis_addr_t *a)
{
    uint32_t rate = w->ctx->conf.client_qps;
    if (rate == 0)
        return 1;
    return bucket_take(g_client, prefix_key(a, 0x1111ull), rate);
}

int elpis_rrl_allow(elpis_worker_t *w, const elpis_addr_t *a, unsigned rcode)
{
    uint32_t rate = w->ctx->conf.nxdomain_qps;

    /*
     * Only negative answers are limited here.  They are the cheap-to-generate,
     * easy-to-amplify case, and unlike positive answers there is no cost to a
     * legitimate client in slowing them down.
     */
    if (rate == 0 || rcode != ELPIS_RC_NXDOMAIN)
        return 1;
    return bucket_take(g_resp, prefix_key(a, 0x2222ull), rate);
}
