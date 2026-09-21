/*
 * webui.c -- read-only status page over plain HTTP.
 *
 * Deliberately small.  One thread, one connection at a time, no keep-alive,
 * hard timeouts on every socket, a cap on request size, and two routes.  A
 * status page that can stall the resolver, or that can be made to allocate,
 * would be worse than no status page, so it does neither.
 */
#define _POSIX_C_SOURCE 200809L

#include "elpis/webui.h"
#include "elpis/telemetry.h"
#include "elpis/crypto.h"
#include "elpis/log.h"
#include "elpis/util.h"
#include "elpis/simd.h"
#include "elpis/loop.h"
#include "webui_assets.h"

#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#define REQ_MAX      8192u        /* a GET and its headers, nothing more    */
#define OUT_MAX      262144u      /* one JSON snapshot                      */
#define SESSIONS     8u
#define SESSION_SECS 28800u       /* eight hours                            */
#define PBKDF2_ITERS 120000u
#define TOPN         10u
#define LOGN         120u

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static const char k_hex[] = "0123456789abcdef";

static void hexenc(const uint8_t *in, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = k_hex[in[i] >> 4];
        out[i * 2 + 1] = k_hex[in[i] & 0x0Fu];
    }
    out[n * 2] = '\0';
}

static int hexdec(const char *in, uint8_t *out, size_t max, size_t *outlen)
{
    size_t n = 0;
    while (in[0] && in[1] && n < max) {
        int hi = -1, lo = -1, k;
        for (k = 0; k < 16; k++) {
            if (k_hex[k] == in[0] || (in[0] >= 'A' && in[0] <= 'F' &&
                                      k_hex[k] == in[0] + 32)) hi = k;
            if (k_hex[k] == in[1] || (in[1] >= 'A' && in[1] <= 'F' &&
                                      k_hex[k] == in[1] + 32)) lo = k;
        }
        if (hi < 0 || lo < 0)
            return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        in += 2;
    }
    *outlen = n;
    return in[0] == '\0' ? 0 : -1;
}

/* ASCII case-insensitive prefix compare; used on header names only. */
static int ncasecmp(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        int ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb || ca == 0)
            return ca - cb;
    }
    return 0;
}

/* Equal-time compare, so a wrong password leaks nothing by how long it took. */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* ------------------------------------------------------------------ */
/* Output buffer                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *p;
    size_t cap, len;
    int    over;
} buf_t;

static void bput(buf_t *b, const char *s, size_t n)
{
    if (b->over || b->len + n + 1u > b->cap) { b->over = 1; return; }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void bputs(buf_t *b, const char *s) { bput(b, s, strlen(s)); }

static void bputf(buf_t *b, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (b->over || b->cap <= b->len + 1u) { b->over = 1; return; }
    va_start(ap, fmt);
    n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->len) { b->over = 1; return; }
    b->len += (size_t)n;
}

static void bputu(buf_t *b, uint64_t v)
{
    bputf(b, "%llu", (unsigned long long)v);
}

/* JSON string, escaping what RFC 8259 requires and dropping control bytes. */
static void bputq(buf_t *b, const char *s)
{
    bputs(b, "\"");
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { char e[2]; e[0] = '\\'; e[1] = (char)c; bput(b, e, 2); }
        else if (c < 0x20u || c == 0x7Fu) bputf(b, "\\u%04x", c);
        else bput(b, (const char *)&c, 1);
    }
    bputs(b, "\"");
}

/* ------------------------------------------------------------------ */
/* Password                                                            */
/* ------------------------------------------------------------------ */

#define PW_PREFIX "$pbkdf2-sha256$"

static void pw_format(char *out, size_t outsz, uint32_t iters,
                      const uint8_t salt[16], const uint8_t hash[32])
{
    char sh[33], hh[65];
    hexenc(salt, 16, sh);
    hexenc(hash, 32, hh);
    snprintf(out, outsz, PW_PREFIX "%u$%s$%s", (unsigned)iters, sh, hh);
}

static void pw_hash(const char *plain, uint32_t iters, const uint8_t salt[16],
                    uint8_t out[32])
{
    elpis_pbkdf2_sha256(plain, strlen(plain), salt, 16u, iters, out, 32u);
}

static int pw_check(const char *stored, const char *plain)
{
    const char *p = stored;
    char salt_hex[64], hash_hex[128];
    uint8_t salt[16], want[32], got[32];
    size_t sl = 0, hl = 0, i;
    uint32_t iters = 0;

    if (strncmp(p, PW_PREFIX, sizeof PW_PREFIX - 1u) != 0)
        return 0;
    p += sizeof PW_PREFIX - 1u;
    for (; *p >= '0' && *p <= '9'; p++)
        iters = iters * 10u + (uint32_t)(*p - '0');
    if (*p++ != '$' || iters == 0u)
        return 0;
    for (i = 0; *p && *p != '$' && i < sizeof salt_hex - 1u; i++)
        salt_hex[i] = *p++;
    salt_hex[i] = '\0';
    if (*p++ != '$')
        return 0;
    for (i = 0; *p && i < sizeof hash_hex - 1u; i++)
        hash_hex[i] = *p++;
    hash_hex[i] = '\0';

    if (hexdec(salt_hex, salt, sizeof salt, &sl) != 0 || sl != 16u)
        return 0;
    if (hexdec(hash_hex, want, sizeof want, &hl) != 0 || hl != 32u)
        return 0;

    elpis_pbkdf2_sha256(plain, strlen(plain), salt, 16u, iters, got, 32u);
    return ct_equal(got, want, 32u);
}

/*
 * Replace the plaintext webgui-password line in the config with its hash.
 *
 * Best effort: the resolver works the same either way, this only stops the
 * plaintext outliving the first start.  Written to a temp file and renamed, so
 * a failure half way cannot leave a truncated config behind.
 */
static int pw_rewrite_conf(const char *path, const char *hashed)
{
    char tmp[600], line[1024];
    FILE *in, *out;
    int fd, replaced = 0;

    if (path == NULL || path[0] == '\0')
        return -1;
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
        return -1;

    in = fopen(path, "r");
    if (in == NULL)
        return -1;
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { fclose(in); return -1; }
    out = fdopen(fd, "w");
    if (out == NULL) { close(fd); fclose(in); return -1; }

    while (fgets(line, (int)sizeof line, in) != NULL) {
        const char *q = line;
        while (*q == ' ' || *q == '\t') q++;
        if (!replaced && ncasecmp(q, "webgui-password", 15) == 0) {
            fprintf(out, "webgui-password: %s\n", hashed);
            replaced = 1;
        } else {
            fputs(line, out);
        }
    }
    if (!replaced)
        fprintf(out, "\nwebgui-password: %s\n", hashed);

    fclose(in);
    if (fclose(out) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int elpis_webui_prepare(elpis_ctx_t *ctx)
{
    elpis_conf_t *c = &ctx->conf;
    uint8_t salt[16], hash[32];
    char hashed[256];

    if (!c->web)
        return ELPIS_OK;
    if (c->web_user[0] == '\0')
        elpis_strlcpy(c->web_user, "admin", sizeof c->web_user);

    /* Already hashed: nothing to do. */
    if (strncmp(c->web_pass, PW_PREFIX, sizeof PW_PREFIX - 1u) == 0)
        return ELPIS_OK;

    if (c->web_pass[0] == '\0') {
        uint8_t raw[12];
        char gen[32];
        elpis_random_bytes(raw, sizeof raw);
        hexenc(raw, sizeof raw, gen);
        elpis_random_bytes(salt, sizeof salt);
        pw_hash(gen, PBKDF2_ITERS, salt, hash);
        pw_format(c->web_pass, sizeof c->web_pass, PBKDF2_ITERS, salt, hash);

        elpis_warn("status page: no webgui-password set, generated one for "
                   "user '%s': %s", c->web_user, gen);
        elpis_warn("status page: this is printed once -- put it in the config "
                   "to keep it, or it changes on the next restart");
        memset(gen, 0, sizeof gen);
        return ELPIS_OK;
    }

    /* Plaintext: hash it, and try to put the hash back where it came from. */
    elpis_random_bytes(salt, sizeof salt);
    pw_hash(c->web_pass, PBKDF2_ITERS, salt, hash);
    pw_format(hashed, sizeof hashed, PBKDF2_ITERS, salt, hash);

    if (pw_rewrite_conf(c->path, hashed) == 0)
        elpis_info("status page: password hashed into %s", c->path);
    else
        elpis_warn("status page: could not rewrite %s -- the password is "
                   "hashed in memory but stays in plaintext on disk",
                   c->path[0] ? c->path : "(no config file)");

    memset(c->web_pass, 0, sizeof c->web_pass);
    elpis_strlcpy(c->web_pass, hashed, sizeof c->web_pass);
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char     token[65];
    uint64_t expires_ms;
} session_t;

static session_t g_sess[SESSIONS];
static pthread_mutex_t g_sess_lock = PTHREAD_MUTEX_INITIALIZER;

static void session_new(char *out, size_t outsz)
{
    uint8_t raw[32];
    char tok[65];
    unsigned i, victim = 0;
    uint64_t oldest = (uint64_t)-1, now = elpis_now_ms();

    elpis_random_bytes(raw, sizeof raw);
    hexenc(raw, sizeof raw, tok);

    pthread_mutex_lock(&g_sess_lock);
    for (i = 0; i < SESSIONS; i++) {
        if (g_sess[i].token[0] == '\0' || g_sess[i].expires_ms <= now) {
            victim = i;
            break;
        }
        if (g_sess[i].expires_ms < oldest) { oldest = g_sess[i].expires_ms; victim = i; }
    }
    elpis_strlcpy(g_sess[victim].token, tok, sizeof g_sess[victim].token);
    g_sess[victim].expires_ms = now + (uint64_t)SESSION_SECS * 1000u;
    pthread_mutex_unlock(&g_sess_lock);

    elpis_strlcpy(out, tok, outsz);
}

static int session_valid(const char *tok)
{
    unsigned i;
    int ok = 0;
    uint64_t now = elpis_now_ms();

    if (tok == NULL || strlen(tok) != 64u)
        return 0;
    pthread_mutex_lock(&g_sess_lock);
    for (i = 0; i < SESSIONS; i++) {
        if (g_sess[i].token[0] == '\0' || g_sess[i].expires_ms <= now)
            continue;
        if (ct_equal((const uint8_t *)g_sess[i].token, (const uint8_t *)tok, 64u)) {
            ok = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_sess_lock);
    return ok;
}

static void session_drop(const char *tok)
{
    unsigned i;
    if (tok == NULL)
        return;
    pthread_mutex_lock(&g_sess_lock);
    for (i = 0; i < SESSIONS; i++)
        if (g_sess[i].token[0] && strcmp(g_sess[i].token, tok) == 0)
            memset(&g_sess[i], 0, sizeof g_sess[i]);
    pthread_mutex_unlock(&g_sess_lock);
}

/* ------------------------------------------------------------------ */
/* JSON snapshot                                                       */
/* ------------------------------------------------------------------ */

static void json_cache(buf_t *b, const char *name, elpis_cache_t *c)
{
    elpis_cache_stats_t s;
    uint64_t total;

    if (c == NULL)
        return;
    elpis_cache_stats(c, &s);
    total = s.hits + s.misses;
    bputs(b, "{\"name\":");
    bputq(b, name);
    bputs(b, ",\"entries\":");  bputu(b, s.entries);
    bputs(b, ",\"bytes\":");    bputu(b, s.bytes);
    bputs(b, ",\"max\":");      bputu(b, s.bytes_max);
    bputs(b, ",\"hit\":");      bputf(b, "%.1f", total ? (double)s.hits * 100.0 / (double)total : 0.0);
    bputs(b, ",\"evict\":");    bputu(b, s.evictions);
    bputs(b, ",\"pinned\":");   bputu(b, s.pinned_entries);
    bputs(b, "}");
}

static void json_top(buf_t *b, const char *name, elpis_top_t which)
{
    elpis_tmrow_t rows[TOPN];
    unsigned n, i;

    n = elpis_tm_top(which, rows, TOPN);
    bputq(b, name);
    bputs(b, ":[");
    for (i = 0; i < n; i++) {
        if (i) bputs(b, ",");
        bputs(b, "{\"k\":");
        bputq(b, rows[i].key);
        bputs(b, ",\"n\":");
        bputu(b, rows[i].count);
        bputs(b, "}");
    }
    bputs(b, "]");
}

static void json_snapshot(elpis_ctx_t *ctx, buf_t *b)
{
    const elpis_stats_t *s = &ctx->stats;
    const elpis_conf_t *c = &ctx->conf;
    static elpis_tmsample_t hist[ELPIS_TM_HISTORY];
    static char logbuf[LOGN][ELPIS_TM_LOGLEN];
    unsigned n, i;
    uint32_t cpu_milli = 0;
    uint64_t rss = 0, total;

    elpis_tm_process(&cpu_milli, &rss);
    total = s->queries;

    bputs(b, "{\"server\":{\"version\":");
    bputq(b, ELPIS_VERSION);
    bputs(b, ",\"uptime\":");
    bputu(b, (elpis_now_ms() - ctx->start_ms) / 1000u);
    bputs(b, ",\"simd\":");   bputq(b, elpis_simd_backend());
    bputs(b, ",\"loop\":");   bputq(b, elpis_loop_backend());
    bputs(b, ",\"workers\":"); bputu(b, c->threads ? c->threads : elpis_cpu_count());
    bputs(b, ",\"cores\":");   bputu(b, elpis_cpu_count());
    bputs(b, ",\"dnssec\":"); bputs(b, c->dnssec ? "true" : "false");
    bputs(b, ",\"listen\":[");
    for (i = 0; i < c->nlisten; i++) {
        char ab[80];
        if (i) bputs(b, ",");
        bputq(b, elpis_addr_str(&c->listen[i], ab, sizeof ab));
    }
    bputs(b, "]},");

    bputs(b, "\"loop\":{\"turns\":");
    bputu(b, ctx->loop.turns);
    bputs(b, ",\"idle\":");    bputu(b, ctx->loop.idle);
    bputs(b, ",\"nosleep\":"); bputu(b, ctx->loop.nosleep);
    bputs(b, ",\"timers\":");  bputu(b, ctx->loop.timers);
    bputs(b, ",\"slowest\":"); bputu(b, ctx->loop.slowest_ms);
    bputs(b, "},");

    bputs(b, "\"proc\":{\"cpu\":");
    bputu(b, cpu_milli);
    bputs(b, ",\"rss\":");     bputu(b, rss);
    bputs(b, ",\"ram\":");     bputu(b, ctx->plan.ram_total);
    bputs(b, ",\"budget\":");  bputu(b, ctx->plan.budget_total);
    bputs(b, "},");

    bputs(b, "\"stats\":{");
    bputs(b, "\"queries\":");   bputu(b, s->queries);
    bputs(b, ",\"hits\":");     bputu(b, s->cache_hits);
    bputs(b, ",\"hitpct\":");   bputf(b, "%.2f", total ? (double)s->cache_hits * 100.0 / (double)total : 0.0);
    bputs(b, ",\"stale\":");    bputu(b, s->cache_stale);
    bputs(b, ",\"recursions\":"); bputu(b, s->recursions);
    bputs(b, ",\"upstream\":");  bputu(b, s->upstream_queries);
    bputs(b, ",\"nxdomain\":");  bputu(b, s->nxdomain);
    bputs(b, ",\"servfail\":");  bputu(b, s->servfail);
    bputs(b, ",\"refused\":");   bputu(b, s->refused);
    bputs(b, ",\"timeouts\":");  bputu(b, s->timeouts);
    bputs(b, ",\"tcp\":");       bputu(b, s->tcp_queries);
    bputs(b, ",\"truncated\":"); bputu(b, s->truncated);
    bputs(b, ",\"secure\":");    bputu(b, s->dnssec_secure);
    bputs(b, ",\"insecure\":");  bputu(b, s->dnssec_insecure);
    bputs(b, ",\"bogus\":");     bputu(b, s->dnssec_bogus);
    bputs(b, ",\"dropped\":");   bputu(b, s->dropped);
    bputs(b, ",\"prefetch\":");  bputu(b, s->prefetches);
    bputs(b, ",\"cookieok\":");  bputu(b, s->cookie_ok);
    bputs(b, ",\"cookiebad\":"); bputu(b, s->cookie_bad);
    bputs(b, "},");

    bputs(b, "\"caches\":[");
    json_cache(b, "message", ctx->mcache);   bputs(b, ",");
    json_cache(b, "rrset", ctx->rcache);     bputs(b, ",");
    json_cache(b, "delegation", ctx->dcache); bputs(b, ",");
    json_cache(b, "infra", ctx->infra);
    bputs(b, "],");

    n = elpis_tm_history(hist, ELPIS_TM_HISTORY);
    bputs(b, "\"history\":{\"qps\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].queries); }
    bputs(b, "],\"servfail\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].servfail); }
    bputs(b, "],\"bogus\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].bogus); }
    bputs(b, "],\"hits\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].cache_hits); }
    bputs(b, "],\"upstream\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].upstream); }
    bputs(b, "],\"cpu\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].cpu_milli); }
    bputs(b, "],\"rss\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].rss_bytes); }
    bputs(b, "],\"rx\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].rx_bytes); }
    bputs(b, "],\"tx\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].tx_bytes); }
    bputs(b, "],\"rtt\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].rtt_us); }
    bputs(b, "],\"rttn\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].rtt_n); }
    bputs(b, "],\"rec\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].rec_us); }
    bputs(b, "],\"recn\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].rec_n); }
    bputs(b, "]},");

    bputs(b, "\"top\":{");
    json_top(b, "qname",   ELPIS_TOP_QNAME);        bputs(b, ",");
    json_top(b, "servfail", ELPIS_TOP_SERVFAIL);    bputs(b, ",");
    json_top(b, "bogus",   ELPIS_TOP_BOGUS);        bputs(b, ",");
    json_top(b, "client",  ELPIS_TOP_CLIENT);       bputs(b, ",");
    json_top(b, "clientfail", ELPIS_TOP_CLIENT_FAIL); bputs(b, ",");
    json_top(b, "clientbogus", ELPIS_TOP_CLIENT_BOGUS); bputs(b, ",");
    json_top(b, "timeout", ELPIS_TOP_TIMEOUT);
    bputs(b, "},");

    n = elpis_tm_log(logbuf, LOGN);
    bputs(b, "\"log\":[");
    for (i = 0; i < n; i++) {
        if (i) bputs(b, ",");
        bputq(b, logbuf[i]);
    }
    bputs(b, "]}");
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

static void send_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0)
            return;
        p += w;
        n -= (size_t)w;
    }
}

static void respond(int fd, const char *status, const char *ctype,
                    const char *extra, const char *body, size_t bodylen)
{
    char head[512];
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %llu\r\n"
                     "Cache-Control: no-store\r\n"
                     "X-Content-Type-Options: nosniff\r\n"
                     "X-Frame-Options: DENY\r\n"
                     "Referrer-Policy: no-referrer\r\n"
                     "Content-Security-Policy: default-src 'none'; "
                     "img-src 'self' data:; style-src 'unsafe-inline'; "
                     "script-src 'unsafe-inline'; connect-src 'self'\r\n"
                     "Connection: close\r\n"
                     "%s\r\n",
                     status, ctype, (unsigned long long)bodylen,
                     extra ? extra : "");
    if (n < 0 || (size_t)n >= sizeof head)
        return;
    send_all(fd, head, (size_t)n);
    if (bodylen)
        send_all(fd, body, bodylen);
}

/* Find a header's value in the raw request.  Returns NULL when absent. */
static const char *header_of(const char *req, const char *name, char *out,
                             size_t outsz)
{
    size_t nl = strlen(name);
    const char *p = req;

    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (ncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            size_t i = 0;
            while (*v == ' ' || *v == '\t') v++;
            while (*v && *v != '\r' && *v != '\n' && i < outsz - 1u)
                out[i++] = *v++;
            out[i] = '\0';
            return out;
        }
    }
    return NULL;
}

/* Pull our cookie out of a Cookie header. */
static int cookie_token(const char *cookies, char *out, size_t outsz)
{
    const char *p = cookies;
    while (p && *p) {
        while (*p == ' ' || *p == ';') p++;
        if (strncmp(p, "elpis=", 6) == 0) {
            size_t i = 0;
            p += 6;
            while (*p && *p != ';' && i < outsz - 1u)
                out[i++] = *p++;
            out[i] = '\0';
            return 1;
        }
        p = strchr(p, ';');
    }
    return 0;
}

/* Read one form field from an application/x-www-form-urlencoded body. */
static int form_field(const char *body, const char *name, char *out, size_t outsz)
{
    size_t nl = strlen(name);
    const char *p = body;

    while (p && *p) {
        if (strncmp(p, name, nl) == 0 && p[nl] == '=') {
            size_t i = 0;
            p += nl + 1;
            while (*p && *p != '&' && i < outsz - 1u) {
                if (*p == '+') { out[i++] = ' '; p++; }
                else if (*p == '%' && p[1] && p[2]) {
                    uint8_t v[1];
                    size_t got;
                    char pair[3];
                    pair[0] = p[1]; pair[1] = p[2]; pair[2] = '\0';
                    if (hexdec(pair, v, 1, &got) == 0 && got == 1)
                        out[i++] = (char)v[0];
                    p += 3;
                } else out[i++] = *p++;
            }
            out[i] = '\0';
            return 1;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return 0;
}

static void handle_conn(elpis_ctx_t *ctx, int fd)
{
    static char req[REQ_MAX + 1];
    static char out[OUT_MAX];
    char hdr[1024], tok[128];
    size_t got = 0;
    const char *body;
    int authed = 0;

    /* Read until the headers end, or the cap, or the timeout. */
    for (;;) {
        ssize_t r = recv(fd, req + got, REQ_MAX - got, 0);
        if (r <= 0)
            return;
        got += (size_t)r;
        req[got] = '\0';
        if (strstr(req, "\r\n\r\n") != NULL || got >= REQ_MAX)
            break;
    }
    req[got] = '\0';
    body = strstr(req, "\r\n\r\n");
    body = body ? body + 4 : "";

    if (header_of(req, "Cookie", hdr, sizeof hdr) != NULL &&
        cookie_token(hdr, tok, sizeof tok))
        authed = session_valid(tok);
    else
        tok[0] = '\0';

    if (strncmp(req, "GET / ", 6) == 0 || strncmp(req, "GET /index.html ", 16) == 0) {
        respond(fd, "200 OK", "text/html; charset=utf-8", NULL,
                elpis_webui_page, strlen(elpis_webui_page));
        return;
    }

    if (strncmp(req, "POST /api/login", 15) == 0) {
        char user[64], pass[256], set[256];
        int ok = 0;

        if (form_field(body, "user", user, sizeof user) &&
            form_field(body, "pass", pass, sizeof pass)) {
            /* Compare the name in equal time too, so it cannot be probed. */
            size_t ul = strlen(ctx->conf.web_user);
            int uok = strlen(user) == ul &&
                      ct_equal((const uint8_t *)user,
                               (const uint8_t *)ctx->conf.web_user, ul);
            int pok = pw_check(ctx->conf.web_pass, pass);
            ok = uok && pok;
            memset(pass, 0, sizeof pass);
        }
        if (!ok) {
            char ab[80];
            (void)ab;
            elpis_warn("status page: failed login for user '%s'",
                       user[0] ? user : "(none)");
            respond(fd, "401 Unauthorized", "application/json", NULL,
                    "{\"ok\":false}", 12);
            return;
        }
        session_new(tok, sizeof tok);
        snprintf(set, sizeof set,
                 "Set-Cookie: elpis=%s; Path=/; HttpOnly; SameSite=Strict; "
                 "Max-Age=%u\r\n", tok, (unsigned)SESSION_SECS);
        respond(fd, "200 OK", "application/json", set, "{\"ok\":true}", 11);
        return;
    }

    if (strncmp(req, "POST /api/logout", 16) == 0) {
        session_drop(tok);
        respond(fd, "200 OK", "application/json",
                "Set-Cookie: elpis=; Path=/; HttpOnly; Max-Age=0\r\n",
                "{\"ok\":true}", 11);
        return;
    }

    if (strncmp(req, "GET /api/status", 15) == 0) {
        buf_t b;
        if (!authed) {
            respond(fd, "401 Unauthorized", "application/json", NULL,
                    "{\"ok\":false}", 12);
            return;
        }
        b.p = out; b.cap = sizeof out; b.len = 0; b.over = 0;
        json_snapshot(ctx, &b);
        if (b.over) {
            respond(fd, "500 Internal Server Error", "application/json", NULL,
                    "{\"ok\":false}", 12);
            return;
        }
        respond(fd, "200 OK", "application/json", NULL, b.p, b.len);
        return;
    }

    if (strncmp(req, "GET /api/session", 16) == 0) {
        const char *yes = "{\"ok\":true}", *no = "{\"ok\":false}";
        respond(fd, "200 OK", "application/json", NULL,
                authed ? yes : no, strlen(authed ? yes : no));
        return;
    }

    respond(fd, "404 Not Found", "text/plain", NULL, "not found\n", 10);
}

/* ------------------------------------------------------------------ */
/* Thread                                                              */
/* ------------------------------------------------------------------ */

static int listen_on(const elpis_addr_t *a)
{
    int fd, on = 1;

    fd = socket(a->u.sa.sa_family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#if defined(IPV6_V6ONLY)
    if (a->u.sa.sa_family == AF_INET6)
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
#endif
    if (bind(fd, &a->u.sa, a->len) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void *elpis_webui_main(void *ctxv)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)ctxv;
    char ab[80];
    int lfd;
    uint64_t last_tick = 0;

    if (!ctx->conf.web)
        return NULL;

    lfd = listen_on(&ctx->conf.web_listen);
    if (lfd < 0) {
        elpis_error("status page: cannot listen on %s: %s",
                    elpis_addr_str(&ctx->conf.web_listen, ab, sizeof ab),
                    strerror(errno));
        return NULL;
    }
    elpis_info("status page on http://%s/ (user '%s')",
               elpis_addr_str(&ctx->conf.web_listen, ab, sizeof ab),
               ctx->conf.web_user);

    while (!ctx->shutdown) {
        struct pollfd pfd;
        int rc, cfd;
        uint64_t now = elpis_now_ms();

        /* One history sample a second, taken here so nothing else has to. */
        if (now - last_tick >= 1000u) {
            elpis_tm_tick(ctx);
            last_tick = now;
        }

        /*
         * poll(), not select(): a resolver has hundreds of sockets open and a
         * descriptor at or past FD_SETSIZE makes select() undefined, which in
         * practice means it fails every time -- and `continue` on a failure
         * that never clears is a loop that burns a core silently.  A real
         * error now backs off instead of spinning.
         */
        pfd.fd = lfd;
        pfd.events = POLLIN;
        rc = poll(&pfd, 1, 250);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            elpis_error("status page: poll failed (%s); stopping",
                        strerror(errno));
            break;
        }
        if (rc == 0)
            continue;

        cfd = accept(lfd, NULL, NULL);
        if (cfd < 0)
            continue;
        {
            struct timeval io;
            int on = 1;
            io.tv_sec = 5; io.tv_usec = 0;
            (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &io, sizeof io);
            (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof io);
            (void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        }
        handle_conn(ctx, cfd);
        close(cfd);
    }
    close(lfd);
    return NULL;
}
