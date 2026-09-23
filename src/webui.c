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
#include "elpis/infra.h"
#include "elpis/deleg.h"
#include "elpis/licence.h"
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

#define REQ_MAX      8192u        /* a request and its headers, nothing more */
#define REQ_MS       3000u        /* the whole request, however it arrives   */
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
void elpis_webui_hash_password(const char *plain, char *out, size_t outsz)
{
    uint8_t salt[16], hash[32];

    elpis_random_bytes(salt, sizeof salt);
    pw_hash(plain, PBKDF2_ITERS, salt, hash);
    pw_format(out, outsz, PBKDF2_ITERS, salt, hash);
}

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

    if (pw_rewrite_conf(c->path, hashed) == 0) {
        elpis_info("status page: password hashed into %s", c->path);
    } else {
        /*
         * Almost always this is the config file being deliberately read-only
         * -- ProtectSystem=strict and ReadOnlyPaths in the shipped unit both
         * do it, whatever the file's owner and mode say -- and that is the
         * right way round.  A resolver that cannot rewrite its own config is
         * a resolver whose config a compromise cannot rewrite either.  So
         * this says what to do rather than suggesting the sandbox be opened.
         */
        elpis_warn("status page: %s is not writable, so the password stays "
                   "in plaintext on disk (it is hashed in memory)",
                   c->path[0] ? c->path : "(no config file)");
        elpis_warn("status page: hash it yourself and paste the result in -- "
                   "%s --hash-password", elpis_exe_path());
    }

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

/*
 * The root servers, ranked by how quickly they have been answering.
 *
 * This is the resolver's live opinion, not the startup probe: the round-trip
 * estimates come from the infrastructure cache and move as the network does,
 * which is what actually decides who gets asked next.
 */
/*
 * The ML-DSA parameter sets, and how much the number each one answers to is
 * worth.  All three verifiers are always built in, so "available" is never in
 * doubt; what varies is whether the DNSSEC algorithm number is one anybody
 * else uses.  draft-westerbaan-dnssec-mldsa assigns 18 to ML-DSA-44 and the
 * deployed test zones sign with it, so that one is live.  It registers nothing
 * for 65 and 87, so those default to placeholders in unassigned space that are
 * interoperable with nothing -- until an operator overrides them, which can
 * only mean they have agreed the numbers with whoever they are talking to.
 */
static void json_mldsa(const elpis_conf_t *c, buf_t *b)
{
    static const struct {
        const char *name;
        uint8_t     dflt;
        int         assigned;       /* a number from the draft, not a placeholder */
    } set[3] = {
        { "ML-DSA-44", ELPIS_ALG_MLDSA44_DEFAULT, 1 },
        { "ML-DSA-65", ELPIS_ALG_MLDSA65_DEFAULT, 0 },
        { "ML-DSA-87", ELPIS_ALG_MLDSA87_DEFAULT, 0 }
    };
    const uint8_t alg[3] = { c->alg_mldsa44, c->alg_mldsa65, c->alg_mldsa87 };
    unsigned i;

    bputs(b, "\"mldsa\":[");
    for (i = 0; i < 3; i++) {
        int live = set[i].assigned || alg[i] != set[i].dflt;
        if (i) bputs(b, ",");
        bputs(b, "{\"name\":");
        bputq(b, set[i].name);
        bputs(b, ",\"alg\":");
        bputu(b, alg[i]);
        bputs(b, ",\"state\":");
        bputq(b, live ? "active" : "available");
        bputs(b, ",\"note\":");
        bputq(b, set[i].assigned      ? "assigned by the draft"
              : alg[i] != set[i].dflt ? "agreed locally"
                                      : "placeholder, unassigned space");
        bputs(b, "}");
    }
    bputs(b, "],");
}

static void json_roots(elpis_ctx_t *ctx, buf_t *b)
{
    typedef struct { char addr[80]; char name[72]; uint32_t rtt, to, q; } row_t;
    static row_t rows[ELPIS_DELEG_MAX_NS * (ELPIS_NS_MAX_A4 + ELPIS_NS_MAX_A6)];
    const elpis_deleg_t *d = &ctx->root_hints;
    unsigned n = 0, i, j, k;

    for (i = 0; i < d->nns && n < ELPIS_ARRAY_LEN(rows); i++) {
        const elpis_nsrec_t *ns = &d->ns[i];
        char nb[ELPIS_MAX_NAME * 4];

        elpis_name_str(&ns->name, nb, sizeof nb);

        for (j = 0; j < ns->n4 && n < ELPIS_ARRAY_LEN(rows); j++) {
            elpis_addr_t a;
            elpis_infra_info_t inf;
            elpis_addr_from4(&a, ns->a4[j], 53);
            elpis_infra_get(ctx->infra, &a, &inf);
            elpis_addr_str(&a, rows[n].addr, sizeof rows[n].addr);
            elpis_strlcpy(rows[n].name, nb, sizeof rows[n].name);
            rows[n].rtt = inf.srtt; rows[n].to = inf.timeouts;
            rows[n].q = inf.queries;
            n++;
        }
        for (j = 0; j < ns->n6 && n < ELPIS_ARRAY_LEN(rows); j++) {
            elpis_addr_t a;
            elpis_infra_info_t inf;
            elpis_addr_from6(&a, ns->a6[j], 53);
            elpis_infra_get(ctx->infra, &a, &inf);
            elpis_addr_str(&a, rows[n].addr, sizeof rows[n].addr);
            elpis_strlcpy(rows[n].name, nb, sizeof rows[n].name);
            rows[n].rtt = inf.srtt; rows[n].to = inf.timeouts;
            rows[n].q = inf.queries;
            n++;
        }
    }

    for (i = 1; i < n; i++) {           /* insertion sort: fewer than thirty */
        row_t tmp = rows[i];
        for (k = i; k > 0 && rows[k - 1].rtt > tmp.rtt; k--)
            rows[k] = rows[k - 1];
        rows[k] = tmp;
    }

    bputs(b, "\"roots\":[");
    for (i = 0; i < n; i++) {
        if (i) bputs(b, ",");
        bputs(b, "{\"name\":");
        bputq(b, rows[i].name);
        bputs(b, ",\"addr\":");
        bputq(b, rows[i].addr);
        bputs(b, ",\"rtt\":");      bputu(b, rows[i].rtt);
        bputs(b, ",\"timeouts\":"); bputu(b, rows[i].to);
        bputs(b, ",\"queries\":");  bputu(b, rows[i].q);
        bputs(b, "}");
    }
    bputs(b, "],");
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
    bputs(b, ",\"hostup\":");
    bputu(b, (unsigned long)elpis_host_uptime());
    bputs(b, ",\"build\":");  bputq(b, elpis_build_rev());
    bputs(b, ",\"cc\":");     bputq(b, elpis_compiler());
    bputs(b, ",\"arch\":");   bputq(b, elpis_build_arch());
    bputs(b, ",\"target\":"); bputq(b, elpis_build_target());
    bputs(b, ",\"edition\":");  bputq(b, c->edition);
    bputs(b, ",\"operator\":"); bputq(b, c->operator_name);
    bputs(b, ",\"identity\":");
    bputq(b, c->identity ? c->identity_name : "");
    {
        const elpis_licence_t *l = &ctx->licence;
        char when[32];
        elpis_licence_date(l->expires, when, sizeof when);
        bputs(b, ",\"licence\":{\"state\":");
        bputq(b, !l->present ? "none" :
                 !l->valid   ? "rejected" :
                 l->expired  ? "expired" : "verified");
        bputs(b, ",\"org\":");     bputq(b, l->valid ? l->org : "");
        bputs(b, ",\"serial\":");  bputu(b, l->valid ? l->serial : 0u);
        bputs(b, ",\"expires\":"); bputq(b, l->valid ? when : "");
        bputs(b, ",\"why\":");     bputq(b, l->present && !l->valid ? l->why : "");
        bputs(b, "}");
    }
    bputs(b, ",\"simd\":");   bputq(b, elpis_simd_backend());
    bputs(b, ",\"loop\":");   bputq(b, elpis_loop_backend());
    bputs(b, ",\"workers\":"); bputu(b, c->threads ? c->threads : elpis_cpu_count());
    bputs(b, ",\"cores\":");   bputu(b, elpis_cpu_count());
    {
        char cpu[160];
        elpis_cpu_model(cpu, sizeof cpu);
        bputs(b, ",\"cpu\":");
        bputq(b, cpu[0] ? cpu : "unknown processor");
    }
    bputs(b, ",\"dnssec\":"); bputs(b, c->dnssec ? "true" : "false");
    bputs(b, ",\"listen\":[");
    for (i = 0; i < c->nlisten; i++) {
        char ab[80];
        if (i) bputs(b, ",");
        bputq(b, elpis_addr_str(&c->listen[i], ab, sizeof ab));
    }
    bputs(b, "]},");

    json_mldsa(c, b);

    bputs(b, "\"self\":{\"v4\":");
    bputq(b, ctx->self.v4);
    bputs(b, ",\"v6\":");     bputq(b, ctx->self.v6);
    bputs(b, ",\"asn\":");    bputq(b, ctx->self.asn);
    bputs(b, ",\"asname\":"); bputq(b, ctx->self.asname);
    bputs(b, "},");

    json_roots(ctx, b);

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
    bputs(b, ",\"verifies\":"); bputu(b, s->dnssec_verifies);
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
    bputs(b, "],\"verify\":[");
    for (i = 0; i < n; i++) { if (i) bputs(b, ","); bputu(b, hist[i].verifies); }
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

/*
 * Read one request: the headers, then as much body as Content-Length says,
 * all inside REQ_MAX bytes and REQ_MS milliseconds.
 *
 * The deadline is for the request, not for each read.  The page serves one
 * connection at a time, and a per-read timeout let a client that sent a byte
 * every few seconds hold it for hours -- nobody else could load the page, and
 * the once-a-second history sampling done on this thread stopped with it.
 *
 * The body is read on purpose, not taken from whatever came with the
 * headers: a browser is free to send a POST's body in a segment of its own,
 * and when it did, the login form failed with the right password.
 *
 * Returns the length read, or 0 when there is no complete request.
 */
static size_t read_request(int fd, char *req, const char **body)
{
    uint64_t deadline = elpis_now_ms() + REQ_MS;
    size_t got = 0, want = 0;

    req[0] = '\0';
    for (;;) {
        struct pollfd p;
        uint64_t now = elpis_now_ms();
        const char *end;
        ssize_t r;

        if (want != 0 && got >= want)
            break;
        if (now >= deadline || got >= REQ_MAX)
            return 0;
        p.fd = fd;
        p.events = POLLIN;
        if (poll(&p, 1, (int)(deadline - now)) <= 0)
            return 0;
        r = recv(fd, req + got, REQ_MAX - got, 0);
        if (r <= 0)
            return 0;
        got += (size_t)r;
        req[got] = '\0';

        if (want == 0 && (end = strstr(req, "\r\n\r\n")) != NULL) {
            char cl[24];
            size_t head = (size_t)(end - req) + 4u;
            unsigned long n = 0;
            if (header_of(req, "Content-Length", cl, sizeof cl) != NULL)
                n = strtoul(cl, NULL, 10);
            if (n > REQ_MAX - head)
                return 0;               /* more than the page ever sends */
            want = head + (size_t)n;
        }
    }
    *body = strstr(req, "\r\n\r\n") + 4;
    return got;
}

static void handle_conn(elpis_ctx_t *ctx, int fd)
{
    static char req[REQ_MAX + 1];
    static char out[OUT_MAX];
    char hdr[1024], tok[128];
    const char *body = "";
    int authed = 0;

    if (read_request(fd, req, &body) == 0)
        return;

    if (header_of(req, "Cookie", hdr, sizeof hdr) != NULL &&
        cookie_token(hdr, tok, sizeof tok))
        authed = session_valid(tok);
    else
        tok[0] = '\0';

    /* "GET /?v=2" is the same page: a query string is the client's business,
     * and refusing it turns an ordinary cache-buster into a 404. */
    if (strncmp(req, "GET / ", 6) == 0 || strncmp(req, "GET /?", 6) == 0 ||
        strncmp(req, "GET /index.html ", 16) == 0 ||
        strncmp(req, "GET /index.html?", 16) == 0) {
        respond(fd, "200 OK", "text/html; charset=utf-8", NULL,
                elpis_webui_page, strlen(elpis_webui_page));
        return;
    }

    if (strncmp(req, "POST /api/login", 15) == 0) {
        /*
         * Empty until form_field() fills them: a login with no "user" field
         * went on to log the name anyway, printing whatever the stack held --
         * up to and past the end of the buffer.
         */
        char user[64] = "", pass[256] = "", set[256];
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
            /*
             * Rate limited: a guessing script must not be able to push
             * everything else off the log, here or on the page's own view
             * of it.  The name it tried is shown with control characters
             * replaced, as every log line now is.
             */
            elpis_logf_rl(ELPIS_LOG_WARN, ELPIS_DROP__MAX + 2, __FILE__,
                          __LINE__, "status page: failed login for user '%s'",
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
            /* Sending a snapshot to a client that will not read it is held
             * to the same few seconds; reading is bounded by read_request(). */
            io.tv_sec = 3; io.tv_usec = 0;
            (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof io);
            (void)setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        }
        handle_conn(ctx, cfd);
        close(cfd);
    }
    close(lfd);
    return NULL;
}
