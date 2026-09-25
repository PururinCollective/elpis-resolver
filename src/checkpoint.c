/*
 * checkpoint.c -- the questions clients ask, written down and warmed back.
 *
 * See elpis/checkpoint.h for why it holds names and not answers.  In order:
 *
 *   collect   walk the message cache, keep what clients asked often enough
 *   rank      hits times cold cost, best first
 *   write     text, one question a line, replaced whole or not at all
 *   read      the same text back, skipping whatever does not parse
 *   warm-up   at startup every worker resolves its share of the list
 */
#include "elpis/checkpoint.h"
#include "elpis/resolver.h"
#include "elpis/store.h"
#include "elpis/name.h"
#include "elpis/util.h"
#include "elpis/log.h"
#include "elpis/atomic.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* The list                                                            */
/* ------------------------------------------------------------------ */

/* 50,000 names average under 30 bytes each; this is far past any real list. */
#define CKPT_NAMES_MAX ((size_t)1 << 30)

void elpis_ckpt_list_init(elpis_ckpt_list_t *l)
{
    memset(l, 0, sizeof *l);
}

void elpis_ckpt_list_free(elpis_ckpt_list_t *l)
{
    elpis_free(l->ent);
    elpis_free(l->names);
    memset(l, 0, sizeof *l);
}

int elpis_ckpt_list_add(elpis_ckpt_list_t *l, const uint8_t *qname,
                        uint8_t qnamelen, uint16_t qtype, uint8_t kflags,
                        uint64_t hits, uint32_t cost_ms)
{
    elpis_ckpt_ent_t *e;

    if (qnamelen == 0)
        return ELPIS_ERR;
    if (l->n == l->cap) {
        unsigned nc = l->cap ? l->cap * 2u : 1024u;
        void *p = elpis_realloc(l->ent, (size_t)nc * sizeof *l->ent);
        if (p == NULL)
            return ELPIS_ENOMEM;
        l->ent = (elpis_ckpt_ent_t *)p;
        l->cap = nc;
    }
    if (l->names_len + qnamelen > l->names_cap) {
        size_t nc = l->names_cap ? l->names_cap * 2u : 32768u;
        void *p;
        while (nc < l->names_len + qnamelen)
            nc *= 2u;
        if (nc > CKPT_NAMES_MAX)
            return ELPIS_ENOMEM;
        p = elpis_realloc(l->names, nc);
        if (p == NULL)
            return ELPIS_ENOMEM;
        l->names = (uint8_t *)p;
        l->names_cap = nc;
    }

    e = &l->ent[l->n++];
    memset(e, 0, sizeof *e);
    e->hits     = hits;
    e->name_off = (uint32_t)l->names_len;
    e->namelen  = qnamelen;
    e->qtype    = qtype;
    e->kflags   = (uint8_t)(kflags & (ELPIS_MK_DO | ELPIS_MK_CD));
    e->cost_ms  = (uint16_t)(cost_ms > 0xFFFFu ? 0xFFFFu : cost_ms);
    memcpy(l->names + l->names_len, qname, qnamelen);
    l->names_len += qnamelen;
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Ranking                                                             */
/* ------------------------------------------------------------------ */

/*
 * The floor is for a name whose first answer came out of the RRset cache and
 * so recorded a cost of nearly nothing: it still ranks by how often it is
 * asked rather than sinking to the bottom.  The cap stops one resolution that
 * sat through timeouts from outranking everything for good.
 */
#define CKPT_COST_FLOOR 20u
#define CKPT_COST_CAP   10000u

uint64_t elpis_ckpt_score(uint64_t hits, uint32_t cost_ms)
{
    if (cost_ms > CKPT_COST_CAP)
        cost_ms = CKPT_COST_CAP;
    if (hits > UINT64_MAX / (CKPT_COST_CAP + CKPT_COST_FLOOR))
        hits = UINT64_MAX / (CKPT_COST_CAP + CKPT_COST_FLOOR);
    return hits * (uint64_t)(cost_ms + CKPT_COST_FLOOR);
}

static int ent_cmp(const void *a, const void *b)
{
    const elpis_ckpt_ent_t *x = (const elpis_ckpt_ent_t *)a;
    const elpis_ckpt_ent_t *y = (const elpis_ckpt_ent_t *)b;

    if (x->score != y->score)
        return x->score > y->score ? -1 : 1;
    if (x->hits != y->hits)
        return x->hits > y->hits ? -1 : 1;
    /* The order they were added in, so equal entries stay put. */
    return x->name_off < y->name_off ? -1 : (x->name_off > y->name_off);
}

/* Drop the names of entries that were cut, so the arena shrinks with them. */
static void compact(elpis_ckpt_list_t *l)
{
    size_t need = 0, off = 0;
    unsigned i;
    uint8_t *arena;

    for (i = 0; i < l->n; i++)
        need += l->ent[i].namelen;
    if (need == l->names_len)
        return;
    arena = (uint8_t *)elpis_malloc(need ? need : 1u);
    if (arena == NULL)
        return;                 /* the old arena is still right, just big */
    for (i = 0; i < l->n; i++) {
        elpis_ckpt_ent_t *e = &l->ent[i];
        memcpy(arena + off, l->names + e->name_off, e->namelen);
        e->name_off = (uint32_t)off;
        off += e->namelen;
    }
    elpis_free(l->names);
    l->names     = arena;
    l->names_len = need;
    l->names_cap = need ? need : 1u;
}

void elpis_ckpt_rank(elpis_ckpt_list_t *l, unsigned max)
{
    unsigned i;

    for (i = 0; i < l->n; i++)
        l->ent[i].score = elpis_ckpt_score(l->ent[i].hits, l->ent[i].cost_ms);
    if (l->n > 1)
        qsort(l->ent, l->n, sizeof *l->ent, ent_cmp);
    if (l->n > max)
        l->n = max;
    compact(l);
}

/* ------------------------------------------------------------------ */
/* Collecting                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    elpis_ckpt_list_t *l;
    uint64_t           min_hits;
    unsigned           max;
    int                err;
} collect_t;

static void collect_one(const elpis_mview_t *v, void *arg)
{
    collect_t *c = (collect_t *)arg;
    uint64_t hits;

    if (c->err)
        return;
    if (v->qclass != ELPIS_CLASS_IN)
        return;
    /* NXDOMAIN is kept: a name asked for that often is worth having ready
     * whichever way it answers.  Anything else was never a real answer. */
    if (v->rcode != ELPIS_RC_NOERROR && v->rcode != ELPIS_RC_NXDOMAIN)
        return;
    hits = elpis_pop_hits(v->pop);
    if (hits < c->min_hits)
        return;
    if (elpis_ckpt_list_add(c->l, v->qname, v->qnamelen, v->qtype, v->kflags,
                            hits, v->cost_ms) != ELPIS_OK) {
        c->err = 1;
        return;
    }
    /*
     * Bound the memory on a cache holding far more qualifying names than will
     * be kept.  This runs under one shard's lock, which is why it waits for
     * four times the list rather than trimming on every add.
     */
    if (c->l->n >= c->max * 4u)
        elpis_ckpt_rank(c->l, c->max);
}

int elpis_ckpt_collect(elpis_cache_t *mcache, uint64_t min_hits, unsigned max,
                       elpis_ckpt_list_t *out)
{
    collect_t c;

    if (max == 0)
        max = 1;
    c.l        = out;
    c.min_hits = min_hits;
    c.max      = max;
    c.err      = 0;
    elpis_mcache_walk(mcache, collect_one, &c);
    elpis_ckpt_rank(out, max);
    return c.err ? ELPIS_ENOMEM : ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* The file                                                            */
/* ------------------------------------------------------------------ */

static const char *kflags_text(uint8_t k)
{
    switch (k & (ELPIS_MK_DO | ELPIS_MK_CD)) {
    case ELPIS_MK_DO:               return "do";
    case ELPIS_MK_CD:               return "cd";
    case ELPIS_MK_DO | ELPIS_MK_CD: return "do+cd";
    default:                        return "-";
    }
}

static int kflags_parse(const char *s, uint8_t *out)
{
    if (!strcmp(s, "-"))     { *out = 0;                         return 0; }
    if (!strcmp(s, "do"))    { *out = ELPIS_MK_DO;               return 0; }
    if (!strcmp(s, "cd"))    { *out = ELPIS_MK_CD;               return 0; }
    if (!strcmp(s, "do+cd")) { *out = ELPIS_MK_DO | ELPIS_MK_CD; return 0; }
    return -1;
}

int elpis_ckpt_write(const char *path, const elpis_ckpt_list_t *l)
{
    char tmp[600];
    char when[40];
    time_t now = time(NULL);
    struct tm tmv;
    unsigned i;
    FILE *f;
    int fd;

    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp", path) >= sizeof tmp)
        return ELPIS_ERR;

    /*
     * Created fresh, never through a link: a leftover from a crash is removed
     * first, and whatever is at the name after that is not followed.
     */
    (void)unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        elpis_warn("checkpoint: cannot create %s: %s", tmp, strerror(errno));
        return ELPIS_ERR;
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
        (void)unlink(tmp);
        return ELPIS_ERR;
    }

    if (gmtime_r(&now, &tmv) == NULL ||
        strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S UTC", &tmv) == 0)
        elpis_strlcpy(when, "an unknown time", sizeof when);
    fprintf(f, "%s\n", ELPIS_CKPT_MAGIC);
    fprintf(f, "# written %s by elpis %s, %u names\n", when, ELPIS_VERSION, l->n);
    fprintf(f, "#\n"
               "# The questions clients asked most, in the order a restart "
               "warms them:\n"
               "# estimated hits, slowest resolution in ms, DO/CD bits, "
               "type, name.\n");

    for (i = 0; i < l->n; i++) {
        const elpis_ckpt_ent_t *e = &l->ent[i];
        elpis_name_t n;
        size_t used;
        char text[ELPIS_MAX_NAME * 4 + 1];

        if (elpis_name_parse_nocomp(&n, elpis_ckpt_name(l, e), e->namelen,
                                    &used) != ELPIS_OK ||
            elpis_name_to_text(&n, text, sizeof text) != ELPIS_OK)
            continue;
        fprintf(f, "%llu %u %s %s %s\n", (unsigned long long)e->hits,
                (unsigned)e->cost_ms, kflags_text(e->kflags),
                elpis_type_name(e->qtype), text);
    }

    if (fflush(f) != 0 || ferror(f) || fsync(fileno(f)) != 0) {
        elpis_warn("checkpoint: cannot write %s: %s", tmp, strerror(errno));
        fclose(f);
        (void)unlink(tmp);
        return ELPIS_ERR;
    }
    if (fclose(f) != 0) {
        elpis_warn("checkpoint: cannot write %s: %s", tmp, strerror(errno));
        (void)unlink(tmp);
        return ELPIS_ERR;
    }
    if (rename(tmp, path) != 0) {
        elpis_warn("checkpoint: cannot rename %s to %s: %s", tmp, path,
                   strerror(errno));
        (void)unlink(tmp);
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

static int is_blank(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/*
 * One line: hits, cost, flags, type, name.  Returns 1 when an entry was
 * added, 0 for a comment or a blank line, -1 for anything that does not
 * parse.
 */
static int parse_line(char *s, elpis_ckpt_list_t *l)
{
    char *f[5];
    unsigned nf = 0;
    char *p = s, *end;
    unsigned long long hits;
    uint32_t cost;
    uint8_t kflags;
    uint16_t qtype;
    elpis_name_t name;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '#' || *p == '\0' || *p == '\r' || *p == '\n')
        return 0;

    while (nf < 5) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '\r' || *p == '\n')
            break;
        f[nf++] = p;
        while (*p != '\0' && !is_blank(*p))
            p++;
        if (*p != '\0')
            *p++ = '\0';
    }
    while (is_blank(*p))
        p++;
    if (nf != 5 || *p != '\0')
        return -1;

    if (f[0][0] < '0' || f[0][0] > '9')
        return -1;
    errno = 0;
    hits = strtoull(f[0], &end, 10);
    if (errno != 0 || *end != '\0')
        return -1;
    if (elpis_parse_u32(f[1], &cost) != 0)
        return -1;
    if (kflags_parse(f[2], &kflags) != 0)
        return -1;
    if (elpis_type_parse(f[3], &qtype) != 0 || qtype == 0 ||
        elpis_type_is_meta(qtype))
        return -1;
    if (elpis_name_from_text(&name, f[4]) != ELPIS_OK)
        return -1;
    elpis_name_lower(&name);

    if (elpis_ckpt_list_add(l, name.d, name.len, qtype, kflags,
                            (uint64_t)hits, cost) != ELPIS_OK)
        return -1;
    return 1;
}

int elpis_ckpt_read(const char *path, unsigned max, elpis_ckpt_list_t *l,
                    unsigned *bad)
{
    char line[2048];
    int skipping = 0;
    size_t len;
    FILE *f;

    *bad = 0;
    if (max == 0)
        max = 1;
    f = fopen(path, "r");
    if (f == NULL)
        return errno == ENOENT ? ELPIS_ENOTFOUND : ELPIS_ERR;

    /*
     * The first line has to say what the file is.  The path is rewritten in
     * place later, so a typo that points it at something else -- the config
     * file, say -- must be caught here rather than overwritten.  An empty file
     * holds nothing to lose and counts as no checkpoint yet.
     */
    if (fgets(line, sizeof line, f) == NULL) {
        int empty = feof(f) && !ferror(f);
        fclose(f);
        return empty ? ELPIS_ENOTFOUND : ELPIS_EFORMAT;
    }
    len = strlen(line);
    while (len > 0 && is_blank(line[len - 1]))
        line[--len] = '\0';
    if (strcmp(line, ELPIS_CKPT_MAGIC) != 0) {
        fclose(f);
        return ELPIS_EFORMAT;
    }

    while (fgets(line, sizeof line, f) != NULL) {
        int complete;

        len = strlen(line);
        complete = len > 0 && line[len - 1] == '\n';
        if (skipping) {
            skipping = !complete;
            continue;
        }
        if (!complete && !feof(f)) {
            (*bad)++;               /* longer than any real line can be */
            skipping = 1;
            continue;
        }
        if (parse_line(line, l) < 0)
            (*bad)++;
        if (l->n >= max * 4u)
            elpis_ckpt_rank(l, max);
    }
    fclose(f);
    elpis_ckpt_rank(l, max);
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

/*
 * What the warm-up works through: read once before the workers start and
 * only read after, so it needs no lock.  It is freed after they stop, never
 * before -- a warm-up task keeps a pointer into it until it finishes.
 */
static elpis_ckpt_list_t g_list;
static int      g_refuse;          /* something else lives at the path */
static uint64_t g_warm_left;       /* workers still warming            */
static uint64_t g_warm_issued, g_warm_cached;
static uint64_t g_warm_t0;

#define WARMUP_DELAY_MS 3000u      /* root priming and the TLDs go first */

void elpis_ckpt_load(elpis_ctx_t *ctx, unsigned nworkers)
{
    const elpis_conf_t *c = &ctx->conf;
    unsigned bad = 0;
    int rc;

    elpis_ckpt_list_init(&g_list);
    if (c->checkpoint[0] == '\0')
        return;

    rc = elpis_ckpt_read(c->checkpoint, c->checkpoint_names, &g_list, &bad);
    if (rc == ELPIS_ENOTFOUND) {
        elpis_info("checkpoint: no names in %s yet", c->checkpoint);
        return;
    }
    if (rc == ELPIS_EFORMAT) {
        g_refuse = 1;
        elpis_error("checkpoint: %s is not a checkpoint file; it is neither "
                    "read nor written over", c->checkpoint);
        return;
    }
    if (rc != ELPIS_OK) {
        elpis_warn("checkpoint: cannot read %s: %s", c->checkpoint,
                   strerror(errno));
        return;
    }
    if (bad > 0)
        elpis_warn("checkpoint: %u line%s of %s did not parse and were "
                   "skipped", bad, bad == 1 ? "" : "s", c->checkpoint);

    if (c->warm_rate == 0 || g_list.n == 0) {
        elpis_info("checkpoint: %u names in %s, warm-up off", g_list.n,
                   c->checkpoint);
        elpis_ckpt_list_free(&g_list);
        return;
    }
    g_warm_left = nworkers ? nworkers : 1u;
    g_warm_t0   = elpis_now_ms() + WARMUP_DELAY_MS;
    elpis_info("checkpoint: warming %u names from %s at %u a second",
               g_list.n, c->checkpoint, (unsigned)c->warm_rate);
}

int elpis_ckpt_writing(const elpis_ctx_t *ctx)
{
    return ctx->conf.checkpoint[0] != '\0' &&
           ctx->conf.checkpoint_interval > 0 && !g_refuse;
}

static void write_now(elpis_ctx_t *ctx)
{
    const elpis_conf_t *c = &ctx->conf;
    elpis_ckpt_list_t l;
    uint64_t t0 = elpis_now_ms();

    elpis_ckpt_list_init(&l);
    if (elpis_ckpt_collect(ctx->mcache, c->checkpoint_min_hits,
                           c->checkpoint_names, &l) != ELPIS_OK) {
        elpis_warn("checkpoint: out of memory collecting names");
    } else if (l.n == 0) {
        /*
         * Overwriting with nothing would lose the last good list to a quiet
         * hour after a restart.
         */
        elpis_info("checkpoint: nothing asked often enough yet; %s kept as "
                   "it was", c->checkpoint);
    } else if (elpis_ckpt_write(c->checkpoint, &l) == ELPIS_OK) {
        elpis_info("checkpoint: %u names written to %s in %llu ms", l.n,
                   c->checkpoint,
                   (unsigned long long)(elpis_now_ms() - t0));
    }
    elpis_ckpt_list_free(&l);
}

void *elpis_ckpt_main(void *arg)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)arg;
    uint32_t waited = 0;

    /* Never at shutdown: a restart should cost no more than it did. */
    while (!ctx->shutdown) {
        sleep(1);
        if (ctx->shutdown)
            break;
        if (++waited < ctx->conf.checkpoint_interval)
            continue;
        waited = 0;
        write_now(ctx);
    }
    return NULL;
}

void elpis_ckpt_fini(void)
{
    elpis_ckpt_list_free(&g_list);
}

/* ------------------------------------------------------------------ */
/* Warm-up                                                             */
/* ------------------------------------------------------------------ */

/*
 * Each worker takes every nth name of the ranked list, so all of them work
 * down it from the top together, and paces itself so the workers between them
 * send warm-rate a second.  Clients come first: a worker at half its
 * max-pending issues nothing, the same line the background refreshes stop at.
 */
#define WARMUP_TICK_MS 100u
#define WARMUP_BURST   16u         /* most one tick catches up on */

typedef struct {
    elpis_worker_t *w;
    elpis_timer_t   timer;
    unsigned        next, stride;
    unsigned        inflight;
    unsigned        issued, cached;
    uint64_t        credit;
    uint64_t        last_ms;       /* when this worker last issued one */
} warmup_t;

static ELPIS_TLS warmup_t g_wu;

static void warmup_key(const elpis_ckpt_ent_t *e, elpis_mkey_t *k)
{
    k->qname    = elpis_ckpt_name(&g_list, e);
    k->qnamelen = e->namelen;
    k->qtype    = e->qtype;
    k->qclass   = ELPIS_CLASS_IN;
    k->kflags   = e->kflags;
    elpis_mkey_hash(k);
}

/*
 * The warmed entry starts with half the count the file carries, so a name
 * nobody asks for any more fades out over a few restarts rather than being
 * warmed for ever on the strength of old traffic.
 */
static uint8_t warmup_pop(const elpis_ckpt_ent_t *e)
{
    return elpis_pop_from_hits(e->hits / 2u);
}

static void warmup_done(elpis_task_t *t, void *ctx)
{
    const elpis_ckpt_ent_t *e = (const elpis_ckpt_ent_t *)ctx;
    elpis_mkey_t k;

    warmup_key(e, &k);
    elpis_mcache_seed(t->w->ctx->mcache, &k, warmup_pop(e));
    if (g_wu.inflight > 0)
        g_wu.inflight--;
}

static void warmup_finished(warmup_t *s)
{
    elpis_atomic_add64(&g_warm_issued, s->issued);
    elpis_atomic_add64(&g_warm_cached, s->cached);
    if (elpis_atomic_sub64(&g_warm_left, 1) != 0)
        return;
    elpis_info("checkpoint: warm-up done in %.1f s, %llu names resolved, "
               "%llu already cached by a client",
               (double)(elpis_now_ms() - g_warm_t0) / 1000.0,
               (unsigned long long)elpis_atomic_load64(&g_warm_issued),
               (unsigned long long)elpis_atomic_load64(&g_warm_cached));
}

static void warmup_tick(elpis_loop_t *lp, elpis_timer_t *tm)
{
    warmup_t *s = (warmup_t *)tm->data;
    elpis_worker_t *w = s->w;
    const elpis_conf_t *c = &w->ctx->conf;
    /* Credit is in tenths of a query per worker: warm-rate is for all of
     * them together, and a tick is a tenth of a second. */
    uint64_t unit = 10ull * s->stride;
    uint64_t now;

    (void)lp;
    if (w->ctx->shutdown)
        return;
    now = elpis_cached_now_ms();

    s->credit += c->warm_rate;
    if (s->credit > unit * WARMUP_BURST)
        s->credit = unit * WARMUP_BURST;

    while (s->credit >= unit && s->next < g_list.n) {
        const elpis_ckpt_ent_t *e = &g_list.ent[s->next];
        elpis_mkey_t k;
        elpis_name_t n;
        elpis_task_t *t;
        size_t used;

        if (w->n_tasks >= c->max_pending / 2u)
            break;

        warmup_key(e, &k);
        if (elpis_mcache_seed(w->ctx->mcache, &k, warmup_pop(e))) {
            s->next += s->stride;       /* a client got there first */
            s->cached++;
            continue;
        }
        if (elpis_name_parse_nocomp(&n, k.qname, k.qnamelen, &used) != ELPIS_OK) {
            s->next += s->stride;
            continue;
        }
        t = elpis_task_new(w);
        if (t == NULL)
            break;
        t->qname     = n;
        t->qtype     = e->qtype;
        t->qclass    = ELPIS_CLASS_IN;
        t->warmup    = 1;
        t->client_do = (e->kflags & ELPIS_MK_DO) ? 1u : 0u;
        t->client_cd = (e->kflags & ELPIS_MK_CD) ? 1u : 0u;
        t->done_cb   = warmup_done;
        t->done_ctx  = (void *)e;
        s->next += s->stride;
        s->inflight++;
        s->issued++;
        s->credit -= unit;
        s->last_ms = now;
        elpis_task_start(t);
    }

    /*
     * Done when the share is issued and answered.  A resolution gives up by
     * query-total-timeout, so one still counted after twice that is a count
     * gone astray, not a query -- stop waiting for it.  The list stays until
     * shutdown either way, so a late callback still finds its entry.
     */
    if (s->next < g_list.n ||
        (s->inflight > 0 &&
         now - s->last_ms < 2ull * c->query_total_ms)) {
        elpis_timer_add(w->loop, &s->timer, WARMUP_TICK_MS, warmup_tick, s);
        return;
    }
    warmup_finished(s);
}

int elpis_warmup_start(elpis_worker_t *w, unsigned nworkers)
{
    if (g_list.n == 0 || w->ctx->conf.warm_rate == 0)
        return ELPIS_OK;
    memset(&g_wu, 0, sizeof g_wu);
    g_wu.w      = w;
    g_wu.next   = w->index;
    g_wu.stride = nworkers ? nworkers : 1u;
    g_wu.last_ms = elpis_cached_now_ms();
    elpis_timer_add(w->loop, &g_wu.timer, WARMUP_DELAY_MS, warmup_tick, &g_wu);
    return ELPIS_OK;
}
