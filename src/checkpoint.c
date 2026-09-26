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
#include "elpis/mesh.h"

#include <errno.h>
#include <pthread.h>
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
/* Merging                                                             */
/* ------------------------------------------------------------------ */

/* FNV-1a over the question: only to bring equal ones together. */
static uint64_t ent_key(const elpis_ckpt_list_t *l, const elpis_ckpt_ent_t *e)
{
    const uint8_t *p = elpis_ckpt_name(l, e);
    uint64_t h = 0xCBF29CE484222325ull;
    unsigned i;

    for (i = 0; i < e->namelen; i++)
        h = (h ^ p[i]) * 0x100000001B3ull;
    h = (h ^ e->qtype) * 0x100000001B3ull;
    h = (h ^ e->kflags) * 0x100000001B3ull;
    return h;
}

static int ent_same(const elpis_ckpt_list_t *l, const elpis_ckpt_ent_t *a,
                    const elpis_ckpt_ent_t *b)
{
    return a->namelen == b->namelen && a->qtype == b->qtype &&
           a->kflags == b->kflags &&
           memcmp(elpis_ckpt_name(l, a), elpis_ckpt_name(l, b), a->namelen) == 0;
}

static int key_cmp(const void *a, const void *b)
{
    const elpis_ckpt_ent_t *x = (const elpis_ckpt_ent_t *)a;
    const elpis_ckpt_ent_t *y = (const elpis_ckpt_ent_t *)b;

    if (x->score != y->score)
        return x->score < y->score ? -1 : 1;
    return x->name_off < y->name_off ? -1 : (x->name_off > y->name_off);
}

/* Fold every repeat of a question into its first appearance. */
static void dedupe(elpis_ckpt_list_t *l)
{
    unsigned i, j, out = 0, run;

    for (i = 0; i < l->n; i++)
        l->ent[i].score = ent_key(l, &l->ent[i]);
    if (l->n > 1)
        qsort(l->ent, l->n, sizeof *l->ent, key_cmp);

    for (i = 0; i < l->n; i = run) {
        /* A run shares a hash; within it, compare the questions properly. */
        for (run = i + 1; run < l->n && l->ent[run].score == l->ent[i].score; run++)
            ;
        for (j = i; j < run; j++) {
            elpis_ckpt_ent_t *e = &l->ent[j];
            unsigned k;
            for (k = out; k > 0 && l->ent[k - 1].score == e->score; k--) {
                elpis_ckpt_ent_t *keep = &l->ent[k - 1];
                if (ent_same(l, keep, e)) {
                    keep->hits += e->hits;
                    if (e->cost_ms > keep->cost_ms)
                        keep->cost_ms = e->cost_ms;
                    break;
                }
            }
            if (k == 0 || l->ent[k - 1].score != e->score)
                l->ent[out++] = *e;
        }
    }
    l->n = out;
    compact(l);
}

int elpis_ckpt_merge(elpis_ckpt_list_t *into, const elpis_ckpt_list_t *from,
                     unsigned div)
{
    unsigned i;

    if (div == 0)
        div = 1;
    for (i = 0; i < from->n; i++) {
        const elpis_ckpt_ent_t *e = &from->ent[i];
        if (elpis_ckpt_list_add(into, elpis_ckpt_name(from, e), e->namelen,
                                e->qtype, e->kflags, (e->hits + div - 1u) / div,
                                e->cost_ms) != ELPIS_OK)
            return ELPIS_ENOMEM;
    }
    dedupe(into);
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static int      g_refuse;          /* something else lives at the path */
static unsigned g_nworkers = 1;
static int      g_warm_on;         /* warm-rate is not 0               */
static int      g_expect_more;     /* the mesh may submit lists later   */
static uint64_t g_start_ms;
/* What was read at startup, until it is submitted or the mesh takes it. */
static elpis_ckpt_list_t g_startup;

#define WARMUP_DELAY_MS 3000u      /* root priming and the TLDs go first */

void elpis_ckpt_load(elpis_ctx_t *ctx, unsigned nworkers)
{
    const elpis_conf_t *c = &ctx->conf;
    unsigned bad = 0;
    int rc;

    g_nworkers    = nworkers ? nworkers : 1u;
    g_warm_on     = c->warm_rate > 0;
    g_expect_more = c->mesh && g_warm_on;
    g_start_ms    = elpis_now_ms();
    elpis_ckpt_list_init(&g_startup);
    if (c->checkpoint[0] == '\0')
        return;

    rc = elpis_ckpt_read(c->checkpoint, c->checkpoint_names, &g_startup, &bad);
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
    elpis_info("checkpoint: %u names read from %s", g_startup.n, c->checkpoint);

    /* With a mesh, the list waits to be merged with what the peers know. */
    if (!c->mesh) {
        elpis_warmup_submit(&g_startup, "checkpoint");
        elpis_ckpt_list_free(&g_startup);
    }
}

void elpis_ckpt_take_startup(elpis_ckpt_list_t *out)
{
    *out = g_startup;
    elpis_ckpt_list_init(&g_startup);
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

/* ------------------------------------------------------------------ */
/* Warm-up jobs                                                        */
/* ------------------------------------------------------------------ */

/*
 * A job is one ranked list to warm: the checkpoint at startup, merged with
 * whatever the mesh's peers sent in time, and later any list a peer sends on
 * its own.  Jobs are taken in order.  Each worker takes every nth name of a
 * job, so all of them work down it from the top together, and paces itself
 * so the workers between them send warm-rate a second.  Clients come first:
 * a worker at half its max-pending issues nothing, the same line the
 * background refreshes stop at.
 *
 * A warm-up task carries what it needs in the task itself, never a pointer
 * into the job, so the last worker to finish its share frees the job.
 */
typedef struct warm_job {
    struct warm_job   *next;
    uint64_t           id;
    elpis_ckpt_list_t  list;
    char               what[96];
    uint64_t           left;          /* workers yet to finish their share */
    uint64_t           issued, cached;
    uint64_t           t0;
} warm_job_t;

static pthread_mutex_t g_jobs_mu = PTHREAD_MUTEX_INITIALIZER;
static warm_job_t     *g_jobs;        /* oldest first */
static uint64_t        g_job_seq;

int elpis_warmup_submit(elpis_ckpt_list_t *l, const char *what)
{
    warm_job_t *j, **pp;
    uint64_t now = elpis_now_ms();

    if (!g_warm_on || l->n == 0)
        return ELPIS_OK;
    j = (warm_job_t *)elpis_calloc(1, sizeof *j);
    if (j == NULL)
        return ELPIS_ENOMEM;
    j->list = *l;                   /* the job owns the names from here */
    elpis_ckpt_list_init(l);
    elpis_strlcpy(j->what, what, sizeof j->what);
    j->left = g_nworkers;
    j->t0 = now > g_start_ms + WARMUP_DELAY_MS ? now : g_start_ms + WARMUP_DELAY_MS;

    pthread_mutex_lock(&g_jobs_mu);
    j->id = ++g_job_seq;
    for (pp = &g_jobs; *pp != NULL; pp = &(*pp)->next)
        ;
    *pp = j;
    pthread_mutex_unlock(&g_jobs_mu);

    elpis_info("warm-up: %u names from %s", j->list.n, what);
    return ELPIS_OK;
}

/* The oldest job this worker has not done yet. */
static warm_job_t *job_after(uint64_t id)
{
    warm_job_t *j;

    pthread_mutex_lock(&g_jobs_mu);
    for (j = g_jobs; j != NULL && j->id <= id; j = j->next)
        ;
    pthread_mutex_unlock(&g_jobs_mu);
    return j;
}

static void job_free(warm_job_t *j)
{
    warm_job_t **pp;

    pthread_mutex_lock(&g_jobs_mu);
    for (pp = &g_jobs; *pp != NULL; pp = &(*pp)->next)
        if (*pp == j) {
            *pp = j->next;
            break;
        }
    pthread_mutex_unlock(&g_jobs_mu);
    elpis_ckpt_list_free(&j->list);
    elpis_free(j);
}

void elpis_ckpt_fini(void)
{
    warm_job_t *j;

    elpis_ckpt_list_free(&g_startup);
    while ((j = g_jobs) != NULL) {
        g_jobs = j->next;
        elpis_ckpt_list_free(&j->list);
        elpis_free(j);
    }
}

#define WARMUP_TICK_MS 100u
#define WARMUP_BURST   16u         /* most one tick catches up on */

typedef struct {
    elpis_worker_t *w;
    elpis_timer_t   timer;
    warm_job_t     *job;           /* the one being worked on, or NULL */
    uint64_t        done_id;       /* the newest job finished          */
    unsigned        next, stride;
    unsigned        inflight;
    unsigned        issued, cached;
    uint64_t        credit;
    uint64_t        last_ms;       /* when this worker last issued one */
} warmup_t;

static ELPIS_TLS warmup_t g_wu;

static void ent_key_m(const elpis_ckpt_list_t *l, const elpis_ckpt_ent_t *e,
                      elpis_mkey_t *k)
{
    k->qname    = elpis_ckpt_name(l, e);
    k->qnamelen = e->namelen;
    k->qtype    = e->qtype;
    k->qclass   = ELPIS_CLASS_IN;
    k->kflags   = e->kflags;
    elpis_mkey_hash(k);
}

/*
 * The warmed entry starts with half the count its list carried, so a name
 * nobody asks for any more fades out over a few restarts rather than being
 * warmed for ever on the strength of old traffic.
 *
 * That count may be partly a peer's, already halved in the merge.  Carrying
 * it is what lets the knowledge outlive the instance that gathered it: when
 * the one instance clients use restarts, the siblings it warmed hand its
 * names back, at a quarter of the weight, and they fade unless asked again.
 * Lists move only when an instance starts, so this is a decay, not a loop.
 */
static uint8_t warmup_pop(const elpis_ckpt_ent_t *e)
{
    return elpis_pop_from_hits(e->hits / 2u);
}

static void warmup_done(elpis_task_t *t, void *ctx)
{
    uint8_t folded[ELPIS_MAX_NAME];
    elpis_mkey_t k;

    (void)ctx;
    memcpy(folded, t->orig_qname.d, t->orig_qname.len);
    k.qname    = folded;
    k.qnamelen = t->orig_qname.len;
    k.qtype    = t->orig_qtype;
    k.qclass   = t->qclass;
    k.kflags   = (uint8_t)((t->client_do ? ELPIS_MK_DO : 0u) |
                           (t->client_cd ? ELPIS_MK_CD : 0u));
    elpis_mkey_hash(&k);
    elpis_mcache_seed(t->w->ctx->mcache, &k, t->warm_pop);
    if (g_wu.inflight > 0)
        g_wu.inflight--;
}

/* This worker's share of the job is done; the last one out frees it. */
static void job_share_done(warmup_t *s)
{
    warm_job_t *j = s->job;

    s->done_id = j->id;
    s->job = NULL;
    elpis_atomic_add64(&j->issued, s->issued);
    elpis_atomic_add64(&j->cached, s->cached);
    if (elpis_atomic_sub64(&j->left, 1) != 0)
        return;                     /* not ours to touch any more */
    elpis_info("warm-up: %s done in %.1f s, %llu names resolved, %llu "
               "already cached", j->what,
               (double)(elpis_now_ms() - j->t0) / 1000.0,
               (unsigned long long)elpis_atomic_load64(&j->issued),
               (unsigned long long)elpis_atomic_load64(&j->cached));
    {
        uint64_t took = elpis_now_ms() - j->t0;
        elpis_mesh_event(ELPIS_MESH_EV_WARM, 0, j->what, 0, "",
                         took > 4294967u ? 0xFFFFFFFFu : (uint32_t)(took * 1000u),
                         (uint32_t)elpis_atomic_load64(&j->issued), NULL);
    }
    job_free(j);
}

static void warmup_tick(elpis_loop_t *lp, elpis_timer_t *tm)
{
    warmup_t *s = (warmup_t *)tm->data;
    elpis_worker_t *w = s->w;
    const elpis_conf_t *c = &w->ctx->conf;
    /* Credit is in tenths of a query per worker: warm-rate is for all of
     * them together, and a tick is a tenth of a second. */
    uint64_t unit = 10ull * s->stride;
    const elpis_ckpt_list_t *l;
    uint64_t now;

    (void)lp;
    if (w->ctx->shutdown)
        return;
    now = elpis_cached_now_ms();

    if (s->job == NULL) {
        s->job = job_after(s->done_id);
        if (s->job == NULL) {
            if (g_expect_more)
                elpis_timer_add(w->loop, &s->timer, WARMUP_TICK_MS,
                                warmup_tick, s);
            return;
        }
        s->next = w->index;
        s->issued = s->cached = 0;
        s->inflight = 0;
        s->last_ms = now;
    }
    l = &s->job->list;

    s->credit += c->warm_rate;
    if (s->credit > unit * WARMUP_BURST)
        s->credit = unit * WARMUP_BURST;

    while (s->credit >= unit && s->next < l->n) {
        const elpis_ckpt_ent_t *e = &l->ent[s->next];
        elpis_mkey_t k;
        elpis_name_t n;
        elpis_task_t *t;
        size_t used;

        if (w->n_tasks >= c->max_pending / 2u)
            break;

        ent_key_m(l, e, &k);
        if (elpis_mcache_seed(w->ctx->mcache, &k, warmup_pop(e))) {
            s->next += s->stride;       /* a client, or a job before, got there first */
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
        t->warm_pop  = warmup_pop(e);
        t->client_do = (e->kflags & ELPIS_MK_DO) ? 1u : 0u;
        t->client_cd = (e->kflags & ELPIS_MK_CD) ? 1u : 0u;
        t->done_cb   = warmup_done;
        s->next += s->stride;
        s->inflight++;
        s->issued++;
        s->credit -= unit;
        s->last_ms = now;
        elpis_task_start(t);
    }

    /*
     * The share is done when it is issued and answered.  A resolution gives
     * up by query-total-timeout, so one still counted after twice that is a
     * count gone astray, not a query: stop waiting for it.
     */
    if (s->next >= l->n &&
        (s->inflight == 0 || now - s->last_ms >= 2ull * c->query_total_ms))
        job_share_done(s);
    elpis_timer_add(w->loop, &s->timer, WARMUP_TICK_MS, warmup_tick, s);
}

int elpis_warmup_start(elpis_worker_t *w, unsigned nworkers)
{
    if (!g_warm_on)
        return ELPIS_OK;
    memset(&g_wu, 0, sizeof g_wu);
    g_wu.w      = w;
    g_wu.stride = nworkers ? nworkers : 1u;
    elpis_timer_add(w->loop, &g_wu.timer, WARMUP_DELAY_MS, warmup_tick, &g_wu);
    return ELPIS_OK;
}
