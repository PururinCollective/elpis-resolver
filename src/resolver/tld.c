/*
 * tld.c -- root priming and TLD cache warming.
 *
 * The point of both is the same: make sure a query for anything under a
 * common TLD never has to start at a root server.  A referral from the root
 * pins the child delegation automatically (see absorb_referral), so warming
 * is just a matter of asking once, quietly, at startup.
 *
 * When root-zone-transfer is enabled the AXFR in axfr.c does this for every
 * TLD at once and the list below is not used.  The list exists for
 * deployments that would rather not open a TCP transfer to ICANN.
 */
#include "elpis/resolver.h"
#include "elpis/deleg.h"
#include "elpis/log.h"
#include "elpis/crypto.h"
#include "elpis/rdata.h"

/*
 * The TLDs that carry essentially all real query volume.  Warming ~120 of
 * them costs a couple of hundred packets once, and removes the root from the
 * critical path for the overwhelming majority of lookups.
 */
static const char *const k_tlds[] = {
    "com.", "net.", "org.", "info.", "biz.", "io.", "co.", "ai.", "dev.",
    "app.", "xyz.", "online.", "site.", "shop.", "cloud.", "tech.", "store.",
    "edu.", "gov.", "mil.", "int.", "arpa.",
    "uk.", "de.", "jp.", "fr.", "au.", "ca.", "cn.", "ru.", "br.", "in.",
    "it.", "nl.", "es.", "se.", "no.", "fi.", "dk.", "pl.", "be.", "ch.",
    "at.", "cz.", "gr.", "pt.", "hu.", "ro.", "bg.", "hr.", "si.", "sk.",
    "lt.", "lv.", "ee.", "ie.", "is.", "lu.", "mt.", "cy.",
    "us.", "mx.", "ar.", "cl.", "co.za", "za.", "ng.", "ke.", "eg.", "ma.",
    "kr.", "tw.", "hk.", "sg.", "my.", "th.", "id.", "ph.", "vn.", "nz.",
    "tr.", "il.", "sa.", "ae.", "ir.", "pk.", "bd.", "lk.", "np.",
    "ua.", "by.", "kz.", "uz.", "ge.", "am.", "az.",
    "eu.", "asia.", "tv.", "me.", "cc.", "ws.", "to.", "fm.", "gg.", "im.",
    "live.", "life.", "world.", "today.", "news.", "blog.", "wiki.", "link.",
    "click.", "space.", "website.", "digital.", "agency.", "media.", "studio.",
    "email.", "network.", "systems.", "solutions.", "services.", "group.",
    "center.", "company.", "team.", "works.", "zone.", "run.", "page.",
    "pro.", "name.", "mobi.", "travel.", "jobs.", "coop.", "aero", "cat.",
    "post.", "tel.", "xxx.", "onl."
};

typedef struct {
    elpis_worker_t *w;
    elpis_timer_t   timer;
    unsigned        index;
    unsigned        inflight;
    unsigned        done;
} warm_state_t;

static ELPIS_TLS warm_state_t g_warm;

static void warm_done(elpis_task_t *child, void *ctx)
{
    (void)child;
    (void)ctx;
    if (g_warm.inflight)
        g_warm.inflight--;
    g_warm.done++;
}
/* ------------------------------------------------------------------ */
/* Priming                                                             */
/* ------------------------------------------------------------------ */

static void prime_done(elpis_task_t *t, void *ctx)
{
    elpis_worker_t *w = t->w;
    elpis_deleg_t d;
    unsigned i;
    unsigned learned = 0;

    (void)ctx;
    if (t->rcode != ELPIS_RC_NOERROR)
        return;

    /* Start from the built-in hints so a partial answer cannot lose servers. */
    d = w->ctx->root_hints;
    d.pinned = 1;

    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        elpis_name_t target;

        if (rr->type != ELPIS_T_NS)
            continue;
        if (elpis_rdata_target(ELPIS_T_NS, elpis_trr_rd(&t->ans, i),
                               rr->rdlen, &target) != ELPIS_OK)
            continue;
        elpis_name_lower(&target);
        elpis_deleg_add_ns(&d, &target);
        learned++;
    }

    if (learned > 0) {
        d.ttl = 518400;
        elpis_dcache_put(w->ctx->dcache, &d, d.ttl, 1);
        elpis_info("worker %u: root primed, %u nameservers, %u addresses",
                   w->index, d.nns, elpis_deleg_addr_count(&d));
    }
}

int elpis_prime_start(elpis_worker_t *w)
{
    elpis_task_t *t;
    elpis_name_t root;

    if (!w->ctx->conf.prime_root)
        return ELPIS_OK;

    elpis_name_init_root(&root);
    t = elpis_task_new(w);
    if (t == NULL)
        return ELPIS_ENOMEM;

    t->qname   = root;
    t->qtype   = ELPIS_T_NS;
    t->qclass  = ELPIS_CLASS_IN;
    t->done_cb  = prime_done;
    t->prefetch = 1;
    t->warming  = 1;
    elpis_task_start(t);
    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Warming                                                             */
/* ------------------------------------------------------------------ */

/*
 * Warming is background work: two at a time, four per second.  The whole
 * list finishes inside a minute and never competes with a real query for
 * sockets or upstream patience.
 */
#define WARM_BATCH   2
#define WARM_PERIOD  500u      /* milliseconds between batches */

static void warm_tick(elpis_loop_t *lp, elpis_timer_t *tm)
{
    warm_state_t *s = (warm_state_t *)tm->data;
    elpis_worker_t *w = s->w;
    unsigned issued = 0;

    (void)lp;
    if (w->ctx->shutdown)
        return;

    while (issued < WARM_BATCH && s->index < ELPIS_ARRAY_LEN(k_tlds)) {
        elpis_name_t n;
        elpis_task_t *t;
        elpis_deleg_t d;

        if (elpis_name_from_text(&n, k_tlds[s->index++]) != ELPIS_OK)
            continue;
        elpis_name_lower(&n);

        /* Already pinned (perhaps by the zone transfer)?  Nothing to do. */
        if (elpis_dcache_get(w->ctx->dcache, &n, elpis_cached_now_s(), &d) == ELPIS_OK &&
            elpis_deleg_addr_count(&d) > 0)
            continue;

        t = elpis_task_new(w);
        if (t == NULL)
            break;
        t->qname    = n;
        t->qtype    = ELPIS_T_NS;
        t->qclass   = ELPIS_CLASS_IN;
        t->prefetch = 1;
        t->warming  = 1;
        t->done_cb  = warm_done;
        s->inflight++;
        elpis_task_start(t);
        issued++;
    }

    if (s->index < ELPIS_ARRAY_LEN(k_tlds)) {
        elpis_timer_add(w->loop, &s->timer, WARM_PERIOD, warm_tick, s);
    } else {
        elpis_info("worker %u: TLD warming finished (%u delegations requested)",
                   w->index, s->index);
    }
}

int elpis_tld_warm_start(elpis_worker_t *w)
{
    if (!w->ctx->conf.warm_tlds)
        return ELPIS_OK;
    /* Only one worker needs to do this; the caches are shared. */
    if (w->index != 0)
        return ELPIS_OK;

    memset(&g_warm, 0, sizeof g_warm);
    g_warm.w = w;
    elpis_timer_add(w->loop, &g_warm.timer, 2000, warm_tick, &g_warm);
    return ELPIS_OK;
}
