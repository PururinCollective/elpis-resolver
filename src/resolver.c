/*
 * resolver.c -- the iterative resolution state machine.
 *
 * Shape of a resolution:
 *
 *   LOOKUP  consult the caches; answer straight away when possible
 *   DELEG   find the deepest known delegation at or above the name
 *   SEND    pick the best-performing server in it and query
 *   WAIT    (network)
 *   NSADDR  a chosen nameserver has no address; resolve it with a child task
 *   FINISH  cache, then answer the client or wake the parent task
 *
 * Referrals drive the loop downwards; CNAMEs restart it at LOOKUP with a new
 * name.  Both are bounded, and every accepted record is checked against the
 * bailiwick of the zone that supplied it.
 */
#include "elpis/resolver.h"
#include "elpis/rdata.h"
#include "elpis/deleg.h"
#include "elpis/infra.h"
#include "elpis/log.h"
#include "elpis/crypto.h"
#include "elpis/simd.h"

static void task_finish(elpis_task_t *t);
static void cache_store_answer(elpis_task_t *t);

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

uint32_t elpis_clamp_ttl(const elpis_conf_t *c, uint32_t ttl)
{
    /* RFC 2181 section 8: the top bit set means "expired", treat as zero. */
    if (ttl & 0x80000000u)
        ttl = 0;
    if (ttl < c->cache_min_ttl)
        ttl = c->cache_min_ttl;
    if (ttl > c->cache_max_ttl)
        ttl = c->cache_max_ttl;
    return ttl;
}

uint32_t elpis_clamp_neg_ttl(const elpis_conf_t *c, uint32_t ttl)
{
    if (ttl & 0x80000000u)
        ttl = 0;
    if (ttl < c->cache_min_neg_ttl)
        ttl = c->cache_min_neg_ttl;
    if (ttl > c->cache_max_neg_ttl)
        ttl = c->cache_max_neg_ttl;
    return ttl;
}

static int in_bailiwick(const elpis_name_t *n, const elpis_name_t *zone)
{
    return elpis_name_is_subdomain(n, zone);
}

/*
 * Deepest configured forward-zone or stub-zone covering `name`.
 *
 * A stub zone is iterative: we talk to the listed servers as if they were the
 * zone's own authorities.  A forward zone is recursive: we set RD and take
 * whatever comes back as the answer, because the far side is doing the work.
 */
static const elpis_zoneroute_t *route_lookup(const elpis_conf_t *c,
                                             const elpis_name_t *name)
{
    const elpis_zoneroute_t *best = NULL;
    unsigned i;

    for (i = 0; i < c->nroute; i++) {
        elpis_name_t z;
        if (elpis_name_from_text(&z, c->route[i].name) != ELPIS_OK)
            continue;
        if (!elpis_name_is_subdomain(name, &z))
            continue;
        if (best == NULL) {
            best = &c->route[i];
        } else {
            elpis_name_t bz;
            if (elpis_name_from_text(&bz, best->name) == ELPIS_OK &&
                z.labels > bz.labels)
                best = &c->route[i];
        }
    }
    return best;
}

/* Turn a configured route into a delegation the send path can use. */
static int route_to_deleg(const elpis_zoneroute_t *r, elpis_deleg_t *d)
{
    elpis_name_t zone;
    unsigned i;

    if (elpis_name_from_text(&zone, r->name) != ELPIS_OK)
        return 0;
    memset(d, 0, sizeof *d);
    d->zone = zone;
    elpis_name_lower(&d->zone);
    d->sec      = ELPIS_SEC_UNCHECKED;
    d->ds_state = ELPIS_DS_UNKNOWN;
    d->ttl      = 3600;

    /*
     * The configured addresses have no names of their own, so they are all
     * hung off one pseudo-nameserver named for the zone.  Nothing downstream
     * looks at that name except to avoid resolving it.
     */
    elpis_deleg_add_ns(d, &d->zone);
    for (i = 0; i < r->naddr; i++) {
        const elpis_addr_t *a = &r->addr[i];
        uint16_t port = elpis_addr_port(a);
        if (port == 0)
            port = 53;
        if (elpis_addr_family(a) == AF_INET)
            elpis_deleg_add_addr_port(d, &d->zone,
                                      (const uint8_t *)&a->u.v4.sin_addr,
                                      AF_INET, ELPIS_NSF_RESOLVED, port);
        else if (elpis_addr_family(a) == AF_INET6)
            elpis_deleg_add_addr_port(d, &d->zone,
                                      (const uint8_t *)&a->u.v6.sin6_addr,
                                      AF_INET6, ELPIS_NSF_RESOLVED, port);
    }
    return elpis_deleg_addr_count(d) > 0;
}

/* ================================================================== */
/* Task lifecycle                                                      */
/* ================================================================== */

elpis_task_t *elpis_task_new(elpis_worker_t *w)
{
    elpis_task_t *t = (elpis_task_t *)elpis_calloc(1, sizeof *t);
    if (t == NULL)
        return NULL;
    t->w = w;
    t->qclass = ELPIS_CLASS_IN;
    t->sec = ELPIS_SEC_UNCHECKED;
    t->ede = -1;
    t->state = ELPIS_TS_INIT;
    t->start_ms = elpis_cached_now_ms();
    elpis_rrlist_init(&t->ans);
    w->n_tasks++;
    return t;
}

static void task_unlink(elpis_task_t *t)
{
    elpis_task_t *p = t->parent;

    if (p == NULL)
        return;
    if (t->sib_prev != NULL) t->sib_prev->sib_next = t->sib_next;
    else                     p->children = t->sib_next;
    if (t->sib_next != NULL) t->sib_next->sib_prev = t->sib_prev;
    t->sib_next = t->sib_prev = NULL;
    t->parent = NULL;
}

void elpis_task_free(elpis_task_t *t)
{
    if (t == NULL)
        return;

    /*
     * Detach any children still running.  They finish on their own and warm
     * the cache; what matters is that they no longer hold a pointer to memory
     * that is about to go away.
     */
    while (t->children != NULL) {
        elpis_task_t *c = t->children;
        t->children = c->sib_next;
        c->sib_next = c->sib_prev = NULL;
        c->parent   = NULL;
        c->done_cb  = NULL;
        c->done_ctx = NULL;
    }
    task_unlink(t);

    elpis_out_cancel(t);
    elpis_timer_del(t->w->loop, &t->deadline);
    elpis_timer_del(t->w->loop, &t->kick);
    elpis_val_free(t);
    elpis_rrlist_free(&t->ans);
    if (t->w->n_tasks)
        t->w->n_tasks--;
    elpis_free(t);
}

static void task_deadline(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_task_t *t = (elpis_task_t *)tm->data;
    (void)lp;
    elpis_debug("task deadline reached for a query");
    elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_NO_REACHABLE_AUTH);
}

static void task_kick(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_task_t *t = (elpis_task_t *)tm->data;
    const elpis_conf_t *c = &t->w->ctx->conf;

    (void)lp;
    if (t->state != ELPIS_TS_INIT)
        return;
    t->state = ELPIS_TS_LOOKUP;
    elpis_timer_add(t->w->loop, &t->deadline, c->query_total_ms,
                    task_deadline, t);
    elpis_task_step(t);
}

/*
 * Resolution always begins on the next turn of the event loop, never inside
 * the caller.  A child that hits the cache would otherwise run to completion
 * before elpis_task_child() returned, re-entering its own parent's state
 * machine half-way through an update.
 */
void elpis_task_start(elpis_task_t *t)
{
    t->orig_qname = t->qname;
    t->orig_qtype = t->qtype;
    t->state = ELPIS_TS_INIT;
    elpis_timer_add(t->w->loop, &t->kick, 0, task_kick, t);
}

void elpis_task_fail(elpis_task_t *t, unsigned rcode, int ede)
{
    if (t->state == ELPIS_TS_DEAD)
        return;
    elpis_out_cancel(t);
    t->rcode = rcode;
    if (ede >= 0 && t->ede < 0)
        t->ede = ede;
    t->state = ELPIS_TS_FINISH;
    task_finish(t);
}

/* ================================================================== */
/* Cache consultation                                                  */
/* ================================================================== */

/* Copy a cached RRset into the answer accumulator. */
static int add_rrset(elpis_task_t *t, elpis_section_t sec,
                     const elpis_rrset_buf_t *b)
{
    unsigned i;
    for (i = 0; i < b->count; i++) {
        if (elpis_rrlist_add(&t->ans, sec, &b->name, b->type, b->klass, b->ttl,
                             b->data + b->off[i], b->len[i]) != ELPIS_OK)
            return ELPIS_ENOMEM;
    }
    /*
     * Signatures ride along whenever validation is on, not just when the
     * client asked: the validator needs them even if the client will never
     * see them.  They are stripped again in task_finish().
     */
    if (t->client_do || t->w->ctx->conf.dnssec) {
        for (i = 0; i < b->sigcount; i++) {
            if (elpis_rrlist_add(&t->ans, sec, &b->name, ELPIS_T_RRSIG, b->klass,
                                 b->ttl, b->data + b->off[b->count + i],
                                 b->len[b->count + i]) != ELPIS_OK)
                break;
        }
    }
    return ELPIS_OK;
}

/* Shim so add_rrset can call the rrlist API with a task. */
static int rrlist_add_t(elpis_task_t *t, elpis_section_t sec,
                        const elpis_name_t *n, uint16_t type, uint16_t klass,
                        uint32_t ttl, const uint8_t *rd, uint16_t rdlen)
{
    return elpis_rrlist_add(&t->ans, sec, n, type, klass, ttl, rd, rdlen);
}

/*
 * Reconstruct the authority section of a cached negative answer from the
 * packed (owner, SOA rdata) blob.
 */
static void add_negative_soa(elpis_task_t *t, const elpis_rrset_buf_t *b)
{
    const uint8_t *p;
    unsigned olen;
    elpis_name_t owner;
    size_t used;

    if (b->count == 0 || b->len[0] < 2)
        return;
    p = b->data + b->off[0];
    olen = p[0];
    if (1u + olen >= b->len[0])
        return;
    if (elpis_name_parse_nocomp(&owner, p + 1, olen, &used) != ELPIS_OK)
        return;
    rrlist_add_t(t, ELPIS_SEC_AUTHORITY, &owner, ELPIS_T_SOA, b->klass,
                 b->ttl, p + 1 + olen, (uint16_t)(b->len[0] - 1u - olen));
}

/*
 * Returns 1 when the caches could answer outright.  CNAME chains are followed
 * here too, so a fully cached chain costs no network traffic at all.
 */
static int cache_try(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_rrset_buf_t *b = w->rrbuf;
    uint32_t now = elpis_cached_now_s();
    unsigned guard = 0;

    for (;;) {
        if (++guard > ELPIS_MAX_CNAME_CHAIN)
            return 0;

        /* Exact type hit. */
        if (elpis_rcache_get(w->ctx->rcache, &t->qname, t->qtype, t->qclass,
                             now, c->serve_stale, b) == ELPIS_OK) {
            if (b->flags & (ELPIS_RRF_NXDOMAIN | ELPIS_RRF_NODATA)) {
                t->rcode = (b->flags & ELPIS_RRF_NXDOMAIN)
                         ? ELPIS_RC_NXDOMAIN : ELPIS_RC_NOERROR;
                add_negative_soa(t, b);
                t->sec = (elpis_sec_t)b->sec;
                t->from_cache = 1;
                return 1;
            }
            if (b->count > 0) {
                add_rrset(t, ELPIS_SEC_ANSWER, b);
                t->rcode = ELPIS_RC_NOERROR;
                t->sec = (elpis_sec_t)b->sec;
                t->from_cache = 1;
                /*
                 * RRsets are cached as they arrive, before the chain of trust
                 * has been walked, so their status is "unchecked".  Validate
                 * now; the result is written back so this only happens once
                 * per RRset rather than once per query.
                 */
                if (c->dnssec && b->sec == ELPIS_SEC_UNCHECKED)
                    t->revalidate = 1;
                return 1;
            }
        }

        /* A CNAME at this name redirects, unless CNAME is what was asked. */
        if (t->qtype != ELPIS_T_CNAME &&
            elpis_rcache_get(w->ctx->rcache, &t->qname, ELPIS_T_CNAME,
                             t->qclass, now, c->serve_stale, b) == ELPIS_OK &&
            b->count > 0 && !(b->flags & (ELPIS_RRF_NXDOMAIN | ELPIS_RRF_NODATA))) {
            elpis_name_t target;
            if (elpis_rdata_target(ELPIS_T_CNAME, b->data + b->off[0],
                                   b->len[0], &target) != ELPIS_OK)
                return 0;
            add_rrset(t, ELPIS_SEC_ANSWER, b);
            if (t->sec == ELPIS_SEC_UNCHECKED)
                t->sec = (elpis_sec_t)b->sec;
            else if ((elpis_sec_t)b->sec < t->sec)
                t->sec = (elpis_sec_t)b->sec;
            elpis_name_lower(&target);
            if (elpis_name_eq(&target, &t->qname))
                return 0;                  /* self-referential CNAME */
            t->qname = target;
            t->restarts++;
            if (t->restarts > ELPIS_MAX_CNAME_CHAIN)
                return 0;
            continue;
        }

        /* A cached NXDOMAIN above this name covers it too (RFC 8020). */
        if (c->harden_below_nxdomain) {
            elpis_name_t up = t->qname;
            unsigned lvl = 0;
            while (up.len > 1 && lvl < 8u) {
                if (elpis_name_parent(&up, &up) != 0)
                    break;
                lvl++;
                if (up.len <= 1)
                    break;
                if (elpis_rcache_get(w->ctx->rcache, &up, ELPIS_T_NXNAME,
                                     t->qclass, now, 0, b) == ELPIS_OK &&
                    (b->flags & ELPIS_RRF_NXDOMAIN)) {
                    t->rcode = ELPIS_RC_NXDOMAIN;
                    add_negative_soa(t, b);
                    t->sec = (elpis_sec_t)b->sec;
                    t->from_cache = 1;
                    return 1;
                }
            }
        }
        return 0;
    }
}

/* ================================================================== */
/* Server selection                                                    */
/* ================================================================== */

static int already_tried(const elpis_task_t *t, const elpis_addr_t *a)
{
    unsigned i;
    for (i = 0; i < t->ntried; i++)
        if (elpis_addr_eq_ip(&t->tried[i], a))
            return 1;
    return 0;
}

static void mark_tried(elpis_task_t *t, const elpis_addr_t *a)
{
    if (t->ntried < ELPIS_MAX_TRIED)
        t->tried[t->ntried++] = *a;
}

/*
 * Choose the cheapest untried address in the current delegation.  "Cheapest"
 * is the smoothed RTT plus a timeout penalty, so a server that just failed is
 * skipped without being forgotten.
 *
 * Servers we have never measured get a little random jitter added.  Without
 * it every unmeasured delegation resolves to the same nameserver -- whichever
 * the parent happened to list first -- so one slow server in a popular zone
 * would slow down every cold lookup in it, and the load would land on one
 * machine instead of spreading.
 */
#define UNKNOWN_JITTER_MS 64u
static int choose_server(elpis_task_t *t, elpis_addr_t *out)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    uint32_t best_cost = 0xFFFFFFFFu;
    int found = 0;
    unsigned i, j;
    elpis_addr_t best;

    memset(&best, 0, sizeof best);

    for (i = 0; i < t->deleg.nns; i++) {
        const elpis_nsrec_t *r = &t->deleg.ns[i];
        if (r->flags & ELPIS_NSF_LAME)
            continue;

        for (j = 0; j < r->n6 && c->do_ipv6; j++) {
            elpis_addr_t a;
            elpis_infra_info_t inf;
            uint32_t cost;
            elpis_addr_from6(&a, r->a6[j], r->port ? r->port : 53);
            if (already_tried(t, &a))
                continue;
            elpis_infra_get(w->ctx->infra, &a, &inf);
            cost = elpis_infra_cost(&inf);
            if (inf.queries == 0)
                cost += elpis_random_below(UNKNOWN_JITTER_MS);
            if (!c->prefer_ipv6)
                cost += 20;      /* mild bias: v4 paths are still more reliable */
            if (cost < best_cost) { best_cost = cost; best = a; found = 1; }
        }
        for (j = 0; j < r->n4 && c->do_ipv4; j++) {
            elpis_addr_t a;
            elpis_infra_info_t inf;
            uint32_t cost;
            elpis_addr_from4(&a, r->a4[j], r->port ? r->port : 53);
            if (already_tried(t, &a))
                continue;
            elpis_infra_get(w->ctx->infra, &a, &inf);
            cost = elpis_infra_cost(&inf);
            if (inf.queries == 0)
                cost += elpis_random_below(UNKNOWN_JITTER_MS);
            if (c->prefer_ipv6)
                cost += 20;
            if (cost < best_cost) { best_cost = cost; best = a; found = 1; }
        }
    }

    if (!found)
        return 0;
    /*
     * Everything left is banned (lame or repeatedly timed out).  Try it
     * anyway rather than give up: a ban is a heuristic, not a fact.
     */
    *out = best;
    return 1;
}

/* Pick a nameserver with no known address, for a child lookup. */
static elpis_nsrec_t *choose_nameless(elpis_task_t *t)
{
    unsigned i;
    for (i = 0; i < t->deleg.nns; i++) {
        elpis_nsrec_t *r = &t->deleg.ns[i];
        if (r->n4 == 0 && r->n6 == 0 && !(r->flags & ELPIS_NSF_NOADDR))
            return r;
    }
    return NULL;
}

/* ================================================================== */
/* Child tasks                                                         */
/* ================================================================== */

elpis_task_t *elpis_task_child(elpis_task_t *parent, const elpis_name_t *qname,
                               uint16_t qtype, elpis_task_done_fn cb, void *ctx)
{
    elpis_task_t *t;

    if (parent->depth + 1u >= ELPIS_MAX_DEPTH)
        return NULL;

    t = elpis_task_new(parent->w);
    if (t == NULL)
        return NULL;

    t->parent   = parent;
    t->depth    = parent->depth + 1u;
    t->qname    = *qname;
    elpis_name_lower(&t->qname);
    t->qtype    = qtype;
    t->qclass   = parent->qclass;
    t->done_cb  = cb;
    t->done_ctx = ctx;
    t->client_do = parent->client_do;

    t->sib_next = parent->children;
    if (parent->children != NULL)
        parent->children->sib_prev = t;
    parent->children = t;
    parent->nchild++;

    elpis_task_start(t);
    return t;
}

typedef struct {
    elpis_name_t ns;
} nsaddr_ctx_t;

static void nsaddr_done(elpis_task_t *child, void *ctxp)
{
    elpis_task_t *p = child->parent;
    elpis_name_t ns;
    unsigned i;
    int got = 0;

    (void)ctxp;
    if (p == NULL)
        return;

    ns = child->orig_qname;

    if (child->rcode == ELPIS_RC_NOERROR) {
        for (i = 0; i < child->ans.n; i++) {
            const elpis_trr_t *rr = &child->ans.rr[i];
            if (rr->section != (uint8_t)ELPIS_SEC_ANSWER)
                continue;
            if (rr->type == ELPIS_T_A && rr->rdlen == 4) {
                elpis_deleg_add_addr(&p->deleg, &ns, elpis_trr_rd(&child->ans, i),
                                     AF_INET, ELPIS_NSF_RESOLVED);
                got = 1;
            } else if (rr->type == ELPIS_T_AAAA && rr->rdlen == 16) {
                elpis_deleg_add_addr(&p->deleg, &ns, elpis_trr_rd(&child->ans, i),
                                     AF_INET6, ELPIS_NSF_RESOLVED);
                got = 1;
            }
        }
    }

    if (!got) {
        elpis_nsrec_t *r = elpis_deleg_find_ns(&p->deleg, &ns);
        if (r != NULL && r->n4 == 0 && r->n6 == 0)
            r->flags = (uint8_t)(r->flags | ELPIS_NSF_NOADDR);
    }

    if (p->nchild)
        p->nchild--;
    if (p->nchild == 0 && p->state == ELPIS_TS_NSADDR) {
        p->state = ELPIS_TS_SEND;
        elpis_task_step(p);
    }
}

/* ================================================================== */
/* Response handling                                                   */
/* ================================================================== */

typedef enum {
    RESP_ANSWER, RESP_CNAME, RESP_DNAME, RESP_REFERRAL, RESP_NODATA,
    RESP_NXDOMAIN, RESP_UNUSABLE, RESP_LAME
} resp_kind_t;

/* Harvest a referral: NS records in the authority section plus their glue. */
static int absorb_referral(elpis_task_t *t, const elpis_msg_t *m,
                           const elpis_name_t *zone, elpis_name_t *newzone)
{
    elpis_rr_iter_t it;
    elpis_rr_t rr;
    int drop = 0;
    int have = 0;
    elpis_deleg_t nd;
    uint32_t ttl = 0xFFFFFFFFu;

    memset(&nd, 0, sizeof nd);

    elpis_rr_iter(&it, m, ELPIS_SEC_AUTHORITY);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        elpis_name_t target;
        uint8_t rd[ELPIS_MAX_NAME + 8];
        size_t rdlen;

        if (rr.type != ELPIS_T_NS || rr.klass != t->qclass)
            continue;
        /* The delegation must come from inside the zone we asked. */
        if (!in_bailiwick(&rr.name, zone))
            continue;
        /* And it must be strictly below it, or it is not a referral at all. */
        if (elpis_name_eq(&rr.name, zone))
            continue;
        if (elpis_rdata_canonical(ELPIS_T_NS, m->wire, m->len, rr.rdoff,
                                  rr.rdlen, rd, sizeof rd, &rdlen, 1) != ELPIS_OK)
            continue;
        if (elpis_rdata_target(ELPIS_T_NS, rd, rdlen, &target) != ELPIS_OK)
            continue;

        if (!have) {
            nd.zone = rr.name;
            elpis_name_lower(&nd.zone);
            have = 1;
        } else if (!elpis_name_eq(&nd.zone, &rr.name)) {
            continue;              /* one zone cut per referral */
        }
        elpis_name_lower(&target);
        elpis_deleg_add_ns(&nd, &target);
        if (rr.ttl < ttl)
            ttl = rr.ttl;
    }

    if (!have || nd.nns == 0)
        return 0;

    /* Glue, accepted only for names inside the child zone. */
    elpis_rr_iter(&it, m, ELPIS_SEC_ADDITIONAL);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        uint8_t ip[16];
        if (rr.klass != t->qclass)
            continue;
        if (rr.type == ELPIS_T_A && rr.rdlen == 4) {
            memcpy(ip, m->wire + rr.rdoff, 4);
            if (elpis_deleg_find_ns(&nd, &rr.name) != NULL)
                elpis_deleg_add_addr(&nd, &rr.name, ip, AF_INET, ELPIS_NSF_GLUE);
        } else if (rr.type == ELPIS_T_AAAA && rr.rdlen == 16) {
            memcpy(ip, m->wire + rr.rdoff, 16);
            if (elpis_deleg_find_ns(&nd, &rr.name) != NULL)
                elpis_deleg_add_addr(&nd, &rr.name, ip, AF_INET6, ELPIS_NSF_GLUE);
        }
    }

    if (ttl == 0xFFFFFFFFu)
        ttl = 3600;
    nd.ttl = elpis_clamp_ttl(&t->w->ctx->conf, ttl);
    nd.sec = ELPIS_SEC_UNCHECKED;

    /* Cache it, pinning the root's own children (the TLDs). */
    {
        int pin = (nd.zone.labels == 1);
        if (elpis_deleg_addr_count(&nd) > 0)
            elpis_dcache_put(t->w->ctx->dcache, &nd, nd.ttl, pin);
    }

    t->deleg = nd;
    t->have_deleg = 1;
    t->ntried = 0;
    *newzone = nd.zone;
    return 1;
}

/* Copy a record out of a message into the task's accumulator. */
/*
 * Copy a record out of a message, in DNSSEC canonical form.
 *
 * The case folding matters more than it looks.  We randomise the case of the
 * question name (RFC 5452 "0x20"), and an authority is free to compress names
 * in its rdata against that question -- so a decompressed NS target can come
 * back as "a.gtld-servers.Net." purely because of our own randomisation.  The
 * signer signed the lowercase form, so anything that reaches the validator or
 * the cache has to be folded exactly as RFC 4034 section 6.2 specifies.
 */
static int accept_rr(elpis_task_t *t, elpis_section_t sec,
                     const elpis_msg_t *m, const elpis_rr_t *rr)
{
    uint8_t *rd = t->w->rd1;
    size_t rdlen;
    int drop = 0;

    if (elpis_rdata_validate(rr->type, m->wire, m->len, rr->rdoff, rr->rdlen,
                             &drop) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (elpis_rdata_canonical(rr->type, m->wire, m->len, rr->rdoff, rr->rdlen,
                              rd, ELPIS_MAX_MSG, &rdlen, 1) != ELPIS_OK)
        return ELPIS_EFORMAT;
    if (rdlen > 0xFFFFu)
        return ELPIS_EFORMAT;
    if (elpis_rrlist_has(&t->ans, &rr->name, rr->type, rd, (uint16_t)rdlen))
        return ELPIS_OK;
    return elpis_rrlist_add(&t->ans, sec, &rr->name, rr->type, rr->klass,
                            elpis_clamp_ttl(&t->w->ctx->conf, rr->ttl),
                            rd, (uint16_t)rdlen);
}

/* Cache each RRset we just learned, grouped by (owner, type). */
static void cache_message_rrsets(elpis_task_t *t, const elpis_msg_t *m,
                                 const elpis_name_t *zone, elpis_section_t sec)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_rr_iter_t it, it2;
    elpis_rr_t rr, rr2;
    int drop = 0;
    unsigned done[64];
    unsigned ndone = 0;
    unsigned idx = 0;

    elpis_rr_iter(&it, m, sec);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        elpis_rrset_buf_t *b = w->rrbuf;
        unsigned i;
        int seen = 0;
        uint32_t ttl;

        idx++;
        for (i = 0; i < ndone; i++)
            if (done[i] == idx) { seen = 1; break; }
        if (seen)
            continue;
        if (rr.type == ELPIS_T_RRSIG || rr.type == ELPIS_T_OPT)
            continue;
        if (rr.klass != t->qclass)
            continue;
        if (!in_bailiwick(&rr.name, zone))
            continue;
        if (elpis_type_is_meta(rr.type))
            continue;

        ttl = elpis_clamp_ttl(c, rr.ttl);
        elpis_rrset_buf_init(b, &rr.name, rr.type, rr.klass, ttl);
        b->sec   = (uint8_t)t->sec;
        b->flags = ELPIS_RRF_AUTH;

        /*
         * Gather the RRset, then its signatures, in two passes.  The records
         * arrive in whatever order the authority chose, and the buffer keeps
         * data ahead of signatures -- a single interleaved pass would silently
         * drop every data record that followed the first RRSIG.
         */
        {
            unsigned pass;
            unsigned j = 0;
            uint8_t *rd = w->rd2;
            size_t rdlen;

            for (pass = 0; pass < 2; pass++) {
                j = 0;
                elpis_rr_iter(&it2, m, sec);
                while (elpis_rr_next(&it2, &rr2, &drop) == ELPIS_OK) {
                    j++;
                    if (rr2.klass != rr.klass)
                        continue;
                    if (!elpis_name_eq(&rr2.name, &rr.name))
                        continue;

                    if (pass == 0) {
                        if (rr2.type != rr.type)
                            continue;
                        if (elpis_rdata_canonical(rr2.type, m->wire, m->len,
                                                  rr2.rdoff, rr2.rdlen, rd,
                                                  ELPIS_MAX_MSG, &rdlen, 1) != ELPIS_OK)
                            continue;
                        if (rdlen <= 0xFFFFu)
                            elpis_rrset_buf_add(b, rd, (uint16_t)rdlen);
                        if (ndone < ELPIS_ARRAY_LEN(done))
                            done[ndone++] = j;
                        if (rr2.ttl < b->ttl)
                            b->ttl = elpis_clamp_ttl(c, rr2.ttl);
                    } else {
                        if (rr2.type != ELPIS_T_RRSIG || rr2.rdlen <= 18)
                            continue;
                        if (elpis_get16(m->wire + rr2.rdoff) != rr.type)
                            continue;
                        if (elpis_rdata_canonical(rr2.type, m->wire, m->len,
                                                  rr2.rdoff, rr2.rdlen, rd,
                                                  ELPIS_MAX_MSG, &rdlen, 1) != ELPIS_OK)
                            continue;
                        if (rdlen <= 0xFFFFu)
                            elpis_rrset_buf_add_sig(b, rd, (uint16_t)rdlen);
                    }
                }
            }
        }

        if (b->count > 0)
            elpis_rcache_put_buf(w->ctx->rcache, b, c->serve_stale, 0);
    }
}

/* Find the SOA that proves a negative answer and cache the marker. */
static void cache_negative(elpis_task_t *t, const elpis_msg_t *m, int nxdomain)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_rr_iter_t it;
    elpis_rr_t rr;
    int drop = 0;

    elpis_rr_iter(&it, m, ELPIS_SEC_AUTHORITY);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        uint8_t rd[ELPIS_MAX_NAME * 2 + 64];
        uint8_t blob[ELPIS_MAX_NAME * 3 + 96];
        size_t rdlen;
        uint32_t minimum, ttl;
        elpis_rrset_buf_t *b = w->rrbuf;
        const uint8_t *rdp;
        uint16_t rdl;

        if (rr.type != ELPIS_T_SOA || rr.klass != t->qclass)
            continue;
        if (!elpis_name_is_subdomain(&t->qname, &rr.name))
            continue;
        if (elpis_rdata_canonical(ELPIS_T_SOA, m->wire, m->len, rr.rdoff,
                                  rr.rdlen, rd, sizeof rd, &rdlen, 1) != ELPIS_OK)
            continue;
        if (rdlen < 20)
            continue;

        /* RFC 2308: negative TTL is min(SOA TTL, SOA MINIMUM). */
        minimum = elpis_get32(rd + rdlen - 4);
        ttl = rr.ttl < minimum ? rr.ttl : minimum;
        ttl = elpis_clamp_neg_ttl(c, ttl);
        if (ttl == 0)
            return;

        if (1u + rr.name.len + rdlen > sizeof blob)
            return;
        blob[0] = rr.name.len;
        memcpy(blob + 1, rr.name.d, rr.name.len);
        memcpy(blob + 1 + rr.name.len, rd, rdlen);
        rdp = blob;
        rdl = (uint16_t)(1u + rr.name.len + rdlen);

        elpis_rrset_buf_init(b, &t->qname,
                             nxdomain ? (uint16_t)ELPIS_T_NXNAME : t->qtype,
                             t->qclass, ttl);
        b->sec   = (uint8_t)t->sec;
        b->flags = nxdomain ? ELPIS_RRF_NXDOMAIN : ELPIS_RRF_NODATA;
        elpis_rrset_buf_add(b, rdp, rdl);
        elpis_rcache_put_buf(w->ctx->rcache, b, c->serve_stale, 0);

        /* Carry the SOA into the reply so the client sees the proof. */
        rrlist_add_t(t, ELPIS_SEC_AUTHORITY, &rr.name, ELPIS_T_SOA,
                     rr.klass, ttl, rd, (uint16_t)rdlen);
        return;
    }
}

static resp_kind_t classify(elpis_task_t *t, const elpis_msg_t *m,
                            const elpis_name_t *zone)
{
    elpis_rr_iter_t it;
    elpis_rr_t rr;
    int drop = 0;
    int saw_answer = 0, saw_cname = 0, saw_ns = 0, saw_soa = 0;
    unsigned rcode = elpis_msg_rcode(m);

    elpis_rr_iter(&it, m, ELPIS_SEC_ANSWER);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        if (rr.klass != t->qclass)
            continue;
        if (!in_bailiwick(&rr.name, zone))
            continue;
        if (!elpis_name_eq(&rr.name, &t->qname))
            continue;
        if (rr.type == t->qtype)
            saw_answer = 1;
        else if (rr.type == ELPIS_T_CNAME && t->qtype != ELPIS_T_CNAME)
            saw_cname = 1;
    }

    /*
     * A DNAME whose owner is a proper ancestor of the question rewrites the
     * whole subtree (RFC 6672).  It is checked before anything else because a
     * conforming server sends the DNAME and the synthesised CNAME together,
     * and we want to follow the DNAME rather than trust the CNAME.
     */
    elpis_rr_iter(&it, m, ELPIS_SEC_ANSWER);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        if (rr.klass != t->qclass || rr.type != ELPIS_T_DNAME)
            continue;
        if (!in_bailiwick(&rr.name, zone))
            continue;
        if (elpis_name_eq(&rr.name, &t->qname))
            continue;                   /* a DNAME does not cover its owner */
        if (elpis_name_is_subdomain(&t->qname, &rr.name))
            return RESP_DNAME;
    }

    elpis_rr_iter(&it, m, ELPIS_SEC_AUTHORITY);
    while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
        if (rr.klass != t->qclass)
            continue;
        if (rr.type == ELPIS_T_SOA)
            saw_soa = 1;
        else if (rr.type == ELPIS_T_NS && in_bailiwick(&rr.name, zone) &&
                 !elpis_name_eq(&rr.name, zone))
            saw_ns = 1;
    }

    if (rcode == ELPIS_RC_NXDOMAIN)
        return saw_cname ? RESP_CNAME : RESP_NXDOMAIN;
    if (saw_answer)
        return RESP_ANSWER;
    /*
     * Some parents answer a DS query with a referral to the child instead of
     * an authoritative "no such DS".  Descending would send the query to the
     * one zone that cannot answer it, so take it as NODATA and let the
     * validator treat the delegation as unsigned.
     */
    if (t->qtype == ELPIS_T_DS && saw_ns && !saw_cname) {
        elpis_rr_iter_t it2;
        elpis_rr_t rr2;
        int d2 = 0;
        elpis_rr_iter(&it2, m, ELPIS_SEC_AUTHORITY);
        while (elpis_rr_next(&it2, &rr2, &d2) == ELPIS_OK) {
            if (rr2.type == ELPIS_T_NS && elpis_name_eq(&rr2.name, &t->qname))
                return RESP_NODATA;
        }
    }
    if (saw_cname)
        return RESP_CNAME;
    if (saw_ns && !(m->hdr.flags & ELPIS_FLAG_AA))
        return RESP_REFERRAL;
    if (saw_ns && !saw_soa)
        return RESP_REFERRAL;
    if (saw_soa)
        return RESP_NODATA;
    if (m->hdr.flags & ELPIS_FLAG_AA)
        return RESP_NODATA;
    return RESP_UNUSABLE;
}

static void next_server(elpis_task_t *t, int ede)
{
    if (t->ede < 0)
        t->ede = ede;
    t->state = ELPIS_TS_SEND;
    elpis_task_step(t);
}

void elpis_resolver_on_response(elpis_task_t *t, elpis_outq_t *q,
                                const elpis_msg_t *m)
{
    elpis_worker_t *w = t->w;
    elpis_name_t zone;
    unsigned rcode = elpis_msg_rcode(m);
    resp_kind_t kind;

    if (t->state == ELPIS_TS_DEAD)
        return;

    zone = t->have_deleg ? t->deleg.zone : elpis_name_root;

    switch (rcode) {
    case ELPIS_RC_NOERROR:
    case ELPIS_RC_NXDOMAIN:
        break;
    case ELPIS_RC_REFUSED:
        /* The server does not serve this zone: it is lame for us. */
        elpis_infra_set_flag(w->ctx->infra, &q->server, ELPIS_INF_LAME, 1);
        next_server(t, ELPIS_EDE_NOT_AUTHORITATIVE);
        return;
    case ELPIS_RC_SERVFAIL:
        next_server(t, ELPIS_EDE_NETWORK_ERROR);
        return;
    case ELPIS_RC_FORMERR:
    case ELPIS_RC_NOTIMP:
        next_server(t, ELPIS_EDE_NOT_SUPPORTED);
        return;
    default:
        next_server(t, ELPIS_EDE_OTHER);
        return;
    }

    /*
     * A QNAME-minimisation probe only ever asks about an ancestor name.  Any
     * outcome other than a referral means we have gone as deep as this zone
     * goes, so drop the minimisation and ask the real question here.
     */
    if (t->qmin_probe) {
        elpis_name_t saved_zone = zone;
        int descended = 0;

        if (rcode == ELPIS_RC_NOERROR)
            descended = absorb_referral(t, m, &saved_zone, &zone);

        t->qmin_probe = 0;
        /*
         * t->qname and t->qtype were already restored when the probe was
         * sent -- the shortened name only ever existed inside out_send().
         * Resetting them to orig_qname here would throw away a CNAME target
         * mid-chase and send the resolution back to the start.
         */

        if (rcode == ELPIS_RC_NXDOMAIN) {
            /*
             * RFC 8020: no name below a non-existent name exists.  In strict
             * mode that is the answer; otherwise fall back to the full name,
             * because some authoritative servers answer NXDOMAIN for empty
             * non-terminals.
             */
            if (w->ctx->conf.qname_min_strict) {
                t->rcode = ELPIS_RC_NXDOMAIN;
                cache_negative(t, m, 1);
                t->state = ELPIS_TS_VALIDATE;
                elpis_task_step(t);
                return;
            }
            t->qmin_active = 0;
        } else if (!descended) {
            t->qmin_active = 0;
        } else {
            t->referrals++;
            t->qmin_labels++;
        }
        t->ntried = 0;
        t->state = ELPIS_TS_SEND;
        elpis_task_step(t);
        return;
    }

    kind = classify(t, m, &zone);

    /*
     * A forwarder is doing the recursion, so it never sends us a referral and
     * its answers are not authoritative.  Take what it gives us.
     */
    if (t->forwarding && kind == RESP_REFERRAL)
        kind = RESP_NODATA;

    switch (kind) {
    case RESP_REFERRAL: {
        elpis_name_t newzone;
        if (++t->referrals > w->ctx->conf.max_referrals) {
            elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_OTHER);
            return;
        }
        if (!absorb_referral(t, m, &zone, &newzone)) {
            next_server(t, ELPIS_EDE_NOT_AUTHORITATIVE);
            return;
        }
        /* A referral that does not descend is a loop. */
        if (!elpis_name_is_subdomain(&newzone, &zone) ||
            elpis_name_eq(&newzone, &zone)) {
            next_server(t, ELPIS_EDE_NOT_AUTHORITATIVE);
            return;
        }
        t->state = ELPIS_TS_SEND;
        elpis_task_step(t);
        return;
    }

    case RESP_DNAME: {
        elpis_rr_iter_t it;
        elpis_rr_t rr;
        int drop = 0;
        elpis_name_t target, newname;
        int done = 0;

        elpis_rr_iter(&it, m, ELPIS_SEC_ANSWER);
        while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
            uint8_t rd[ELPIS_MAX_NAME + 8];
            size_t rdlen;

            if (rr.klass != t->qclass || rr.type != ELPIS_T_DNAME)
                continue;
            if (!in_bailiwick(&rr.name, &zone) ||
                !elpis_name_is_subdomain(&t->qname, &rr.name) ||
                elpis_name_eq(&rr.name, &t->qname))
                continue;
            if (elpis_rdata_canonical(ELPIS_T_DNAME, m->wire, m->len, rr.rdoff,
                                      rr.rdlen, rd, sizeof rd, &rdlen, 1) != ELPIS_OK)
                continue;
            if (elpis_rdata_target(ELPIS_T_DNAME, rd, rdlen, &target) != ELPIS_OK)
                continue;
            /*
             * RFC 6672 section 2.2: a substitution that would exceed 255
             * octets is answered YXDOMAIN, not silently truncated.
             */
            if (elpis_name_substitute(&t->qname, &rr.name, &target,
                                      &newname) != ELPIS_OK) {
                elpis_task_fail(t, ELPIS_RC_YXDOMAIN, ELPIS_EDE_OTHER);
                return;
            }
            accept_rr(t, ELPIS_SEC_ANSWER, m, &rr);

            /*
             * RFC 6672 section 3.4.1: include the CNAME the DNAME implies.
             * Clients that predate DNAME only understand the CNAME, and it
             * costs one record to keep them working.  It is synthesised here
             * rather than copied from the response so its correctness does
             * not depend on the server having sent one.
             */
            {
                uint8_t cn[ELPIS_MAX_NAME];
                memcpy(cn, newname.d, newname.len);
                elpis_rrlist_add(&t->ans, ELPIS_SEC_ANSWER, &t->qname,
                                 ELPIS_T_CNAME, t->qclass,
                                 elpis_clamp_ttl(&w->ctx->conf, rr.ttl),
                                 cn, newname.len);
            }
            done = 1;
            break;
        }
        if (!done) {
            next_server(t, ELPIS_EDE_OTHER);
            return;
        }

        cache_message_rrsets(t, m, &zone, ELPIS_SEC_ANSWER);

        elpis_name_lower(&newname);
        if (elpis_name_eq(&newname, &t->qname) ||
            ++t->restarts > ELPIS_MAX_CNAME_CHAIN) {
            elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_OTHER);
            return;
        }
        t->qname       = newname;
        t->have_deleg  = 0;
        t->ntried      = 0;
        t->referrals   = 0;
        t->qmin_active = w->ctx->conf.qname_minimisation ? 1u : 0u;
        t->qmin_labels = 0;
        t->state       = ELPIS_TS_LOOKUP;
        elpis_task_step(t);
        return;
    }

    case RESP_CNAME: {
        elpis_rr_iter_t it;
        elpis_rr_t rr;
        int drop = 0;
        elpis_name_t target;
        int found = 0;

        elpis_rr_iter(&it, m, ELPIS_SEC_ANSWER);
        while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
            if (rr.klass != t->qclass || !in_bailiwick(&rr.name, &zone))
                continue;
            if (rr.type == ELPIS_T_CNAME && elpis_name_eq(&rr.name, &t->qname)) {
                uint8_t rd[ELPIS_MAX_NAME + 8];
                size_t rdlen;
                if (elpis_rdata_canonical(ELPIS_T_CNAME, m->wire, m->len,
                                          rr.rdoff, rr.rdlen, rd, sizeof rd,
                                          &rdlen, 1) != ELPIS_OK)
                    continue;
                if (elpis_rdata_target(ELPIS_T_CNAME, rd, rdlen, &target) != ELPIS_OK)
                    continue;
                accept_rr(t, ELPIS_SEC_ANSWER, m, &rr);
                found = 1;
                break;
            }
        }
        if (!found) {
            next_server(t, ELPIS_EDE_OTHER);
            return;
        }

        /* Also keep any records already present for the target. */
        elpis_rr_iter(&it, m, ELPIS_SEC_ANSWER);
        while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
            if (rr.klass == t->qclass && in_bailiwick(&rr.name, &zone) &&
                rr.type != ELPIS_T_CNAME)
                accept_rr(t, ELPIS_SEC_ANSWER, m, &rr);
        }
        cache_message_rrsets(t, m, &zone, ELPIS_SEC_ANSWER);

        if (rcode == ELPIS_RC_NXDOMAIN) {
            t->rcode = ELPIS_RC_NXDOMAIN;
            t->state = ELPIS_TS_VALIDATE;
            elpis_task_step(t);
            return;
        }

        elpis_name_lower(&target);
        if (elpis_name_eq(&target, &t->qname) ||
            ++t->restarts > ELPIS_MAX_CNAME_CHAIN) {
            elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_OTHER);
            return;
        }
        t->qname = target;
        t->have_deleg = 0;
        t->ntried = 0;
        t->referrals = 0;
        t->qmin_active = w->ctx->conf.qname_minimisation ? 1u : 0u;
        t->qmin_labels = 0;
        t->state = ELPIS_TS_LOOKUP;
        elpis_task_step(t);
        return;
    }

    case RESP_ANSWER: {
        elpis_rr_iter_t it;
        elpis_rr_t rr;
        int drop = 0;

        elpis_rr_iter(&it, m, ELPIS_SEC_ANSWER);
        while (elpis_rr_next(&it, &rr, &drop) == ELPIS_OK) {
            if (rr.klass != t->qclass || !in_bailiwick(&rr.name, &zone))
                continue;
            if (rr.type == ELPIS_T_RRSIG && !t->client_do && !w->ctx->conf.dnssec)
                continue;
            accept_rr(t, ELPIS_SEC_ANSWER, m, &rr);
        }
        cache_message_rrsets(t, m, &zone, ELPIS_SEC_ANSWER);
        t->aa = (m->hdr.flags & ELPIS_FLAG_AA) ? 1u : 0u;
        t->rcode = ELPIS_RC_NOERROR;
        t->state = ELPIS_TS_VALIDATE;
        elpis_task_step(t);
        return;
    }

    case RESP_NXDOMAIN:
        t->rcode = ELPIS_RC_NXDOMAIN;
        cache_negative(t, m, 1);
        cache_message_rrsets(t, m, &zone, ELPIS_SEC_AUTHORITY);
        t->state = ELPIS_TS_VALIDATE;
        elpis_task_step(t);
        return;

    case RESP_NODATA:
        t->rcode = ELPIS_RC_NOERROR;
        cache_negative(t, m, 0);
        cache_message_rrsets(t, m, &zone, ELPIS_SEC_AUTHORITY);
        t->state = ELPIS_TS_VALIDATE;
        elpis_task_step(t);
        return;

    case RESP_LAME:
        elpis_infra_set_flag(w->ctx->infra, &q->server, ELPIS_INF_LAME, 1);
        next_server(t, ELPIS_EDE_NOT_AUTHORITATIVE);
        return;

    case RESP_UNUSABLE:
    default:
        next_server(t, ELPIS_EDE_OTHER);
        return;
    }
}

void elpis_resolver_on_timeout(elpis_task_t *t, elpis_outq_t *q)
{
    (void)q;
    if (t->state == ELPIS_TS_DEAD)
        return;
    next_server(t, ELPIS_EDE_NO_REACHABLE_AUTH);
}

void elpis_resolver_on_error(elpis_task_t *t, elpis_outq_t *q, int ede)
{
    (void)q;
    if (t->state == ELPIS_TS_DEAD)
        return;
    next_server(t, ede);
}

/* ================================================================== */
/* The step function                                                   */
/* ================================================================== */

void elpis_task_step(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    unsigned guard = 0;

    while (++guard < 64) {
        switch (t->state) {

        case ELPIS_TS_LOOKUP:
            if (t->depth == 0 && elpis_localzone_answer(t)) {
                t->state = ELPIS_TS_FINISH;
                continue;
            }
            /*
             * A refresh must not answer itself from the cache it was sent to
             * refresh.  Without this the RRset cache hands back the same
             * expired data, the message-cache entry is never replaced, and the
             * name is served stale for as long as anyone keeps asking for it.
             */
            if (!t->prefetch && cache_try(t)) {
                t->state = t->revalidate ? ELPIS_TS_VALIDATE : ELPIS_TS_FINISH;
                continue;
            }
            t->have_deleg = 0;
            t->state = ELPIS_TS_DELEG;
            continue;

        case ELPIS_TS_DELEG: {
            elpis_name_t start = t->qname;

            /*
             * A DS record lives in the parent zone, never in the child.
             * Looking up the delegation for the name itself would send the
             * query to the very servers that do not have it, and they answer
             * NODATA -- which a validator would read as "insecure".
             */
            if (t->qtype == ELPIS_T_DS && t->qname.len > 1)
                (void)elpis_name_parent(&t->qname, &start);

            t->forwarding = 0;
            {
                const elpis_zoneroute_t *r = route_lookup(c, &start);
                if (r != NULL && route_to_deleg(r, &t->deleg)) {
                    t->forwarding = r->is_stub ? 0u : 1u;
                    t->have_deleg = 1;
                    t->ntried = 0;
                    t->qmin_active = 0;   /* never minimise to a forwarder */
                    t->qmin_labels = t->deleg.zone.labels;
                    t->state = ELPIS_TS_SEND;
                    continue;
                }
            }

            if (elpis_dcache_closest(w->ctx->dcache, &start,
                                     elpis_cached_now_s(), &t->deleg) != ELPIS_OK) {
                t->deleg = w->ctx->root_hints;
            }
            t->have_deleg = 1;
            t->ntried = 0;
            /*
             * Start minimising from the delegation we already have rather
             * than from the root: with a warm TLD cache that usually means a
             * single extra probe, not one per label.
             */
            if (c->qname_minimisation && t->qname.labels > t->deleg.zone.labels + 1u)
                t->qmin_active = 1;
            else
                t->qmin_active = 0;
            t->qmin_labels = t->deleg.zone.labels;
            t->state = ELPIS_TS_SEND;
            continue;
        }

        case ELPIS_TS_SEND: {
            elpis_addr_t server;
            elpis_name_t probe;

            if (elpis_cached_now_ms() - t->start_ms > c->query_total_ms) {
                elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_NO_REACHABLE_AUTH);
                return;
            }
            if (!t->have_deleg) {
                t->state = ELPIS_TS_DELEG;
                continue;
            }
            if (!choose_server(t, &server)) {
                if (choose_nameless(t) != NULL) {
                    t->state = ELPIS_TS_NSADDR;
                    continue;
                }
                elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_NO_REACHABLE_AUTH);
                return;
            }
            mark_tried(t, &server);

            /* Decide what question to actually put on the wire. */
            t->qmin_probe = 0;
            if (t->qmin_active && t->qmin_labels < t->qname.labels) {
                unsigned keep = t->qmin_labels + 1u;
                if (keep < t->qname.labels &&
                    elpis_name_suffix(&t->qname, keep, &probe) == 0) {
                    elpis_name_t real = t->qname;
                    uint16_t realtype = t->qtype;
                    t->qname = probe;
                    /*
                     * RFC 9156 allows any type for the probe; A is the least
                     * likely to upset a non-conforming authority.
                     */
                    t->qtype = ELPIS_T_A;
                    t->qmin_probe = 1;
                    t->sends++;
                    if (elpis_out_send(t, &server, 0) != ELPIS_OK) {
                        t->qname = real;
                        t->qtype = realtype;
                        t->qmin_probe = 0;
                        continue;
                    }
                    t->qname = real;
                    t->qtype = realtype;
                    t->state = ELPIS_TS_WAIT;
                    return;
                }
                t->qmin_active = 0;
            }

            t->sends++;
            if (elpis_out_send(t, &server, 0) != ELPIS_OK)
                continue;               /* try the next server */
            t->state = ELPIS_TS_WAIT;
            return;
        }

        case ELPIS_TS_NSADDR: {
            elpis_nsrec_t *r = choose_nameless(t);
            elpis_name_t ns;
            int launched = 0;

            if (r == NULL) {
                t->state = ELPIS_TS_SEND;
                continue;
            }
            ns = r->name;
            /* Mark it now so we do not pick the same one again this pass. */
            r->flags = (uint8_t)(r->flags | ELPIS_NSF_NOADDR);

            if (c->do_ipv4 &&
                elpis_task_child(t, &ns, ELPIS_T_A, nsaddr_done, NULL) != NULL)
                launched++;
            if (c->do_ipv6 &&
                elpis_task_child(t, &ns, ELPIS_T_AAAA, nsaddr_done, NULL) != NULL)
                launched++;

            if (launched == 0) {
                t->state = ELPIS_TS_SEND;
                continue;
            }
            return;                     /* resumed from nsaddr_done() */
        }

        case ELPIS_TS_VALIDATE:
            if (elpis_val_start(t) != 0)
                return;                 /* validator needs more data */
            t->state = ELPIS_TS_FINISH;
            continue;

        case ELPIS_TS_FINISH:
            task_finish(t);
            return;

        case ELPIS_TS_WAIT:
        case ELPIS_TS_DEAD:
        case ELPIS_TS_INIT:
        default:
            return;
        }
    }

    elpis_task_fail(t, ELPIS_RC_SERVFAIL, ELPIS_EDE_OTHER);
}

/* ================================================================== */
/* Completion                                                          */
/* ================================================================== */

static void task_finish(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;

    if (t->state == ELPIS_TS_DEAD)
        return;
    t->state = ELPIS_TS_DEAD;

    elpis_out_cancel(t);
    elpis_timer_del(w->loop, &t->deadline);

    /*
     * RFC 4035 section 5.5: data that fails validation must not be handed to
     * the client at all.  SERVFAIL plus an extended error is the only honest
     * answer -- returning the records with AD clear would let a downstream
     * cache keep forged data.
     */
    if ((t->sec == ELPIS_SEC_BOGUS || t->val_unavailable) &&
        w->ctx->conf.dnssec && !w->ctx->conf.dnssec_permissive &&
        !t->client_cd) {
        char nb[ELPIS_MAX_NAME * 4];
        int forged = (t->sec == ELPIS_SEC_BOGUS);
        uint8_t alg = 0;
        unsigned k;

        /* Naming the algorithm turns "bogus" into something actionable. */
        for (k = 0; k < t->ans.n; k++)
            if (t->ans.rr[k].type == ELPIS_T_RRSIG && t->ans.rr[k].rdlen > 2) {
                alg = elpis_trr_rd(&t->ans, k)[2];
                break;
            }
        elpis_logf_rl(ELPIS_LOG_WARN, ELPIS_DROP__MAX - 1, __FILE__, __LINE__,
                      "dnssec: %s for %s %s (alg %s); replying SERVFAIL",
                      forged ? "bogus answer"
                             : "could not fetch validation material",
                      elpis_name_str(&t->orig_qname, nb, sizeof nb),
                      elpis_type_name(t->orig_qtype),
                      alg ? elpis_alg_name(alg) : "none");
        elpis_rrlist_clear(&t->ans);
        t->rcode = ELPIS_RC_SERVFAIL;
        if (t->ede < 0)
            t->ede = ELPIS_EDE_DNSSEC_BOGUS;
    }

    /*
     * Only data we actually trust goes into the message cache -- including
     * answers assembled from the RRset cache.  Skipping those would leave a
     * name whose prebuilt response has expired permanently on the slow path,
     * reassembling the same records on every query.
     */
    if (t->rcode == ELPIS_RC_NOERROR && t->sec != ELPIS_SEC_BOGUS)
        cache_store_answer(t);

    /*
     * Completion callbacks run for parent-less tasks too: priming and cache
     * warming use them without having anything to wake up.
     */
    {
        elpis_task_done_fn cb = t->done_cb;
        t->done_cb = NULL;              /* never run twice */
        if (cb != NULL)
            cb(t, t->done_ctx);
    }

    /*
     * The callback may have driven the parent to completion, which detaches
     * this task; either way a task with a parent has no client to answer.
     */
    if (t->parent != NULL || !t->has_client) {
        elpis_task_free(t);
        return;
    }

    /*
     * RRSIGs are requested from upstream whenever validation is on, but a
     * client that did not set DO never asked for them and some stub resolvers
     * choke on the extra records.
     */
    if ((t->has_client || t->prefetch) && !t->client_do && t->ans.n > 0) {
        unsigned i, out = 0;
        for (i = 0; i < t->ans.n; i++) {
            uint16_t ty = t->ans.rr[i].type;
            if (ty == ELPIS_T_RRSIG || ty == ELPIS_T_NSEC || ty == ELPIS_T_NSEC3)
                continue;
            t->ans.rr[out++] = t->ans.rr[i];
        }
        t->ans.n = out;
    }

    /*
     * DNS64 needs an extra A lookup, which means suspending here and coming
     * back once the child finishes.  Everything above has already run, so the
     * second pass only adds the synthesised records.
     */
    if (w->ctx->conf.dns64 && t->has_client && elpis_dns64_needed(t)) {
        t->state = ELPIS_TS_WAIT;
        if (elpis_dns64_start(t) == ELPIS_OK)
            return;
        t->state = ELPIS_TS_DEAD;
    }

    if (w->ctx->conf.dns64)
        elpis_dns64_apply(t);

    elpis_task_respond(t);
    elpis_task_free(t);
}

/*
 * Build the response once and hand the bytes to the message cache, so a
 * repeat of this exact question becomes a header write plus one memcpy.
 */
static void cache_store_answer(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_bld_t b;
    elpis_mkey_t k;
    uint8_t folded[ELPIS_MAX_NAME];
    size_t qend, ns_off, ar_off;
    unsigned i;
    uint32_t ttl;

    /* Background refreshes must land in the cache too; that is their job. */
    if (!t->has_client && !t->prefetch && t->parent == NULL)
        return;
    if (t->ans.n == 0 && t->rcode == ELPIS_RC_NOERROR)
        return;

    ttl = elpis_rrlist_min_ttl(&t->ans, 0);
    if (ttl == 0)
        return;

    elpis_bld_init(&b, w->txbuf, ELPIS_MAX_MSG, w->ctab, 1);
    elpis_bld_track_ttl(&b, w->ttl_off, w->ttl_val, 4096);
    if (elpis_bld_header(&b, 0, (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA)) != ELPIS_OK)
        return;

    memcpy(folded, t->orig_qname.d, t->orig_qname.len);
    elpis_simd_lower(folded, folded, t->orig_qname.len);
    if (elpis_bld_question_raw(&b, folded, t->orig_qname.len,
                               t->orig_qtype, t->qclass) != ELPIS_OK)
        return;
    qend = b.len;

    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        elpis_name_t on;
        size_t rdpos;

        if (rr->section != (uint8_t)ELPIS_SEC_ANSWER)
            continue;
        if (elpis_trr_get_name(&t->ans, i, &on) != ELPIS_OK)
            continue;
        if (elpis_bld_rr_begin(&b, &on, rr->type, rr->klass, rr->ttl, &rdpos) != ELPIS_OK)
            return;
        if (elpis_bld_bytes(&b, elpis_trr_rd(&t->ans, i), rr->rdlen) != ELPIS_OK)
            return;
        if (elpis_bld_rr_end(&b, rdpos) != ELPIS_OK)
            return;
        elpis_bld_count(&b, ELPIS_SEC_ANSWER, 1);
    }
    ns_off = b.len;

    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        elpis_name_t on;
        size_t rdpos;

        if (rr->section != (uint8_t)ELPIS_SEC_AUTHORITY)
            continue;
        if (elpis_trr_get_name(&t->ans, i, &on) != ELPIS_OK)
            continue;
        if (elpis_bld_rr_begin(&b, &on, rr->type, rr->klass, rr->ttl, &rdpos) != ELPIS_OK)
            return;
        if (elpis_bld_bytes(&b, elpis_trr_rd(&t->ans, i), rr->rdlen) != ELPIS_OK)
            return;
        if (elpis_bld_rr_end(&b, rdpos) != ELPIS_OK)
            return;
        elpis_bld_count(&b, ELPIS_SEC_AUTHORITY, 1);
    }
    ar_off = b.len;

    for (i = 0; i < t->ans.n; i++) {
        const elpis_trr_t *rr = &t->ans.rr[i];
        elpis_name_t on;
        size_t rdpos;

        if (rr->section != (uint8_t)ELPIS_SEC_ADDITIONAL)
            continue;
        if (elpis_trr_get_name(&t->ans, i, &on) != ELPIS_OK)
            continue;
        if (elpis_bld_rr_begin(&b, &on, rr->type, rr->klass, rr->ttl, &rdpos) != ELPIS_OK)
            return;
        if (elpis_bld_bytes(&b, elpis_trr_rd(&t->ans, i), rr->rdlen) != ELPIS_OK)
            return;
        if (elpis_bld_rr_end(&b, rdpos) != ELPIS_OK)
            return;
        elpis_bld_count(&b, ELPIS_SEC_ADDITIONAL, 1);
    }

    elpis_bld_finish(&b);
    if (b.overflow)
        return;

    k.qname    = folded;
    k.qnamelen = t->orig_qname.len;
    k.qtype    = t->orig_qtype;
    k.qclass   = t->qclass;
    k.kflags   = (uint8_t)((t->client_do ? ELPIS_MK_DO : 0) |
                           (t->client_cd ? ELPIS_MK_CD : 0));
    elpis_mkey_hash(&k);

    elpis_mcache_store(w->ctx->mcache, &k, w->txbuf, b.len, qend,
                       w->ttl_off, w->ttl_val, b.nttl, ns_off, ar_off,
                       t->rcode,
                       (uint16_t)(t->sec == ELPIS_SEC_SECURE ? ELPIS_FLAG_AD : 0),
                       t->sec, ttl, c->serve_stale);
}
