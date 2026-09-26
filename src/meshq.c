/*
 * meshq.c -- asking a nearby peer's cache on a miss, from a worker.
 *
 * The other half of mesh lookups: mesh.c answers them, and keeps the table of
 * peers worth asking (elpis/mesh.h).  A worker whose client query misses the
 * cache asks one peer while its own resolution carries on, and whichever
 * answers first goes to the client, so a lookup can only make an answer
 * sooner, never later.  What a peer answers goes out without AD -- this
 * instance did not validate it -- and is resolved again here straight after,
 * which replaces it with this instance's own answer (resolver.c).
 *
 * Each worker has its own sockets, one per family, on ports of their own, so
 * an answer always comes back to the worker that asked.
 */
#include "elpis/resolver.h"
#include "elpis/mesh.h"
#include "elpis/crypto.h"
#include "elpis/sock.h"
#include "elpis/simd.h"
#include "elpis/util.h"
#include "elpis/log.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct peerq {
    struct peerq *hnext;
    elpis_task_t *task;
    uint8_t       token[8];
    uint8_t       key[32];
    uint32_t      key_id;
    elpis_addr_t  to;
} peerq_t;

#define MQ_BUCKETS 256u             /* by the token's first byte */

typedef struct {
    int         ready;
    int         fd[2];              /* IPv4, IPv6; -1 until first needed */
    elpis_ev_t  ev[2];
    peerq_t    *hash[MQ_BUCKETS];
} meshq_t;

/* Every task lives and dies on its worker's thread, and so does this. */
static ELPIS_TLS meshq_t g_mq;

static void mq_readable(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);

static int mq_socket(elpis_worker_t *w, int family)
{
    int i = family == AF_INET ? 0 : 1;
    int fd;

    if (!g_mq.ready) {
        memset(&g_mq, 0, sizeof g_mq);
        g_mq.fd[0] = g_mq.fd[1] = -1;
        g_mq.ready = 1;
    }
    if (g_mq.fd[i] >= 0)
        return g_mq.fd[i];
    fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    elpis_sock_cloexec(fd);
    if (elpis_sock_nonblock(fd) != ELPIS_OK ||
        elpis_loop_add(w->loop, &g_mq.ev[i], fd, ELPIS_EV_READ, mq_readable,
                       w) != ELPIS_OK) {
        close(fd);
        return -1;
    }
    g_mq.fd[i] = fd;
    return fd;
}

/*
 * Questions a peer answered and this instance then could not confirm.  For
 * a while nobody asks a peer about them again -- otherwise every query would
 * be answered from the peer first, and dropped again after.  Shared by every
 * worker, so written the way server.c keeps its failure memory: a slot a
 * racing writer overwrites costs one more peer lookup, nothing worse.
 */
#define DISTRUST_SLOTS 1024u
#define DISTRUST_MS    (10u * 60u * 1000u)

static struct {
    uint64_t h;
    uint64_t until_ms;
} g_distrust[DISTRUST_SLOTS];

void elpis_meshq_distrust(uint64_t qhash)
{
    unsigned i = (unsigned)(qhash % DISTRUST_SLOTS);

    __atomic_store_n(&g_distrust[i].until_ms,
                     elpis_cached_now_ms() + DISTRUST_MS, __ATOMIC_RELAXED);
    __atomic_store_n(&g_distrust[i].h, qhash, __ATOMIC_RELAXED);
}

static int distrusted(uint64_t qhash)
{
    unsigned i = (unsigned)(qhash % DISTRUST_SLOTS);

    return __atomic_load_n(&g_distrust[i].h, __ATOMIC_RELAXED) == qhash &&
           __atomic_load_n(&g_distrust[i].until_ms, __ATOMIC_RELAXED) >
               elpis_cached_now_ms();
}

static void mq_free(peerq_t *q)
{
    elpis_memzero(q->key, sizeof q->key);
    elpis_free(q);
}

void elpis_meshq_ask(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    uint8_t folded[ELPIS_MAX_NAME];
    uint8_t pt[ELPIS_MESH_LQ_MAX], dg[ELPIS_MESH_LQ_MAX + 64];
    elpis_mesh_pick_t pick;
    peerq_t *q;
    uint8_t kflags, len;
    size_t n, dn;
    int fd;

    if (!c->mesh || !c->mesh_lookup || t->peer_asked)
        return;
    t->peer_asked = 1;              /* once, whatever happens next */
    /*
     * A client's own question, and one a peer may answer: the types a browser
     * waits on.  Never with CD set -- that asks for data nobody checked.
     */
    if (!t->has_client || t->parent != NULL || t->client_cd ||
        t->qclass != ELPIS_CLASS_IN ||
        (t->orig_qtype != ELPIS_T_A && t->orig_qtype != ELPIS_T_AAAA &&
         t->orig_qtype != ELPIS_T_HTTPS))
        return;

    len = t->orig_qname.len;
    memcpy(folded, t->orig_qname.d, len);
    elpis_simd_lower(folded, folded, len);
    kflags = t->client_do ? (uint8_t)ELPIS_MK_DO : 0u;
    {
        uint64_t h = elpis_mesh_qhash(folded, len, t->orig_qtype, kflags);
        if (distrusted(h) || elpis_mesh_pick(h, &pick) != ELPIS_OK)
            return;
    }

    fd = mq_socket(w, elpis_addr_family(&pick.addr));
    q = fd >= 0 ? (peerq_t *)elpis_calloc(1, sizeof *q) : NULL;
    if (q == NULL) {
        elpis_memzero(pick.key, sizeof pick.key);
        return;
    }
    elpis_random_bytes(q->token, sizeof q->token);

    pt[0] = (uint8_t)ELPIS_MESH_LQ_ASK;
    pt[1] = kflags;
    memcpy(pt + 2, q->token, 8);
    memset(pt + ELPIS_MESH_LQ_HDR, 0, ELPIS_HDR_LEN);
    elpis_put16(pt + ELPIS_MESH_LQ_HDR + 4, 1);          /* one question */
    n = ELPIS_MESH_LQ_HDR + ELPIS_HDR_LEN;
    memcpy(pt + n, folded, len);
    n += len;
    elpis_put16(pt + n, t->orig_qtype);
    elpis_put16(pt + n + 2, ELPIS_CLASS_IN);
    n += 4;

    dn = elpis_mesh_lq_seal(pick.key, pick.key_id, pt, n, dg);
    if (sendto(fd, dg, dn, 0, &pick.addr.u.sa, pick.addr.len) < 0) {
        elpis_memzero(pick.key, sizeof pick.key);
        mq_free(q);
        return;
    }
    q->task = t;
    q->key_id = pick.key_id;
    q->to = pick.addr;
    memcpy(q->key, pick.key, 32);
    elpis_memzero(pick.key, sizeof pick.key);
    q->hnext = g_mq.hash[q->token[0]];
    g_mq.hash[q->token[0]] = q;
    t->peerq = q;
    elpis_stat_inc(&w->stats.peer_asked, 1);
}

void elpis_meshq_cancel(elpis_task_t *t)
{
    peerq_t *q = (peerq_t *)t->peerq, **pp;

    if (q == NULL)
        return;
    t->peerq = NULL;
    for (pp = &g_mq.hash[q->token[0]]; *pp != NULL; pp = &(*pp)->hnext)
        if (*pp == q) {
            *pp = q->hnext;
            break;
        }
    mq_free(q);
}

/* Any lookup in flight to that peer under that key: all share the key, and
 * the token inside then says which one this answers. */
static peerq_t *mq_any(uint32_t key_id, const elpis_addr_t *from)
{
    unsigned b;
    peerq_t *q;

    for (b = 0; b < MQ_BUCKETS; b++)
        for (q = g_mq.hash[b]; q != NULL; q = q->hnext)
            if (q->key_id == key_id && elpis_addr_eq(&q->to, from))
                return q;
    return NULL;
}

static void mq_readable(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_worker_t *w = (elpis_worker_t *)ev->data;

    (void)lp;
    (void)events;
    for (;;) {
        uint8_t dg[ELPIS_MESH_LQ_MAX + 64], pt[ELPIS_MESH_LQ_MAX + 64];
        elpis_addr_t from;
        peerq_t *any, *hit = NULL, **pp;
        elpis_task_t *t;
        elpis_msg_t m;
        size_t ptlen;
        uint32_t id;
        ssize_t n;
        int drop = 0;

        memset(&from, 0, sizeof from);
        from.len = sizeof from.u.ss;
        n = recvfrom(ev->fd, dg, sizeof dg, 0, &from.u.sa, &from.len);
        if (n < 0)
            return;
        if ((size_t)n < ELPIS_MESH_LQ_OVERHEAD + ELPIS_MESH_LQ_HDR)
            continue;
        id = elpis_get32(dg);
        if ((any = mq_any(id, &from)) == NULL ||
            elpis_mesh_lq_open(any->key, dg, (size_t)n, pt, &ptlen) != ELPIS_OK ||
            ptlen < ELPIS_MESH_LQ_HDR || pt[0] != ELPIS_MESH_LQ_ANSWER)
            continue;               /* late, forged, or for a task now gone */

        for (pp = &g_mq.hash[pt[2]]; *pp != NULL; pp = &(*pp)->hnext)
            if (memcmp((*pp)->token, pt + 2, 8) == 0 && (*pp)->key_id == id &&
                elpis_addr_eq(&(*pp)->to, &from)) {
                hit = *pp;
                *pp = hit->hnext;
                break;
            }
        if (hit == NULL)
            continue;
        t = hit->task;
        t->peerq = NULL;
        mq_free(hit);

        if (!pt[1])
            continue;               /* the digest's false positive */
        elpis_stat_inc(&w->stats.peer_found, 1);
        if (elpis_msg_parse(&m, pt + ELPIS_MESH_LQ_HDR, ptlen - ELPIS_MESH_LQ_HDR,
                            ELPIS_PARSE_RESPONSE, &drop) != ELPIS_OK)
            continue;
        if (elpis_task_peer_answer(t, &m) == ELPIS_OK)
            elpis_stat_inc(&w->stats.peer_used, 1);
    }
}
