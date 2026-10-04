/*
 * dot.c -- DNS over TLS to authoritative servers (RFC 9539): the connections.
 *
 * Each worker keeps at most one TLS connection per server, on the server's
 * port 853, and every DoT query for that server goes over it: written back to
 * back, answered in any order, matched by ID and question as RFC 7766 says.
 * A new connection costs two round trips before its first answer -- TCP,
 * then TLS -- so they are kept, and closed after ELPIS_DOT_IDLE_MS unused.
 *
 * What a query does about DoT is decided in outbound.c from the server's
 * infra entry: use it, test it, or leave it.  This file only carries queries
 * and reports back.  An answer goes to elpis_out_dot_message().  A
 * connection that fails -- refused, silent, a TLS alert -- marks the server
 * failed and hands every query on it to elpis_out_dot_failed(), which sends
 * it plain.  A connection that had worked and is then closed with queries on
 * it has only lost them: they are sent again, once, on a fresh one.
 */
#include "elpis/resolver.h"
#include "elpis/infra.h"
#include "elpis/sock.h"
#include "elpis/simd.h"
#include "elpis/log.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Why a connection failed. */
enum { DF_REFUSED, DF_TIMEOUT, DF_CLOSED, DF_TLS };

static void conn_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);
static void conn_timer(elpis_loop_t *lp, elpis_timer_t *tm);

static unsigned dot_slot(const elpis_addr_t *a)
{
    return (unsigned)(elpis_mix64(elpis_addr_hash(a)) & (ELPIS_DOT_HASH - 1u));
}

elpis_dotconn_t *elpis_dot_find(elpis_worker_t *w, const elpis_addr_t *server)
{
    elpis_dotconn_t *c;
    for (c = w->dothash[dot_slot(server)]; c != NULL; c = c->hnext)
        if (elpis_addr_eq(&c->server, server))
            return c;
    return NULL;
}

/* The open connection with nothing on it that was used longest ago. */
static elpis_dotconn_t *idlest(elpis_worker_t *w)
{
    elpis_dotconn_t *best = NULL, *c;
    unsigned i;

    for (i = 0; i < ELPIS_DOT_HASH; i++)
        for (c = w->dothash[i]; c != NULL; c = c->hnext)
            if (c->open && c->npending == 0 && !c->in_event &&
                (best == NULL || c->used_ms < best->used_ms))
                best = c;
    return best;
}

int elpis_dot_can_send(elpis_worker_t *w, const elpis_addr_t *server)
{
    elpis_dotconn_t *c = elpis_dot_find(w, server);

    if (c != NULL)
        return c->npending < ELPIS_DOT_MAX_PENDING;
    if (w->n_dot_hs >= ELPIS_DOT_MAX_HANDSHAKES)
        return 0;
    return w->n_dot < ELPIS_DOT_MAX_CONNS || idlest(w) != NULL;
}

/* ------------------------------------------------------------------ */
/* Closing                                                             */
/* ------------------------------------------------------------------ */

/* What the status page has not been told yet. */
static void report(elpis_dotconn_t *c)
{
    if (c->unreported > 0) {
        elpis_tm_dot_answers(&c->server, &c->zone, c->unreported,
                             elpis_cached_now_s());
        c->unreported = 0;
    }
}

static void conn_destroy(elpis_dotconn_t *c)
{
    report(c);
    elpis_tls_free(&c->tls);
    elpis_free(c);
}

/*
 * Out of the table and off the loop at once, so nothing finds it and no
 * event reaches it; the memory goes when its handler, if running, returns.
 */
static void conn_close(elpis_dotconn_t *c)
{
    elpis_worker_t *w = c->w;
    elpis_dotconn_t **pp = &w->dothash[dot_slot(&c->server)];

    while (*pp != NULL) {
        if (*pp == c) {
            *pp = c->hnext;
            break;
        }
        pp = &(*pp)->hnext;
    }
    c->hnext = NULL;
    elpis_timer_del(w->loop, &c->timer);
    if (c->fd >= 0) {
        elpis_loop_del(w->loop, &c->ev);
        close(c->fd);
        c->fd = -1;
    }
    if (!c->open && w->n_dot_hs > 0)
        w->n_dot_hs--;
    if (w->n_dot > 0)
        w->n_dot--;
    elpis_stat_inc(&w->stats.dot_closed, 1);
    if (c->in_event)
        c->dead = 1;
    else
        conn_destroy(c);
}

/* Send what the engine has queued.  -1 when the socket has failed. */
static int flush(elpis_dotconn_t *c)
{
    unsigned want = ELPIS_EV_READ;

    for (;;) {
        const uint8_t *p;
        size_t n = elpis_tls_out(&c->tls, &p);
        ssize_t r;

        if (n == 0)
            break;
        r = send(c->fd, p, n, MSG_NOSIGNAL);
        if (r > 0) {
            elpis_tls_out_done(&c->tls, (size_t)r);
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            want |= ELPIS_EV_WRITE;
            break;
        }
        return -1;
    }
    if (c->ev.mask != want)
        elpis_loop_mod(c->w->loop, &c->ev, want);
    return 0;
}

/* An idle connection, or one being evicted: say goodbye and go. */
static void conn_close_quiet(elpis_dotconn_t *c)
{
    if (c->open && c->fd >= 0) {
        elpis_tls_close(&c->tls);
        (void)flush(c);
    }
    conn_close(c);
}

static int tls_why(const elpis_tls_t *t, elpis_stats_t *s)
{
    unsigned alert = t->err == ELPIS_TLS_E_ALERT ? t->alert : 255u;

    if (t->err == ELPIS_TLS_E_HRR || alert == 40) {
        elpis_stat_inc(&s->dot_fail_nogroup, 1);    /* no X25519 */
    } else if (t->err == ELPIS_TLS_E_VERSION || alert == 70) {
        elpis_stat_inc(&s->dot_fail_version, 1);    /* no TLS 1.3 */
    } else if (t->err == ELPIS_TLS_E_ALPN || alert == 120) {
        elpis_stat_inc(&s->dot_fail_alpn, 1);
    } else {
        elpis_stat_inc(&s->dot_fail_tls, 1);
    }
    return DF_TLS;
}

/*
 * The connection is no good.  Unless it had worked and is merely gone, the
 * server is marked failed; then every query on it goes back to outbound.c.
 */
static void conn_fail(elpis_dotconn_t *c, int why)
{
    elpis_worker_t *w = c->w;
    const elpis_conf_t *conf = &w->ctx->conf;
    elpis_outq_t *list = c->pending, *q;
    int lost = c->answers > 0;
    char ab[80];

    if (!lost) {
        elpis_stats_t *s = &w->stats;
        uint32_t now = elpis_cached_now_s();
        int st;

        switch (why) {
        case DF_REFUSED: elpis_stat_inc(&s->dot_fail_refused, 1); break;
        case DF_TIMEOUT: elpis_stat_inc(&s->dot_fail_timeout, 1); break;
        case DF_CLOSED:  elpis_stat_inc(&s->dot_fail_closed, 1);  break;
        default:         (void)tls_why(&c->tls, s);               break;
        }
        st = elpis_infra_dot_fail(w->ctx->infra, &c->server, now,
                                  ELPIS_MIN(conf->adot_retry_s, conf->adot_ttl_s),
                                  conf->adot_max_try);
        elpis_tm_dot_failed(&c->server, st, now);
        elpis_debug("dot: %s failed: %s%s",
                    elpis_addr_str(&c->peer, ab, sizeof ab),
                    why == DF_REFUSED ? "refused" :
                    why == DF_TIMEOUT ? "no handshake in time" :
                    why == DF_CLOSED  ? "closed" : elpis_tls_err_name(c->tls.err),
                    st == ELPIS_DOT_UNAVAILABLE ? "; giving up on it" : "");
    }

    /* Off the connection first: the hand-back may open a new one. */
    c->pending = NULL;
    c->npending = 0;
    for (q = list; q != NULL; q = q->cnext)
        q->conn = NULL;
    if (c->fd >= 0 && c->tls.state == ELPIS_TLS_FAILED)
        (void)flush(c);                 /* our alert, for the server's log */
    conn_close(c);

    while (list != NULL) {
        q = list;
        list = q->cnext;
        q->cnext = NULL;
        elpis_out_dot_failed(w, q, lost);
    }
}

/* ------------------------------------------------------------------ */
/* Opening                                                             */
/* ------------------------------------------------------------------ */

/*
 * A connection refused before it was ever made: the kernel can say so at
 * connect() itself, nearby.  That is a failed test as surely as a refusal
 * that comes later, and is marked the same way.
 */
static void refused_now(elpis_worker_t *w, const elpis_addr_t *server)
{
    const elpis_conf_t *conf = &w->ctx->conf;
    uint32_t now = elpis_cached_now_s();
    int st;

    elpis_stat_inc(&w->stats.dot_fail_refused, 1);
    st = elpis_infra_dot_fail(w->ctx->infra, server, now,
                              ELPIS_MIN(conf->adot_retry_s, conf->adot_ttl_s),
                              conf->adot_max_try);
    elpis_tm_dot_failed(server, st, now);
}

static elpis_dotconn_t *conn_open(elpis_worker_t *w, const elpis_addr_t *server)
{
    const elpis_conf_t *conf = &w->ctx->conf;
    uint16_t port = w->ctx->dot_port ? w->ctx->dot_port : 853;
    elpis_dotconn_t *c;
    int fd, fam = elpis_addr_family(server);

    c = (elpis_dotconn_t *)elpis_calloc(1, sizeof *c);
    if (c == NULL)
        return NULL;
    c->w = w;
    c->fd = -1;
    c->server = *server;
    c->peer = *server;
    if (fam == AF_INET)
        c->peer.u.v4.sin_port = htons(port);
    else
        c->peer.u.v6.sin6_port = htons(port);

    if (elpis_tls_init(&c->tls, "dot", NULL) != 0) {
        elpis_free(c);
        return NULL;
    }
    if (elpis_sock_tcp_connect(&c->peer,
                               fam == AF_INET
                                   ? (conf->have_src4 ? &conf->out_src4[0] : NULL)
                                   : (conf->have_src6 ? &conf->out_src6[0] : NULL),
                               &fd) != ELPIS_OK) {
        if (errno == ECONNREFUSED)
            refused_now(w, server);
        elpis_tls_free(&c->tls);
        elpis_free(c);
        return NULL;
    }
    c->fd = fd;
    if (elpis_loop_add(w->loop, &c->ev, fd, ELPIS_EV_WRITE, conn_event, c)
        != ELPIS_OK) {
        close(fd);
        elpis_tls_free(&c->tls);
        elpis_free(c);
        return NULL;
    }
    c->opened_ms = c->used_ms = elpis_cached_now_ms();
    elpis_timer_add(w->loop, &c->timer, ELPIS_DOT_HANDSHAKE_MS, conn_timer, c);

    c->hnext = w->dothash[dot_slot(server)];
    w->dothash[dot_slot(server)] = c;
    w->n_dot++;
    w->n_dot_hs++;
    elpis_stat_inc(&w->stats.dot_opened, 1);
    return c;
}

static void write_query(elpis_dotconn_t *c, elpis_outq_t *q)
{
    if (elpis_tls_write(&c->tls, q->txbuf, q->txlen) == 0) {
        q->dot_sent = 1;
        q->sent_ms  = elpis_cached_now_ms();
        c->used_ms  = q->sent_ms;
    }
}

int elpis_dot_send(elpis_worker_t *w, elpis_outq_t *q, const elpis_name_t *zone)
{
    elpis_dotconn_t *c = elpis_dot_find(w, &q->server);
    elpis_outq_t **pp;

    if (c == NULL) {
        if (w->n_dot_hs >= ELPIS_DOT_MAX_HANDSHAKES)
            return -1;
        if (w->n_dot >= ELPIS_DOT_MAX_CONNS) {
            elpis_dotconn_t *victim = idlest(w);
            if (victim == NULL)
                return -1;
            conn_close_quiet(victim);
        }
        c = conn_open(w, &q->server);
        if (c == NULL)
            return -1;
    } else if (c->npending >= ELPIS_DOT_MAX_PENDING) {
        return -1;
    }
    if (zone != NULL && zone->len > 0)
        c->zone = *zone;

    q->conn  = c;
    q->cnext = NULL;
    for (pp = &c->pending; *pp != NULL; pp = &(*pp)->cnext)
        ;
    *pp = q;
    c->npending++;
    elpis_stat_inc(&w->stats.dot_queries, 1);

    if (c->open) {
        elpis_timer_del(w->loop, &c->timer);    /* no longer idle */
        write_query(c, q);
        /*
         * A socket that has failed is not dealt with here, in the middle of
         * the caller's send: the loop reports it, and the connection fails
         * from its own handler, where handing q back is safe.
         */
        if (!c->in_event)
            (void)flush(c);
    }
    return 0;
}

void elpis_dot_detach(elpis_outq_t *q)
{
    elpis_dotconn_t *c = q->conn;
    elpis_outq_t **pp;

    if (c == NULL)
        return;
    for (pp = &c->pending; *pp != NULL; pp = &(*pp)->cnext) {
        if (*pp == q) {
            *pp = q->cnext;
            c->npending--;
            break;
        }
    }
    q->conn = NULL;
    q->cnext = NULL;
    if (c->npending == 0 && c->open && !c->dead)
        elpis_timer_add(c->w->loop, &c->timer, ELPIS_DOT_IDLE_MS, conn_timer, c);
}

/* ------------------------------------------------------------------ */
/* Events                                                              */
/* ------------------------------------------------------------------ */

static void on_open(elpis_dotconn_t *c)
{
    elpis_worker_t *w = c->w;
    uint64_t now = elpis_cached_now_ms();
    elpis_outq_t *q;

    c->open = 1;
    if (w->n_dot_hs > 0)
        w->n_dot_hs--;
    elpis_timer_del(w->loop, &c->timer);
    elpis_stat_inc(&w->stats.dot_handshakes, 1);
    elpis_stat_inc(&w->stats.dot_hs_ms, now - c->opened_ms);
    elpis_tm_dot_handshake(&c->server, c->tls.suite,
                           (uint32_t)(now - c->opened_ms), elpis_cached_now_s());

    for (q = c->pending; q != NULL; q = q->cnext)
        if (!q->dot_sent)
            write_query(c, q);
    if (c->npending == 0)
        elpis_timer_add(w->loop, &c->timer, ELPIS_DOT_IDLE_MS, conn_timer, c);
}

/* Whole DNS messages out of the decrypted stream, each to its query. */
static void drain(elpis_dotconn_t *c)
{
    elpis_worker_t *w = c->w;

    while (!c->dead) {
        const uint8_t *p;
        size_t n, len;
        uint8_t pre[2];
        elpis_msg_t m;
        elpis_outq_t *q;
        int drop = ELPIS_DROP_NONE;

        p = elpis_tls_peek(&c->tls, &n);
        if (n < 2)
            return;
        len = elpis_get16(p);
        if (n < 2u + len)
            return;
        elpis_tls_read(&c->tls, pre, 2);
        elpis_tls_read(&c->tls, w->rxbuf, len);

        if (elpis_msg_parse(&m, w->rxbuf, len, ELPIS_PARSE_RESPONSE,
                            &drop) != ELPIS_OK) {
            elpis_drop_log((elpis_drop_t)drop, &c->peer, w->rxbuf, len,
                           "upstream dot response");
            continue;
        }
        for (q = c->pending; q != NULL; q = q->cnext)
            if (q->dot_sent && q->id == m.hdr.id && q->qtype == m.qtype &&
                q->qclass == m.qclass && q->qnamelen == m.qname.len &&
                memcmp(q->qname_wire, m.qname.d, q->qnamelen) == 0)
                break;
        if (q == NULL) {
            elpis_drop_log_quiet(ELPIS_DROP_SPOOF, &c->peer, w->rxbuf, len,
                                 "dot response matches no query");
            continue;
        }
        c->answers++;
        c->unreported++;
        c->used_ms = elpis_cached_now_ms();
        if (c->unreported >= 64)
            report(c);
        elpis_out_dot_message(w, q, &m);
    }
}

static void conn_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_dotconn_t *c = (elpis_dotconn_t *)ev->data;
    elpis_worker_t *w = c->w;
    unsigned budget = 8;

    (void)lp;
    c->in_event = 1;

    if (!c->connected) {
        int err = 0;
        socklen_t el = sizeof err;

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0)
            err = errno;
        if (err != 0) {
            conn_fail(c, err == ECONNREFUSED ? DF_REFUSED : DF_CLOSED);
            goto out;
        }
        if (events & (ELPIS_EV_ERROR | ELPIS_EV_HUP)) {
            conn_fail(c, DF_CLOSED);
            goto out;
        }
        if (!(events & ELPIS_EV_WRITE))
            goto out;
        c->connected = 1;
    }

    while (budget-- > 0 &&
           (events & (ELPIS_EV_READ | ELPIS_EV_HUP | ELPIS_EV_ERROR))) {
        elpis_tls_state_t st;
        ssize_t n = recv(c->fd, w->rxbuf, ELPIS_MAX_MSG, 0);

        if (n == 0) {
            if (c->open && c->npending == 0)
                conn_close(c);
            else
                conn_fail(c, DF_CLOSED);
            goto out;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            conn_fail(c, errno == ECONNREFUSED ? DF_REFUSED : DF_CLOSED);
            goto out;
        }
        st = elpis_tls_feed(&c->tls, w->rxbuf, (size_t)n);
        if (st == ELPIS_TLS_FAILED) {
            conn_fail(c, DF_TLS);
            goto out;
        }
        if (!c->open && st != ELPIS_TLS_HANDSHAKE)
            on_open(c);
        drain(c);
        if (c->dead)
            goto out;
        if (st == ELPIS_TLS_CLOSED) {
            if (c->npending == 0)
                conn_close(c);
            else
                conn_fail(c, DF_CLOSED);
            goto out;
        }
    }
    if (flush(c) != 0)
        conn_fail(c, DF_CLOSED);

out:
    c->in_event = 0;
    if (c->dead)
        conn_destroy(c);
}

static void conn_timer(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_dotconn_t *c = (elpis_dotconn_t *)tm->data;

    (void)lp;
    if (!c->open)
        conn_fail(c, DF_TIMEOUT);
    else if (c->npending == 0)
        conn_close_quiet(c);
}

void elpis_dot_fini(elpis_worker_t *w)
{
    unsigned i;

    for (i = 0; i < ELPIS_DOT_HASH; i++) {
        while (w->dothash[i] != NULL) {
            elpis_dotconn_t *c = w->dothash[i];
            while (c->pending != NULL)
                elpis_out_free(w, c->pending);      /* detaches it */
            conn_close(c);
        }
    }
}
