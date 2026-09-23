/*
 * outbound.c -- upstream query transmission and response matching.
 *
 * Every defence a plain-UDP resolver has against off-path spoofing is applied
 * here at once: a random transaction ID, a random source port drawn from a
 * pool of sockets, 0x20 case encoding of the question name, and DNS cookies.
 * A response is accepted only if it matches on all of them plus the server
 * address and port.
 */
#include "elpis/resolver.h"
#include "elpis/sock.h"
#include "elpis/infra.h"
#include "elpis/crypto.h"
#include "elpis/log.h"

#include <errno.h>
#include <unistd.h>

static void out_udp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);
static void out_timeout(elpis_loop_t *lp, elpis_timer_t *tm);
static void out_tcp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);

ELPIS_INLINE unsigned out_slot(uint16_t id, int sockidx)
{
    uint32_t h = ((uint32_t)id << 8) ^ (uint32_t)(sockidx & 0xFF);
    h ^= h >> 7;
    return (unsigned)(h & (ELPIS_OUT_HASH - 1u));
}

/* ------------------------------------------------------------------ */
/* Socket pool                                                         */
/* ------------------------------------------------------------------ */

int elpis_out_init(elpis_worker_t *w)
{
    const elpis_conf_t *c = &w->ctx->conf;
    unsigned want = c->out_sockets ? c->out_sockets : 16u;
    unsigned i;

    if (want > ELPIS_MAX_OSOCK)
        want = ELPIS_MAX_OSOCK;

    for (i = 0; i < want; i++) {
        int family;
        int fd;
        elpis_osock_t *s;

        /* Alternate families so both are always available. */
        if (c->do_ipv4 && c->do_ipv6)
            family = (i % 2u == 0) ? AF_INET : AF_INET6;
        else if (c->do_ipv6)
            family = AF_INET6;
        else
            family = AF_INET;

        if (elpis_sock_udp_client(family,
                                  family == AF_INET
                                      ? (c->have_src4
                                         ? &c->out_src4[i % c->have_src4] : NULL)
                                      : (c->have_src6
                                         ? &c->out_src6[i % c->have_src6] : NULL),
                                  c->port_lo, c->port_hi, &fd) != ELPIS_OK) {
            if (family == AF_INET6) {
                /* No IPv6 on this host: stop asking for it. */
                continue;
            }
            break;
        }
        s = &w->osock[w->n_osock];
        memset(s, 0, sizeof *s);
        s->fd     = fd;
        s->family = family;
        s->w      = w;
        if (elpis_loop_add(w->loop, &s->ev, fd, ELPIS_EV_READ,
                           out_udp_event, s) != ELPIS_OK) {
            close(fd);
            break;
        }
        w->n_osock++;
    }

    if (w->n_osock == 0) {
        elpis_error("worker %u: no outbound sockets could be created", w->index);
        return ELPIS_ERR;
    }
    elpis_debug("worker %u: %u outbound sockets", w->index, w->n_osock);
    return ELPIS_OK;
}

void elpis_out_fini(elpis_worker_t *w)
{
    unsigned i;
    for (i = 0; i < ELPIS_OUT_HASH; i++) {
        while (w->outhash[i] != NULL) {
            elpis_outq_t *q = w->outhash[i];
            w->outhash[i] = q->hnext;
            elpis_timer_del(w->loop, &q->timer);
            if (q->tcpfd >= 0) {
                elpis_loop_del(w->loop, &q->tcpev);
                close(q->tcpfd);
            }
            elpis_free(q->txbuf);
            elpis_free(q->rxbuf);
            elpis_free(q);
        }
    }
    for (i = 0; i < w->n_osock; i++) {
        elpis_loop_del(w->loop, &w->osock[i].ev);
        close(w->osock[i].fd);
    }
    w->n_osock = 0;
}

static int pick_socket(elpis_worker_t *w, int family)
{
    unsigned i, start;

    if (w->n_osock == 0)
        return -1;
    /* Random start, then scan: the port a query leaves from is unpredictable. */
    start = elpis_random_below(w->n_osock);
    for (i = 0; i < w->n_osock; i++) {
        unsigned idx = (start + i) % w->n_osock;
        if (w->osock[idx].family == family)
            return (int)idx;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Query construction                                                  */
/* ------------------------------------------------------------------ */

/*
 * RFC 5452 "0x20" encoding: randomise the case of every letter in the
 * question name.  DNS name comparison is case-insensitive, so an authority
 * echoes the name back unchanged, and an off-path attacker must guess those
 * bits too.
 */
static void apply_0x20(uint8_t *name, size_t len)
{
    size_t i = 0;
    uint8_t rnd[ELPIS_MAX_NAME / 8 + 2];
    size_t rbits = 0;

    elpis_random_bytes(rnd, sizeof rnd);
    while (i < len) {
        unsigned l = name[i];
        unsigned j;
        if (l == 0 || l > ELPIS_MAX_LABEL)
            break;
        for (j = 1; j <= l && i + j < len; j++) {
            uint8_t ch = name[i + j];
            if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
                unsigned bit = (rnd[rbits / 8u] >> (rbits % 8u)) & 1u;
                rbits++;
                if (rbits >= sizeof rnd * 8u)
                    rbits = 0;
                name[i + j] = (uint8_t)(bit ? (ch | 0x20u) : (ch & ~0x20u));
            }
        }
        i += 1u + l;
    }
}

static size_t build_query(elpis_worker_t *w, elpis_outq_t *q,
                          const elpis_task_t *t, uint8_t *buf, size_t cap,
                          const elpis_infra_info_t *inf)
{
    elpis_bld_t b;
    elpis_edns_t e;
    /*
     * Iterative queries carry RD clear; a forwarder is asked to recurse on
     * our behalf, so that one gets RD set.
     */
    uint16_t flags = t->forwarding ? (uint16_t)ELPIS_FLAG_RD : (uint16_t)0;
    const elpis_conf_t *c = &w->ctx->conf;

    elpis_bld_init(&b, buf, cap, w->ctab, 1);
    if (elpis_bld_header(&b, q->id, flags) != ELPIS_OK)
        return 0;

    memcpy(q->qname_wire, t->qname.d, t->qname.len);
    q->qnamelen = t->qname.len;
    if (c->use_0x20)
        apply_0x20(q->qname_wire, q->qnamelen);

    if (elpis_bld_question_raw(&b, q->qname_wire, q->qnamelen,
                               q->qtype, q->qclass) != ELPIS_OK)
        return 0;

    if (inf->edns_state != ELPIS_EDNS_NO) {
        uint16_t bufsize = c->edns_buffer;
        if (inf->edns_state == ELPIS_EDNS_FALLBACK && inf->edns_max)
            bufsize = inf->edns_max;
        if (q->over_tcp)
            bufsize = ELPIS_MAX_UDP;

        elpis_edns_init(&e, bufsize, w->ctx->conf.dnssec ? 1 : 0);
        if (c->use_cookies) {
            elpis_cookie_client(&q->server, q->cookie);
            memcpy(e.cookie, q->cookie, 8);
            e.cookie_len = 8;
            /* Replay the server half we were given last time, if any. */
            if ((inf->flags & ELPIS_INF_COOKIE_OK) && inf->cookie_len > 0 &&
                (size_t)inf->cookie_len + 8u <= sizeof e.cookie) {
                memcpy(e.cookie + 8, inf->cookie, inf->cookie_len);
                e.cookie_len = (uint8_t)(8u + inf->cookie_len);
            }
            e.have_cookie = 1;
            q->used_cookie = 1;
        }
        if (elpis_edns_write(&b, &e, 0) == ELPIS_OK) {
            q->used_edns = 1;
            q->edns_size = bufsize;
        }
    }

    elpis_bld_finish(&b);
    if (b.overflow)
        return 0;
    return b.len;
}

/* ------------------------------------------------------------------ */
/* Send                                                                */
/* ------------------------------------------------------------------ */

static void out_register(elpis_worker_t *w, elpis_outq_t *q)
{
    unsigned s = out_slot(q->id, q->sockidx);
    q->hnext = w->outhash[s];
    w->outhash[s] = q;
    w->n_out++;
}

static void out_unregister(elpis_worker_t *w, elpis_outq_t *q)
{
    unsigned s = out_slot(q->id, q->sockidx);
    elpis_outq_t **pp = &w->outhash[s];
    while (*pp != NULL) {
        if (*pp == q) {
            *pp = q->hnext;
            q->hnext = NULL;
            if (w->n_out)
                w->n_out--;
            return;
        }
        pp = &(*pp)->hnext;
    }
}

void elpis_out_free(elpis_worker_t *w, elpis_outq_t *q)
{
    if (q == NULL)
        return;
    out_unregister(w, q);
    elpis_timer_del(w->loop, &q->timer);
    if (q->tcpfd >= 0) {
        elpis_loop_del(w->loop, &q->tcpev);
        close(q->tcpfd);
        q->tcpfd = -1;
    }
    elpis_free(q->txbuf);
    elpis_free(q->rxbuf);
    if (q->task != NULL && q->task->out == q)
        q->task->out = NULL;
    elpis_free(q);
}

void elpis_out_cancel(elpis_task_t *t)
{
    if (t->out != NULL) {
        t->out->task = NULL;
        elpis_out_free(t->w, t->out);
        t->out = NULL;
    }
}

static int start_tcp(elpis_task_t *t, elpis_outq_t *q, const uint8_t *msg,
                     size_t msglen);

int elpis_out_send(elpis_task_t *t, const elpis_addr_t *server, int force_tcp)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_outq_t *q;
    elpis_infra_info_t inf;
    size_t len;
    int sockidx;
    ssize_t sent;
    uint32_t timeout;

    elpis_out_cancel(t);

    q = (elpis_outq_t *)elpis_calloc(1, sizeof *q);
    if (q == NULL)
        return ELPIS_ENOMEM;
    q->tcpfd = -1;
    q->task   = t;
    q->server = *server;
    q->qtype  = t->qtype;
    q->qclass = t->qclass;
    q->over_tcp = force_tcp ? 1u : 0u;
    q->id = (uint16_t)elpis_random_u32();

    elpis_infra_get(w->ctx->infra, server, &inf);

    if (force_tcp || (inf.flags & ELPIS_INF_TCP_ONLY))
        q->over_tcp = 1;

    sockidx = pick_socket(w, elpis_addr_family(server));
    if (sockidx < 0) {
        elpis_free(q);
        return ELPIS_ERR;
    }
    q->sockidx = sockidx;

    len = build_query(w, q, t, w->txbuf, ELPIS_MAX_MSG, &inf);
    if (len == 0) {
        elpis_free(q);
        return ELPIS_ERR;
    }

    q->sent_ms = elpis_cached_now_ms();
    q->attempt = t->sends;
    t->out = q;

    if (q->over_tcp) {
        if (start_tcp(t, q, w->txbuf, len) != ELPIS_OK) {
            t->out = NULL;
            elpis_free(q);
            return ELPIS_ERR;
        }
        out_register(w, q);
    } else {
        sent = elpis_sock_send(w->osock[sockidx].fd, w->txbuf, len, server, NULL);
        if (sent != (ssize_t)len) {
            char ab[80];
            elpis_debug("send to %s failed: %s",
                        elpis_addr_str(server, ab, sizeof ab), strerror(errno));
            t->out = NULL;
            elpis_free(q);
            return ELPIS_ERR;
        }
        out_register(w, q);
    }

    elpis_stat_inc(&w->stats.upstream_queries, 1);

    /*
     * Wait a little longer than this server's measured round trip -- and over
     * TCP, one round trip more, for the handshake that has to finish before
     * the query is even sent.  Without it a server more than about 100 ms
     * away could not answer over TCP inside its own UDP allowance.
     */
    timeout = inf.srtt + 4u * inf.rttvar;
    if (q->over_tcp)
        timeout += inf.srtt;
    if (timeout < 250u)
        timeout = 250u;
    if (timeout > c->query_timeout_ms * 4u)
        timeout = c->query_timeout_ms * 4u;
    if (timeout > 5000u)
        timeout = 5000u;
    elpis_timer_add(w->loop, &q->timer, timeout, out_timeout, q);

    return ELPIS_OK;
}

/* ------------------------------------------------------------------ */
/* Response matching                                                   */
/* ------------------------------------------------------------------ */

static elpis_outq_t *out_find(elpis_worker_t *w, uint16_t id, int sockidx,
                              const elpis_addr_t *from, const elpis_msg_t *m)
{
    unsigned s = out_slot(id, sockidx);
    elpis_outq_t *q;

    for (q = w->outhash[s]; q != NULL; q = q->hnext) {
        if (q->id != id || q->sockidx != sockidx || q->dead)
            continue;
        if (!elpis_addr_eq(&q->server, from))
            continue;
        if (m->qtype != q->qtype || m->qclass != q->qclass)
            continue;
        /*
         * Byte-exact question name comparison, which is what makes the 0x20
         * encoding worth anything.  A case-insensitive compare here would
         * throw away the entropy we just spent.
         */
        if (m->qname.len != q->qnamelen)
            continue;
        if (memcmp(m->qname.d, q->qname_wire, q->qnamelen) != 0)
            continue;
        return q;
    }
    return NULL;
}

/* Learn the server's cookie half so the next query is pre-authenticated. */
static void absorb_cookie(elpis_worker_t *w, elpis_outq_t *q,
                          const elpis_msg_t *m)
{
    if (!m->have_cookie || m->cookie_len <= 8)
        return;
    if (memcmp(m->cookie, q->cookie, 8) != 0)
        return;                         /* not our client cookie */
    elpis_infra_set_cookie(w->ctx->infra, &q->server,
                           m->cookie + 8, (size_t)m->cookie_len - 8u);
}

static void handle_message(elpis_worker_t *w, elpis_outq_t *q,
                           const elpis_msg_t *m)
{
    elpis_task_t *t = q->task;
    uint32_t rtt;

    if (t == NULL) {
        elpis_out_free(w, q);
        return;
    }

    rtt = (uint32_t)(elpis_cached_now_ms() - q->sent_ms);
    elpis_infra_rtt_ok(w->ctx->infra, &q->server, rtt);
    absorb_cookie(w, q, m);

    if (q->used_edns) {
        if (m->have_opt) {
            elpis_infra_set_edns(w->ctx->infra, &q->server, ELPIS_EDNS_YES,
                                 q->edns_size);
        } else if (elpis_msg_rcode(m) == ELPIS_RC_FORMERR ||
                   elpis_msg_rcode(m) == ELPIS_RC_NOTIMP) {
            /* The peer does not understand EDNS; remember and retry plain. */
            elpis_infra_set_edns(w->ctx->infra, &q->server, ELPIS_EDNS_NO, 0);
        }
    }

    /*
     * BADCOOKIE means "resend with the cookie I just gave you"; we have
     * already stored it, so a single retry to the same server is correct.
     */
    if (elpis_msg_rcode(m) == ELPIS_RC_BADCOOKIE && q->used_cookie &&
        q->attempt < 2) {
        elpis_addr_t server = q->server;
        t->out = NULL;
        q->task = NULL;
        elpis_out_free(w, q);
        t->sends++;
        if (elpis_out_send(t, &server, 0) != ELPIS_OK)
            elpis_resolver_on_error(t, NULL, ELPIS_EDE_NETWORK_ERROR);
        return;
    }

    /* Truncated over UDP: repeat the query over TCP (RFC 7766). */
    if ((m->hdr.flags & ELPIS_FLAG_TC) && !q->over_tcp &&
        w->ctx->conf.tcp_upstream) {
        elpis_addr_t server = q->server;
        t->out = NULL;
        q->task = NULL;
        elpis_out_free(w, q);
        elpis_stat_inc(&w->stats.truncated, 1);
        if (elpis_out_send(t, &server, 1) != ELPIS_OK)
            elpis_resolver_on_error(t, NULL, ELPIS_EDE_NETWORK_ERROR);
        return;
    }

    t->out = NULL;
    q->task = NULL;
    elpis_resolver_on_response(t, q, m);
    elpis_out_free(w, q);
}

static void out_udp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_osock_t *s = (elpis_osock_t *)ev->data;
    elpis_worker_t *w = s->w;
    int sockidx = (int)(s - w->osock);
    unsigned budget = 64;

    (void)lp;
    if (!(events & ELPIS_EV_READ))
        return;

    while (budget-- > 0) {
        elpis_addr_t from;
        ssize_t n;
        elpis_msg_t m;
        int drop = ELPIS_DROP_NONE;
        elpis_outq_t *q;
        elpis_hdr_t h;

        memset(&from, 0, sizeof from);
        n = elpis_sock_recv(s->fd, w->rxbuf, ELPIS_MAX_MSG, &from, NULL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            return;
        }
        if (n < ELPIS_HDR_LEN) {
            elpis_drop_log(ELPIS_DROP_SHORT, &from, w->rxbuf, (size_t)n, "upstream");
            continue;
        }

        /*
         * Match on the header before parsing the body.  A flood of spoofed
         * packets should cost us a hash lookup, not a full parse.
         */
        if (elpis_hdr_parse(&h, w->rxbuf, (size_t)n) != ELPIS_OK)
            continue;
        if (!(h.flags & ELPIS_FLAG_QR)) {
            elpis_drop_log(ELPIS_DROP_QR_SET, &from, w->rxbuf, (size_t)n,
                           "query on outbound socket");
            continue;
        }

        if (elpis_msg_parse(&m, w->rxbuf, (size_t)n, ELPIS_PARSE_RESPONSE,
                            &drop) != ELPIS_OK) {
            elpis_drop_log((elpis_drop_t)drop, &from, w->rxbuf, (size_t)n,
                           "upstream response");
            continue;
        }

        q = out_find(w, h.id, sockidx, &from, &m);
        if (q == NULL) {
            /*
             * Either a spoofing attempt or, far more often, a legitimate
             * answer that arrived after we gave up on it.  The two are
             * indistinguishable from here, so it is counted as a drop but not
             * shouted about -- a slow authority must not fill the log.
             */
            elpis_drop_log_quiet(ELPIS_DROP_SPOOF, &from, w->rxbuf, (size_t)n,
                                 "no matching outstanding query");
            continue;
        }

        elpis_timer_del(w->loop, &q->timer);
        handle_message(w, q, &m);
    }
}

static void out_timeout(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_outq_t *q = (elpis_outq_t *)tm->data;
    elpis_worker_t *w;
    elpis_task_t *t = q->task;

    if (t == NULL)
        return;
    w = t->w;

    elpis_infra_timeout(w->ctx->infra, &q->server);
    elpis_stat_inc(&w->stats.timeouts, 1);

    t->out = NULL;
    q->task = NULL;
    elpis_resolver_on_timeout(t, q);
    elpis_out_free(w, q);
    (void)lp;
}

/* ------------------------------------------------------------------ */
/* TCP upstream                                                        */
/* ------------------------------------------------------------------ */

static int start_tcp(elpis_task_t *t, elpis_outq_t *q, const uint8_t *msg,
                     size_t msglen)
{
    elpis_worker_t *w = t->w;
    int fd;

    if (elpis_sock_tcp_connect(&q->server,
                               elpis_addr_family(&q->server) == AF_INET
                                   ? (w->ctx->conf.have_src4
                                      ? &w->ctx->conf.out_src4[0] : NULL)
                                   : (w->ctx->conf.have_src6
                                      ? &w->ctx->conf.out_src6[0] : NULL),
                               &fd) != ELPIS_OK)
        return ELPIS_ERR;

    q->txbuf = (uint8_t *)elpis_malloc(msglen + 2);
    if (q->txbuf == NULL) {
        close(fd);
        return ELPIS_ENOMEM;
    }
    elpis_put16(q->txbuf, (uint16_t)msglen);
    memcpy(q->txbuf + 2, msg, msglen);
    q->txlen  = msglen + 2;
    q->txsent = 0;
    q->tcpfd  = fd;

    if (elpis_loop_add(w->loop, &q->tcpev, fd, ELPIS_EV_WRITE,
                       out_tcp_event, q) != ELPIS_OK) {
        close(fd);
        q->tcpfd = -1;
        elpis_free(q->txbuf);
        q->txbuf = NULL;
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

static void tcp_fail(elpis_worker_t *w, elpis_outq_t *q, int ede)
{
    elpis_task_t *t = q->task;
    t = q->task;
    if (t != NULL) {
        t->out = NULL;
        q->task = NULL;
        elpis_infra_timeout(w->ctx->infra, &q->server);
        elpis_resolver_on_error(t, q, ede);
    }
    elpis_out_free(w, q);
}

static void out_tcp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_outq_t *q = (elpis_outq_t *)ev->data;
    elpis_task_t *t = q->task;
    elpis_worker_t *w;

    if (t == NULL) {
        return;
    }
    w = t->w;

    if (events & (ELPIS_EV_ERROR | ELPIS_EV_HUP)) {
        if (q->rxwant == 0 || q->rxlen < q->rxwant + 2u) {
            tcp_fail(w, q, ELPIS_EDE_NETWORK_ERROR);
            return;
        }
    }

    if (events & ELPIS_EV_WRITE) {
        while (q->txsent < q->txlen) {
            ssize_t n = write(q->tcpfd, q->txbuf + q->txsent, q->txlen - q->txsent);
            if (n > 0) {
                q->txsent += (size_t)n;
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                return;
            if (n < 0 && errno == EINTR)
                continue;
            tcp_fail(w, q, ELPIS_EDE_NETWORK_ERROR);
            return;
        }
        elpis_loop_mod(lp, &q->tcpev, ELPIS_EV_READ);
        return;
    }

    if (!(events & ELPIS_EV_READ))
        return;

    for (;;) {
        ssize_t n;

        if (q->rxcap == 0) {
            q->rxcap = 2048;
            q->rxbuf = (uint8_t *)elpis_malloc(q->rxcap);
            if (q->rxbuf == NULL) {
                tcp_fail(w, q, ELPIS_EDE_OTHER);
                return;
            }
        }
        if (q->rxwant != 0 && q->rxwant + 2u > q->rxcap) {
            uint8_t *nb = (uint8_t *)elpis_realloc(q->rxbuf, q->rxwant + 2u);
            if (nb == NULL) {
                tcp_fail(w, q, ELPIS_EDE_OTHER);
                return;
            }
            q->rxbuf = nb;
            q->rxcap = q->rxwant + 2u;
        }

        n = read(q->tcpfd, q->rxbuf + q->rxlen, q->rxcap - q->rxlen);
        if (n == 0) {
            tcp_fail(w, q, ELPIS_EDE_NETWORK_ERROR);
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            tcp_fail(w, q, ELPIS_EDE_NETWORK_ERROR);
            return;
        }
        q->rxlen += (size_t)n;

        /*
         * No `continue` once the length is known: the check below has to see
         * this same read.  An authority normally writes the prefix and the
         * message together, so the first read usually returns the whole
         * answer -- and going round for another read got EAGAIN, left the
         * complete answer sitting in the buffer, and waited for bytes that
         * were never coming until the timer gave up on the server.  Only a
         * reply split across segments ever got through, which made TCP look
         * flaky rather than broken: a truncated org. DNSKEY walked every org
         * server in turn, 250 ms apiece.
         */
        if (q->rxwant == 0 && q->rxlen >= 2) {
            q->rxwant = elpis_get16(q->rxbuf);
            if (q->rxwant < ELPIS_HDR_LEN) {
                elpis_drop_log(ELPIS_DROP_SHORT, &q->server, q->rxbuf,
                               q->rxlen, "tcp length prefix");
                tcp_fail(w, q, ELPIS_EDE_INVALID_DATA);
                return;
            }
        }
        if (q->rxwant != 0 && q->rxlen >= q->rxwant + 2u) {
            elpis_msg_t m;
            int drop = ELPIS_DROP_NONE;

            elpis_timer_del(w->loop, &q->timer);
            elpis_loop_del(w->loop, &q->tcpev);
            close(q->tcpfd);
            q->tcpfd = -1;

            if (elpis_msg_parse(&m, q->rxbuf + 2, q->rxwant,
                                ELPIS_PARSE_RESPONSE, &drop) != ELPIS_OK) {
                elpis_drop_log((elpis_drop_t)drop, &q->server, q->rxbuf + 2,
                               q->rxwant, "upstream tcp response");
                tcp_fail(w, q, ELPIS_EDE_INVALID_DATA);
                return;
            }
            if (m.hdr.id != q->id || m.qtype != q->qtype ||
                m.qclass != q->qclass || m.qname.len != q->qnamelen ||
                memcmp(m.qname.d, q->qname_wire, q->qnamelen) != 0) {
                elpis_drop_log(ELPIS_DROP_SPOOF, &q->server, q->rxbuf + 2,
                               q->rxwant, "tcp response does not match query");
                tcp_fail(w, q, ELPIS_EDE_INVALID_DATA);
                return;
            }
            handle_message(w, q, &m);
            return;
        }
    }
}
