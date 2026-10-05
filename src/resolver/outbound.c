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
static void dot_mark_failed(elpis_worker_t *w, const elpis_addr_t *server);
static void dot_timeout(elpis_worker_t *w, elpis_outq_t *q);

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
    elpis_dot_fini(w);
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

/*
 * Does this query carry an EDNS Client Subnet option, and with what?  Returns
 * 1 with q->ecs filled in.  Sets q->ecs_local instead when the resolution has
 * no subnet to give a server that would have been sent one.
 */
static int ecs_decide(elpis_worker_t *w, elpis_outq_t *q,
                      const elpis_task_t *t, const elpis_infra_info_t *inf)
{
    const elpis_conf_t *c = &w->ctx->conf;

    if (!c->ecs)
        return 0;
    /*
     * Never to the root or a TLD, which only ever refer onwards: a subnet
     * there tells them something for nothing.  A forwarder is asked for
     * everything, so it is asked with a subnet for everything.
     */
    if (!t->forwarding && (!t->have_deleg || t->deleg.zone.labels < 2u))
        return 0;
    /* A QNAME-minimisation probe is after a delegation, not an answer. */
    if (t->qmin_probe)
        return 0;
    if (!elpis_conf_ecs_zone_ok(c, &t->qname))
        return 0;
    if (inf->ecs_off_until != 0 && elpis_cached_now_s() < inf->ecs_off_until)
        return 0;

    memset(&q->ecs, 0, sizeof q->ecs);
    switch (c->ecs_ip_type) {
    case ELPIS_ECS_TYPE_NONE:
        q->ecs.family = ELPIS_ECS_IPV4;         /* 0.0.0.0/0 */
        return 1;
    case ELPIS_ECS_TYPE_THIS:
        return elpis_selfinfo_ecs(w->ctx, &q->ecs);
    default:
        if (t->ecs.family == 0) {
            q->ecs_local = 1;
            return 0;
        }
        q->ecs = t->ecs;
        q->ecs.scope = 0;
        return 1;
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
    /*
     * Not over TCP, where the handshake already shuts out an off-path
     * attacker and the entropy buys nothing.  Not for a name under
     * caps-exempt:, whose servers answer a randomised name without knowing
     * it for theirs.  Not to a server known to drop randomised names.  And
     * not, once, to a server that has timed out without ever answering one
     * -- that is the test for the last case.  An exempt name is neither, so
     * it teaches the server's infra entry nothing about 0x20.
     */
    if (c->use_0x20 && !q->over_tcp && !(inf->flags & ELPIS_INF_NO_0X20) &&
        !elpis_conf_caps_exempt(c, &t->qname)) {
        if ((inf->flags & ELPIS_INF_0X20_OK) || inf->timeouts == 0) {
            apply_0x20(q->qname_wire, q->qnamelen);
            q->used_0x20 = 1;
        } else {
            q->caps_test = 1;
        }
    }

    if (elpis_bld_question_raw(&b, q->qname_wire, q->qnamelen,
                               q->qtype, q->qclass) != ELPIS_OK)
        return 0;

    if (inf->edns_state != ELPIS_EDNS_NO) {
        uint16_t bufsize = elpis_addr_family(&q->server) == AF_INET6
                               ? c->edns_buffer6 : c->edns_buffer4;
        if (inf->edns_state == ELPIS_EDNS_FALLBACK && inf->edns_max)
            bufsize = inf->edns_max;
        if (q->over_tcp)
            bufsize = ELPIS_MAX_UDP;

        elpis_edns_init(&e, bufsize, w->ctx->conf.dnssec ? 1 : 0);
        /* Over DoT, padded to a multiple of 128 bytes (RFC 8467), so the
         * length gives away less of the name. */
        if (q->over_dot)
            e.pad_to = 128;
        if (c->use_cookies) {
            elpis_cookie_client(&q->server, q->cookie);
            memcpy(e.cookie, q->cookie, 8);
            e.cookie_len = 8;
            /* Replay the server half we were given last time, if any. */
            if ((inf->flags & ELPIS_INF_COOKIE_OK) &&
                !(inf->flags & ELPIS_INF_COOKIE_ROAM) && inf->cookie_len > 0 &&
                (size_t)inf->cookie_len + 8u <= sizeof e.cookie) {
                memcpy(e.cookie + 8, inf->cookie, inf->cookie_len);
                e.cookie_len = (uint8_t)(8u + inf->cookie_len);
                q->sent_server_cookie = 1;
            }
            e.have_cookie = 1;
            q->used_cookie = 1;
        }
        q->ecs_local = 0;
        if (ecs_decide(w, q, t, inf)) {
            e.ecs = q->ecs;
            e.have_ecs = 1;
        }
        if (elpis_edns_write(&b, &e, 0) == ELPIS_OK) {
            q->used_edns = 1;
            q->edns_size = bufsize;
            q->used_ecs  = e.have_ecs;
            if (q->used_ecs)
                elpis_stat_inc(&w->stats.ecs_sent, 1);
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
    elpis_dot_detach(q);
    if (q->tcpfd >= 0) {
        elpis_loop_del(w->loop, &q->tcpev);
        close(q->tcpfd);
        q->tcpfd = -1;
    }
    elpis_free(q->txbuf);
    elpis_free(q->rxbuf);
    if (q->task != NULL && q->task->out == q)
        q->task->out = NULL;
    if (q->task != NULL && q->task->race == q)
        q->task->race = NULL;
    elpis_free(q);
}

/*
 * Take q off its task.  Whatever else the task still has out becomes its one
 * outstanding query, and is returned.
 */
static elpis_outq_t *out_unhook(elpis_task_t *t, elpis_outq_t *q)
{
    elpis_outq_t *other = NULL;

    if (t->out == q)
        other = t->race;
    else if (t->race == q)
        other = t->out;
    t->out  = other;
    t->race = NULL;
    q->task = NULL;
    return other;
}

/* Nobody wants the answer now, but its round trip is still worth measuring. */
static void out_to_probe(elpis_outq_t *q)
{
    q->task  = NULL;
    q->probe = 1;
}

void elpis_out_cancel(elpis_task_t *t)
{
    if (t->race != NULL) {
        out_to_probe(t->race);
        t->race = NULL;
    }
    if (t->out != NULL) {
        t->out->task = NULL;
        elpis_out_free(t->w, t->out);
        t->out = NULL;
    }
}

static int start_tcp(elpis_task_t *t, elpis_outq_t *q, const uint8_t *msg,
                     size_t msglen);
static void dot_test(elpis_worker_t *w, const elpis_outq_t *orig,
                     const uint8_t *msg, size_t len, const elpis_task_t *t);

/* The query length-prefixed in q->txbuf, as DoT carries it. */
static int dot_frame(elpis_outq_t *q, const uint8_t *msg, size_t len)
{
    q->txbuf = (uint8_t *)elpis_malloc(len + 2);
    if (q->txbuf == NULL)
        return -1;
    elpis_put16(q->txbuf, (uint16_t)len);
    memcpy(q->txbuf + 2, msg, len);
    q->txlen = len + 2;
    return 0;
}

/*
 * Build and send t's current question to one server, with its own ID, port,
 * 0x20 pattern and timer.  The caller decides what the query is to the task.
 * With udp_only set, a server that needs TCP is refused rather than dialled.
 * With no_dot set, it goes plain even to a server that takes DoT.
 *
 * authoritative-dot: decides here between plain and DoT, from the server's
 * infra entry (elpis_infra_dot_mode): a server known to take DoT gets the
 * query over DoT only; one due a test gets it plain, as always, and a copy
 * over DoT that nobody waits for, whose answer or failure is the test.
 * Forwarders and stub zones are configuration and are left as they are, and
 * so are races and probes, which are about measuring the plain path.
 */
static elpis_outq_t *out_start(elpis_task_t *t, const elpis_addr_t *server,
                               int force_tcp, int udp_only, int no_dot)
{
    elpis_worker_t *w = t->w;
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_outq_t *q;
    elpis_infra_info_t inf;
    size_t len;
    int sockidx, mode = ELPIS_DOTM_PLAIN;
    ssize_t sent;
    uint32_t timeout;

    elpis_infra_get(w->ctx->infra, server, &inf);
    if (udp_only && (force_tcp || (inf.flags & ELPIS_INF_TCP_ONLY)))
        return NULL;

again:
    if (c->adot && !udp_only && !no_dot && !t->forwarding &&
        !t->deleg_from_route) {
        mode = elpis_infra_dot_mode(&inf, elpis_cached_now_s());
        /* No room for another connection: plain this once, no failure. */
        if (mode == ELPIS_DOTM_USE && !elpis_dot_can_send(w, server))
            mode = ELPIS_DOTM_PLAIN;
    }

    q = (elpis_outq_t *)elpis_calloc(1, sizeof *q);
    if (q == NULL)
        return NULL;
    q->tcpfd = -1;
    q->task   = t;
    q->w      = w;
    q->server = *server;
    q->qtype  = t->qtype;
    q->qclass = t->qclass;
    q->over_tcp = force_tcp ? 1u : 0u;
    q->id = (uint16_t)elpis_random_u32();

    if (force_tcp || (inf.flags & ELPIS_INF_TCP_ONLY))
        q->over_tcp = 1;
    if (mode == ELPIS_DOTM_USE) {
        q->over_dot = 1;
        q->over_tcp = 1;
    }

    if (q->over_dot) {
        sockidx = 0;                    /* not matched by socket */
    } else {
        sockidx = pick_socket(w, elpis_addr_family(server));
        if (sockidx < 0) {
            elpis_free(q);
            return NULL;
        }
    }
    q->sockidx = sockidx;

    len = build_query(w, q, t, w->txbuf, ELPIS_MAX_MSG, &inf);
    if (len == 0) {
        elpis_free(q);
        return NULL;
    }

    q->sent_ms = elpis_cached_now_ms();

    if (q->over_dot) {
        if (dot_frame(q, w->txbuf, len) != 0 ||
            elpis_dot_send(w, q, t->have_deleg ? &t->deleg.zone : NULL) != 0) {
            /* Could not get a connection after all: plain, built afresh. */
            elpis_free(q->txbuf);
            elpis_free(q);
            no_dot = 1;
            mode = ELPIS_DOTM_PLAIN;
            goto again;
        }
    } else if (q->over_tcp) {
        if (start_tcp(t, q, w->txbuf, len) != ELPIS_OK) {
            elpis_free(q);
            return NULL;
        }
        out_register(w, q);
    } else {
        sent = elpis_sock_send(w->osock[sockidx].fd, w->txbuf, len, server, NULL);
        if (sent != (ssize_t)len) {
            char ab[80];
            elpis_debug("send to %s failed: %s",
                        elpis_addr_str(server, ab, sizeof ab), strerror(errno));
            elpis_free(q);
            return NULL;
        }
        out_register(w, q);
    }

    elpis_stat_inc(&w->stats.upstream_queries, 1);
    if (mode == ELPIS_DOTM_TEST)
        dot_test(w, q, w->txbuf, len, t);

    /*
     * Wait a little longer than this server's measured round trip -- and over
     * TCP, one round trip more, for the handshake that has to finish before
     * the query is even sent.  Without it a server more than about 100 ms
     * away could not answer over TCP inside its own UDP allowance.  A DoT
     * connection still in its handshake needs one more: TCP, then TLS.
     */
    timeout = inf.srtt + 4u * inf.rttvar;
    if (q->over_tcp)
        timeout += inf.srtt;
    if (q->over_dot && q->conn != NULL && !q->conn->open)
        timeout += inf.srtt;
    /*
     * A server that has never answered or timed out has no round trip to go
     * on, and the formula turns the starting guess into 376 + 4 x 188 =
     * 1128 ms.  Wait the guess itself instead, as Unbound does.  Every cold
     * lookup meets servers like this, and on a path that drops one packet in
     * twenty, each loss cost a client more than a second before the next
     * server was tried.  A server genuinely further away than this loses its
     * first answer and is tried again with the doubled estimate.
     */
    if (inf.queries == 0)
        timeout = q->over_tcp ? 2u * ELPIS_RTT_INITIAL : ELPIS_RTT_INITIAL;
    if (timeout < 250u)
        timeout = 250u;
    if (timeout > c->query_timeout_ms * 4u)
        timeout = c->query_timeout_ms * 4u;
    if (timeout > 5000u)
        timeout = 5000u;
    /*
     * Past the first round through a delegation, hold each attempt to
     * query-timeout.  Every timeout doubles the server's estimate, and left
     * to that a zone whose servers are all down took sixteen seconds to
     * fail instead of a few.
     */
    if (t->rounds > 0 && timeout > c->query_timeout_ms)
        timeout = c->query_timeout_ms;
    /*
     * The same for a server that timed out the last time it was asked.  Its
     * estimate has doubled with every miss, and waiting that out cost 4.8 s
     * on one of www.kemendesa.go.id's dead servers, in the first round, with
     * nothing else left to try.  If it is merely slow, the late listener
     * below still hears it, and its estimate comes back down.
     */
    if (inf.timeouts > 0 && timeout > c->query_timeout_ms)
        timeout = c->query_timeout_ms;
    q->timeout_ms = timeout;
    elpis_timer_add(w->loop, &q->timer, timeout, out_timeout, q);

    /*
     * The first query to a held server after its hold runs out is the probe.
     * It takes the next hold now, before it is answered, or every query in
     * the next second or so would be let through behind it.  An answer
     * clears the hold whenever it comes.
     */
    if (c->server_hold_s != 0 &&
        elpis_infra_probe_due(&inf, q->qtype, elpis_cached_now_s()))
        elpis_infra_hold(w->ctx->infra, server,
                         elpis_cached_now_s() + c->server_hold_s);

    return q;
}

int elpis_out_send(elpis_task_t *t, const elpis_addr_t *server, int force_tcp)
{
    elpis_outq_t *q;

    elpis_out_cancel(t);
    q = out_start(t, server, force_tcp, 0, 0);
    if (q == NULL)
        return ELPIS_ERR;
    t->out = q;
    return ELPIS_OK;
}

int elpis_out_race(elpis_task_t *t, const elpis_addr_t *server)
{
    elpis_outq_t *q;

    /* Only beside a UDP query: TCP has its own handshake to wait for. */
    if (t->out == NULL || t->out->over_tcp || t->race != NULL)
        return ELPIS_ERR;
    q = out_start(t, server, 0, 1, 1);
    if (q == NULL)
        return ELPIS_ERR;
    t->race = q;
    elpis_stat_inc(&t->w->stats.races, 1);
    return ELPIS_OK;
}

int elpis_out_probe(elpis_task_t *t, const elpis_addr_t *server)
{
    elpis_outq_t *q = out_start(t, server, 0, 1, 1);

    if (q == NULL)
        return ELPIS_ERR;
    out_to_probe(q);
    elpis_stat_inc(&t->w->stats.races, 1);
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

/*
 * Settle whether this server takes case-randomised names, from what it has
 * answered so far -- read now, not as it stood when the query left.  The two
 * kinds of answer can arrive in either order: a server that is merely slow
 * lets its randomised query time out, is re-asked as-is, and then answers
 * both.  One randomised answer is proof enough that 0x20 is not the problem,
 * and overrides a lowercase one that happened to land first.
 *
 * A lossy server can still be misjudged -- a randomised query lost, then a
 * lowercase one answered -- and keeps its names in lowercase until its infra
 * entry goes.  That costs it the 0x20 bits and nothing else; the ID, port and
 * cookie checks are unchanged.
 */
static void learn_0x20(elpis_worker_t *w, const elpis_outq_t *q)
{
    elpis_infra_info_t inf;

    elpis_infra_get(w->ctx->infra, &q->server, &inf);
    if (q->used_0x20) {
        if (!(inf.flags & ELPIS_INF_0X20_OK))
            elpis_infra_set_flag(w->ctx->infra, &q->server,
                                 ELPIS_INF_0X20_OK, 1);
        if (inf.flags & ELPIS_INF_NO_0X20)
            elpis_infra_set_flag(w->ctx->infra, &q->server,
                                 ELPIS_INF_NO_0X20, 0);
    } else if (!(inf.flags & (ELPIS_INF_0X20_OK | ELPIS_INF_NO_0X20))) {
        char ab[80];
        elpis_infra_set_flag(w->ctx->infra, &q->server, ELPIS_INF_NO_0X20, 1);
        elpis_logf_rl(ELPIS_LOG_INFO, ELPIS_DROP__MAX + 1, __FILE__, __LINE__,
                      "%s answers only names sent in lowercase; "
                      "case randomisation is off for it",
                      elpis_addr_str(&q->server, ab, sizeof ab));
    }
}

/*
 * What the server made of the subnet it was sent.  Returns 1 when the reply
 * cannot be used and the question should go again without one; the server
 * is already marked, so the next query to it carries none.
 */
static int ecs_answer(elpis_worker_t *w, elpis_outq_t *q, const elpis_msg_t *m)
{
    unsigned rcode = elpis_msg_rcode(m);
    uint32_t off = elpis_cached_now_s() + ELPIS_ECS_OFF_S;

    /* Truncated, and often without its OPT: the answer over TCP will say. */
    if (m->hdr.flags & ELPIS_FLAG_TC)
        return 0;
    if (rcode == ELPIS_RC_FORMERR || rcode == ELPIS_RC_NOTIMP) {
        elpis_infra_ecs_off(w->ctx->infra, &q->server, off);
        return 1;
    }
    if (!m->have_ecs) {
        /*
         * A server that tailors its answers says how, so this one does not,
         * and the next hour of queries to it can keep the subnet to
         * themselves.  Not with ecs-ip-type: none, though: that /0 is there
         * to stop a forwarder adding a subnet of its own, whether or not it
         * says it read it.
         */
        if ((rcode == ELPIS_RC_NOERROR || rcode == ELPIS_RC_NXDOMAIN) &&
            w->ctx->conf.ecs_ip_type != ELPIS_ECS_TYPE_NONE)
            elpis_infra_ecs_off(w->ctx->infra, &q->server, off);
        return 0;
    }
    /*
     * FAMILY, SOURCE and ADDRESS have to come back as they went, or the
     * answer is for some other subnet and is not used (RFC 7871).  A /0 is a
     * /0 in any family; some servers echo it as family 0.
     */
    if (m->ecs_bad ||
        (!(q->ecs.source == 0 && m->ecs.source == 0) &&
         !elpis_ecs_same_subnet(&m->ecs, &q->ecs))) {
        char ab[80], sb[64], rb[64];
        elpis_logf_rl(ELPIS_LOG_INFO, ELPIS_DROP_EDNS, __FILE__, __LINE__,
                      "ecs: %s answered for %s when asked for %s; asking "
                      "again without a subnet",
                      elpis_addr_str(&q->server, ab, sizeof ab),
                      m->ecs_bad ? "a malformed subnet"
                                 : elpis_ecs_str(&m->ecs, rb, sizeof rb),
                      elpis_ecs_str(&q->ecs, sb, sizeof sb));
        elpis_infra_ecs_off(w->ctx->infra, &q->server, off);
        return 1;
    }
    /* A SCOPE longer than what was sent cannot be told apart from it. */
    q->ecs_scope = m->ecs.scope < q->ecs.source ? m->ecs.scope : q->ecs.source;
    if (q->ecs_scope > 0)
        elpis_stat_inc(&w->stats.ecs_tailored, 1);
    return 0;
}

static void handle_message(elpis_worker_t *w, elpis_outq_t *q,
                           const elpis_msg_t *m)
{
    elpis_task_t *t = q->task;
    elpis_outq_t *other;
    unsigned rcode = elpis_msg_rcode(m);
    uint32_t rtt;
    int ecs_retry = 0;

    if (t == NULL && !q->probe) {
        elpis_out_free(w, q);
        return;
    }

    /* Sent plain because the same question over DoT went unanswered, and
     * plain got through: DoT is what failed. */
    if (q->dot_safety)
        dot_mark_failed(w, &q->server);

    w->last_answer_ms = elpis_cached_now_ms();
    rtt = (uint32_t)(w->last_answer_ms - q->sent_ms);
    elpis_infra_rtt_ok(w->ctx->infra, &q->server, rtt);
    absorb_cookie(w, q, m);
    if (q->used_0x20 || q->caps_test)
        learn_0x20(w, q);

    if (q->used_edns) {
        if (m->have_opt) {
            elpis_infra_set_edns(w->ctx->infra, &q->server, ELPIS_EDNS_YES,
                                 q->edns_size);
        } else if ((elpis_msg_rcode(m) == ELPIS_RC_FORMERR ||
                    elpis_msg_rcode(m) == ELPIS_RC_NOTIMP) && !q->used_ecs) {
            /*
             * The peer does not understand EDNS; remember and retry plain.
             * Not when the query carried a subnet: that is the likelier
             * thing to have upset it, and ecs_answer() tries without it
             * first, rather than give up on EDNS -- and DNSSEC -- for good.
             */
            elpis_infra_set_edns(w->ctx->infra, &q->server, ELPIS_EDNS_NO, 0);
        }
    }
    if (q->used_ecs)
        ecs_retry = ecs_answer(w, q, m);

    /* A probe was sent to be measured, and now it has been. */
    if (t == NULL) {
        elpis_out_free(w, q);
        return;
    }

    /*
     * Two servers were asked.  The first usable answer is the one the task
     * gets, and the other query stays out as a probe so its server is still
     * measured.  A server with nothing to give -- SERVFAIL, REFUSED, a
     * complaint about the query -- is not a reason to stop waiting for the
     * other one.
     */
    other = out_unhook(t, q);
    if (other != NULL) {
        if (rcode != ELPIS_RC_NOERROR && rcode != ELPIS_RC_NXDOMAIN &&
            rcode != ELPIS_RC_BADCOOKIE && !(m->hdr.flags & ELPIS_FLAG_TC)) {
            if (rcode == ELPIS_RC_REFUSED)
                elpis_infra_set_flag(w->ctx->infra, &q->server,
                                     ELPIS_INF_LAME, 1);
            elpis_task_note_answered(t, &q->server);
            elpis_out_free(w, q);
            return;
        }
        out_to_probe(other);
        t->out = NULL;
    }

    /* The subnet was refused or garbled: the same question, without it. */
    if (ecs_retry) {
        elpis_addr_t server = q->server;
        int tcp = q->over_tcp;
        elpis_out_free(w, q);
        t->sends++;
        if (elpis_task_resend(t, &server, tcp) != ELPIS_OK)
            elpis_resolver_on_error(t, NULL, ELPIS_EDE_NETWORK_ERROR);
        return;
    }

    /*
     * BADCOOKIE means "resend with the cookie I just gave you"; we have
     * already stored it, so a single retry to the same server is correct.
     *
     * Single per query, that is.  This used to test the task's send count,
     * so only a task's very first query was ever retried: behind a QNAME
     * minimisation probe or a referral, BADCOOKIE was taken as the server
     * failing, and the next one was tried instead.
     *
     * And if it was our replay of its own cookie that it refused, it is one
     * of many machines behind one address; stop replaying to it.
     */
    if (rcode == ELPIS_RC_BADCOOKIE && q->used_cookie) {
        elpis_addr_t server = q->server;
        if (q->sent_server_cookie)
            elpis_infra_set_flag(w->ctx->infra, &server,
                                 ELPIS_INF_COOKIE_ROAM, 1);
        if (!q->cookie_retry) {
            elpis_out_free(w, q);
            t->sends++;
            if (elpis_task_resend(t, &server, 0) != ELPIS_OK)
                elpis_resolver_on_error(t, NULL, ELPIS_EDE_NETWORK_ERROR);
            else if (t->out != NULL)
                t->out->cookie_retry = 1;
            return;
        }
    }

    /* Truncated over UDP: repeat the query over TCP (RFC 7766). */
    if ((m->hdr.flags & ELPIS_FLAG_TC) && !q->over_tcp &&
        w->ctx->conf.tcp_upstream) {
        elpis_addr_t server = q->server;
        elpis_out_free(w, q);
        elpis_stat_inc(&w->stats.truncated, 1);
        if (elpis_task_resend(t, &server, 1) != ELPIS_OK)
            elpis_resolver_on_error(t, NULL, ELPIS_EDE_NETWORK_ERROR);
        return;
    }

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

/*
 * How long to hold `q`'s server if this timeout makes it due: 0 unless some
 * other server has answered since the query went out.  When nobody has, the
 * silence is as likely to be this host's own link, and a hold would outlast
 * the outage by up to server-hold-down seconds for every server that was
 * being asked when it began.
 */
static uint32_t hold_for(const elpis_worker_t *w, const elpis_outq_t *q)
{
    if (w->last_answer_ms < q->sent_ms)
        return 0;
    return w->ctx->conf.server_hold_s;
}

/*
 * Tell the status page a server has been held, and on whose behalf.  The
 * query may be a child lookup's -- a nameserver's address, a DNSKEY -- so the
 * client is the one at the top of the chain, if one is still waiting.
 */
static void note_hold(elpis_worker_t *w, const elpis_outq_t *q,
                      const elpis_task_t *t)
{
    elpis_tmhold_t h;
    elpis_infra_info_t inf;
    const elpis_task_t *top = t;

    if (!elpis_tm_enabled)
        return;
    elpis_infra_get(w->ctx->infra, &q->server, &inf);
    memset(&h, 0, sizeof h);
    h.server = &q->server;
    h.streak = inf.silent_since;
    h.types  = inf.silent_types;
    h.now    = elpis_cached_now_s();
    if (t == NULL) {
        h.who = "nobody waiting";
    } else {
        while (top->parent != NULL)
            top = top->parent;
        if (t->have_deleg)
            h.zone = &t->deleg.zone;
        h.qname = &top->orig_qname;
        h.qtype = top->orig_qtype;
        if (top->has_client)
            h.client = &top->client;
        else
            h.who = top->prefetch ? "prefetch" :
                    top->warming  ? "warming"  : "internal";
    }
    elpis_tm_held(&h);
}

static void out_timeout(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_outq_t *q = (elpis_outq_t *)tm->data;
    elpis_worker_t *w = q->w;
    elpis_task_t *t = q->task;
    int others;

    if (q->over_dot) {
        dot_timeout(w, q);
        return;
    }
    if (t == NULL && !q->probe)
        return;
    if (q->late) {                      /* it really was not coming */
        elpis_out_free(w, q);
        return;
    }

    if (elpis_infra_timeout(w->ctx->infra, &q->server, q->qtype,
                            elpis_cached_now_s(), hold_for(w, q)))
        note_hold(w, q, t);
    elpis_stat_inc(&w->stats.timeouts, 1);

    others = (t != NULL && out_unhook(t, q) != NULL);

    /*
     * Keep listening for one more timeout's worth.  A server slower than its
     * timer -- one never measured is given 376 ms, and intel.com's answered
     * this host in 250 to 410 when it answered at all -- used to have its
     * reply thrown away as unmatched, so it was never measured and every
     * lookup timed out on it again.  Kept as a probe, the late answer is
     * measured, and the next query waits for it properly.  TCP is closed as
     * before: a connection with nobody reading it would only wake the loop.
     */
    if (!q->over_tcp) {
        out_to_probe(q);
        q->late = 1;
        elpis_timer_add(w->loop, &q->timer,
                        q->timeout_ms > 2000u ? 2000u : q->timeout_ms,
                        out_timeout, q);
    }

    /*
     * A silent probe, or one of two racing queries while the other is still
     * out: the server is marked, and nothing else changes.  Moving on to the
     * next server is for when nobody is left to answer.
     */
    if (t == NULL || others) {
        elpis_tm_timeout(&w->tm, &q->server);
        if (q->over_tcp)
            elpis_out_free(w, q);
        return;
    }
    elpis_resolver_on_timeout(t, q);
    if (q->over_tcp)
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
    if (t != NULL) {
        t->out = NULL;
        q->task = NULL;
        if (elpis_infra_timeout(w->ctx->infra, &q->server, q->qtype,
                                elpis_cached_now_s(), hold_for(w, q)))
            note_hold(w, q, t);
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

/* ------------------------------------------------------------------ */
/* DNS over TLS                                                        */
/* ------------------------------------------------------------------ */

static void dot_mark_failed(elpis_worker_t *w, const elpis_addr_t *server)
{
    const elpis_conf_t *c = &w->ctx->conf;
    uint32_t now = elpis_cached_now_s();
    int st = elpis_infra_dot_fail(w->ctx->infra, server, now,
                                  ELPIS_MIN(c->adot_retry_s, c->adot_ttl_s),
                                  c->adot_max_try);
    elpis_stat_inc(&w->stats.dot_fail_timeout, 1);
    elpis_tm_dot_failed(server, st, now);
}

/*
 * The test: the plain query just sent, again over DoT, as a probe nobody
 * waits for.  Its answer makes the server available; a connection that
 * fails, or an answer that never comes, makes it failed.  One test per
 * server at a time, across the workers (the claim), and none while this
 * worker already has a connection there.
 */
static void dot_test(elpis_worker_t *w, const elpis_outq_t *orig,
                     const uint8_t *msg, size_t len, const elpis_task_t *t)
{
    elpis_outq_t *p;

    if (elpis_dot_find(w, &orig->server) != NULL ||
        !elpis_dot_can_send(w, &orig->server) ||
        !elpis_infra_dot_claim(w->ctx->infra, &orig->server,
                               elpis_cached_now_s()))
        return;

    p = (elpis_outq_t *)elpis_calloc(1, sizeof *p);
    if (p == NULL)
        return;
    p->tcpfd    = -1;
    p->w        = w;
    p->server   = orig->server;
    p->id       = orig->id;
    p->qtype    = orig->qtype;
    p->qclass   = orig->qclass;
    p->qnamelen = orig->qnamelen;
    memcpy(p->qname_wire, orig->qname_wire, orig->qnamelen);
    memcpy(p->cookie, orig->cookie, sizeof p->cookie);
    p->used_edns   = orig->used_edns;
    p->edns_size   = orig->edns_size;
    p->used_cookie = orig->used_cookie;
    p->sent_server_cookie = orig->sent_server_cookie;
    p->used_ecs    = orig->used_ecs;
    p->ecs_local   = orig->ecs_local;
    p->ecs         = orig->ecs;
    p->probe    = 1;
    p->over_dot = 1;
    p->over_tcp = 1;
    p->dot_test = 1;
    p->sent_ms  = elpis_cached_now_ms();

    if (dot_frame(p, msg, len) != 0 ||
        elpis_dot_send(w, p, t->have_deleg ? &t->deleg.zone : NULL) != 0) {
        elpis_free(p->txbuf);
        elpis_free(p);
        return;
    }
    elpis_stat_inc(&w->stats.dot_tests, 1);
    /* The connection has its own deadline; this one covers an open
     * connection that never answers. */
    p->timeout_ms = ELPIS_DOT_HANDSHAKE_MS + 2000u;
    elpis_timer_add(w->loop, &p->timer, p->timeout_ms, out_timeout, p);
}

/*
 * A DoT query's timer ran out.  A test that went unanswered is a failed
 * test.  A query someone is waiting on is asked again, plain, of the same
 * server -- the safety net -- and if that is answered, DoT is marked failed
 * (handle_message).  The silence is not held against the server itself: that
 * is for the plain query's own timer to judge.
 */
static void dot_timeout(elpis_worker_t *w, elpis_outq_t *q)
{
    elpis_task_t *t = q->task;
    elpis_addr_t server = q->server;
    elpis_outq_t *np;

    if (t == NULL) {
        if (q->dot_test)
            dot_mark_failed(w, &server);
        elpis_out_free(w, q);
        return;
    }
    if (t->out != q) {                  /* not the task's query: drop it */
        q->task = NULL;
        elpis_out_free(w, q);
        return;
    }
    elpis_stat_inc(&w->stats.dot_safety, 1);
    np = out_start(t, &server, 0, 0, 1);
    t->out = NULL;
    q->task = NULL;
    if (np == NULL) {
        elpis_resolver_on_error(t, q, ELPIS_EDE_NETWORK_ERROR);
        elpis_out_free(w, q);
        return;
    }
    np->dot_safety = 1;
    t->out = np;
    elpis_out_free(w, q);
}

void elpis_out_dot_message(elpis_worker_t *w, elpis_outq_t *q,
                           const elpis_msg_t *m)
{
    const elpis_conf_t *c = &w->ctx->conf;
    uint32_t now = elpis_cached_now_s();
    elpis_infra_info_t inf;

    elpis_timer_del(w->loop, &q->timer);
    elpis_stat_inc(&w->stats.dot_answers, 1);
    if (q->dot_test)
        elpis_stat_inc(&w->stats.dot_tests_ok, 1);
    /*
     * Any answer at all, even SERVFAIL, shows DoT works, and keeps it
     * standing for another authoritative-dot-ttl.  Renewed at most once a
     * minute, not written on every answer.
     */
    elpis_infra_get(w->ctx->infra, &q->server, &inf);
    if (inf.dot_state != ELPIS_DOT_AVAILABLE ||
        inf.dot_until < now + c->adot_ttl_s - 60u)
        elpis_infra_dot_ok(w->ctx->infra, &q->server, now, c->adot_ttl_s);
    handle_message(w, q, m);
}

/*
 * q's connection is gone.  A test is over (dot.c has marked the server).  A
 * query someone waits on goes plain -- or, when a connection that had worked
 * was only lost, over DoT once more first.
 */
void elpis_out_dot_failed(elpis_worker_t *w, elpis_outq_t *q, int lost)
{
    elpis_task_t *t = q->task;
    elpis_addr_t server = q->server;
    elpis_outq_t *np;
    int again = lost && !q->dot_resent;

    if (t == NULL || t->out != q) {
        q->task = NULL;
        elpis_out_free(w, q);
        return;
    }
    if (lost)
        elpis_stat_inc(&w->stats.dot_lost, 1);
    np = out_start(t, &server, 0, 0, !again);
    t->out = NULL;
    q->task = NULL;
    if (np == NULL) {
        elpis_resolver_on_error(t, q, ELPIS_EDE_NETWORK_ERROR);
        elpis_out_free(w, q);
        return;
    }
    if (np->over_dot)
        np->dot_resent = 1;
    t->out = np;
    elpis_out_free(w, q);
}
