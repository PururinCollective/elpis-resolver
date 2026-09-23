/*
 * server.c -- the client-facing side: UDP and TCP listeners, the cache fast
 * path, and response assembly.
 *
 * The fast path is deliberately short.  On a message-cache hit the work is:
 * parse the header and question, check the ACL, hash the key, and write
 * header + echoed question + one memcpy of the cached blob with the TTLs
 * patched in place.  No record is re-encoded and no name is re-compressed.
 */
#include "elpis/resolver.h"
#include "elpis/sock.h"
#include "elpis/rdata.h"
#include "elpis/simd.h"
#include "elpis/log.h"
#include "elpis/telemetry.h"

#include <errno.h>
#include <unistd.h>

static void tcp_close(elpis_tcpconn_t *c);

/* Kick off a background refresh of the name just served from cache. */
static void elpis_prefetch_start(elpis_worker_t *w, const elpis_msg_t *m,
                                 uint8_t kflags)
{
    elpis_task_t *t;

    /* Never let refresh work crowd out real resolutions. */
    if (w->n_tasks > 4096)
        return;

    t = elpis_task_new(w);
    if (t == NULL)
        return;
    t->qname = m->qname;
    elpis_name_lower(&t->qname);
    t->qtype    = m->qtype;
    t->qclass   = m->qclass;
    t->prefetch = 1;
    /*
     * The refresh has no client, but it has to produce the same cache entry
     * the client path would, so the DO and CD bits of the key are carried
     * over.  has_client stays clear: nothing is sent anywhere.
     */
    t->client_do = (kflags & ELPIS_MK_DO) ? 1u : 0u;
    t->client_cd = (kflags & ELPIS_MK_CD) ? 1u : 0u;
    elpis_stat_inc(&w->stats.prefetches, 1);
    elpis_task_start(t);
}

/* ------------------------------------------------------------------ */
/* Response assembly                                                   */
/* ------------------------------------------------------------------ */

static size_t client_budget(const elpis_task_t *t)
{
    const elpis_conf_t *c = &t->w->ctx->conf;
    size_t b;

    if (t->from_tcp)
        return ELPIS_MAX_MSG;
    b = t->client_edns ? t->client_bufsize : ELPIS_MAX_UDP_LEGACY;
    if (b < 512)
        b = 512;
    if (b > c->max_udp_size_reply)
        b = c->max_udp_size_reply;
    return b;
}

static void fill_edns(elpis_task_t *t, elpis_edns_t *e, unsigned rcode)
{
    const elpis_conf_t *c = &t->w->ctx->conf;

    elpis_edns_init(e, c->edns_buffer, t->client_do);
    if (c->nsid[0] != '\0') {
        e->nsid = c->nsid;
        e->want_nsid = 1;
    }
    if (t->ede >= 0 && t->rcode != ELPIS_RC_NOERROR)
        e->ede_code = t->ede;
    else if (t->sec == ELPIS_SEC_BOGUS)
        e->ede_code = ELPIS_EDE_DNSSEC_BOGUS;

    if (c->use_cookies && t->client_cookie_len >= 8) {
        uint8_t full[24];
        elpis_cookie_server(t->client_cookie, &t->client, full);
        memcpy(e->cookie, full, sizeof full);
        e->cookie_len = (uint8_t)sizeof full;
        e->have_cookie = 1;
    }
    (void)rcode;
}

/*
 * Send a reply, and say so when it does not go.
 *
 * This used to return a status that every caller ignored, which meant a
 * resolver on a host that could not route the answer looked exactly like one
 * that was not listening: the query arrives, the work happens, and the reply
 * evaporates with nothing in the log.  A failed send is now counted and
 * reported with the reason and both addresses involved.
 */
static int send_udp(elpis_worker_t *w, int fd, const uint8_t *buf, size_t len,
                    const elpis_addr_t *to, const elpis_addr_t *from)
{
    ssize_t n = elpis_sock_send(fd, buf, len, to, from);
    int err;

    if (n == (ssize_t)len) {
        elpis_tm_bytes(&w->tm, 0, len);
        return ELPIS_OK;
    }
    err = errno;

    elpis_stat_inc(&w->stats.dropped, 1);
    {
        char db[80], sb[80];
        elpis_addr_str(to, db, sizeof db);
        if (from != NULL && from->len != 0)
            elpis_addr_str(from, sb, sizeof sb);
        else
            elpis_strlcpy(sb, "(kernel choice)", sizeof sb);
        elpis_drop_log_quiet(ELPIS_DROP_SENDFAIL, to, NULL, 0, NULL);
        elpis_logf_rl(ELPIS_LOG_WARN, ELPIS_DROP_SENDFAIL, __FILE__, __LINE__,
                      "could not send the reply to %s from %s: %s -- the "
                      "query arrived but this host cannot route the answer "
                      "back", db, sb, strerror(err));
    }
    return ELPIS_ERR;
}

static int tcp_queue(elpis_tcpconn_t *c, const uint8_t *buf, size_t len);

/* Build the reply for a completed task and hand it to the transport. */
void elpis_task_respond(elpis_task_t *t)
{
    elpis_worker_t *w = t->w;
    uint64_t now_ms;
    elpis_bld_t b;
    elpis_edns_t e;
    uint16_t flags;
    size_t budget = client_budget(t);
    unsigned i;
    elpis_bld_mark_t mark;
    int truncated = 0;

    if (!t->has_client)
        return;

    now_ms = elpis_cached_now_ms();
    elpis_tm_observe(&w->tm,
                     (now_ms > t->start_ms ? now_ms - t->start_ms : 0u) * 1000u,
                     !t->from_cache);
    elpis_tm_answer(&w->tm, &t->orig_qname, &t->client, t->rcode,
                    t->sec == ELPIS_SEC_BOGUS);

    flags = (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA);
    if (t->client_rd)
        flags |= ELPIS_FLAG_RD;
    if (t->client_cd)
        flags |= ELPIS_FLAG_CD;
    if (t->sec == ELPIS_SEC_SECURE && !t->client_cd)
        flags |= ELPIS_FLAG_AD;
    flags |= (uint16_t)(t->rcode & ELPIS_RCODE_MASK);

    elpis_bld_init(&b, w->txbuf, ELPIS_MAX_MSG, w->ctab, 1);
    if (elpis_bld_header(&b, t->client_id, flags) != ELPIS_OK)
        return;
    if (elpis_bld_question_raw(&b, t->client_qname, t->client_qnamelen,
                               t->orig_qtype, t->qclass) != ELPIS_OK)
        return;

    fill_edns(t, &e, t->rcode);
    /* Reserve room for the OPT record we will append last -- if there is to
     * be one; see below. */
    if (t->client_edns) {
        size_t opt = 11 + (e.have_cookie ? 4u + e.cookie_len : 0u) +
                     (e.ede_code >= 0 ? 6u : 0u) +
                     (e.want_nsid && e.nsid ? 4u + strlen(e.nsid) : 0u);
        if (budget > opt)
            budget -= opt;
    }

    for (i = 0; i < 3 && !truncated; i++) {
        elpis_section_t sec = (elpis_section_t)i;
        unsigned j;

        elpis_bld_mark(&b, &mark);
        for (j = 0; j < t->ans.n; j++) {
            const elpis_trr_t *rr = &t->ans.rr[j];
            elpis_name_t on;
            size_t rdpos;

            if (rr->section != (uint8_t)sec)
                continue;
            if (elpis_trr_get_name(&t->ans, j, &on) != ELPIS_OK)
                continue;
            if (elpis_bld_rr_begin(&b, &on, rr->type, rr->klass, rr->ttl,
                                   &rdpos) != ELPIS_OK ||
                elpis_bld_bytes(&b, elpis_trr_rd(&t->ans, j), rr->rdlen) != ELPIS_OK ||
                elpis_bld_rr_end(&b, rdpos) != ELPIS_OK ||
                b.len > budget) {
                /*
                 * A section that does not fit is dropped whole.  For the
                 * answer section that means truncation; for the others the
                 * reply is still correct, just less helpful.
                 */
                elpis_bld_rollback(&b, &mark);
                if (sec == ELPIS_SEC_ANSWER)
                    truncated = 1;
                break;
            }
            elpis_bld_count(&b, sec, 1);
        }
    }

    if (truncated && !t->from_tcp) {
        elpis_bld_rollback(&b, &mark);
        elpis_put16(w->txbuf + 2, (uint16_t)(flags | ELPIS_FLAG_TC));
        elpis_stat_inc(&w->stats.truncated, 1);
    }

    /*
     * Only to a client that sent one.  RFC 6891 section 7: a query without an
     * OPT record says the client does not speak EDNS, and the responder MUST
     * NOT include one in its reply.  Every answer that had to be resolved got
     * one anyway -- a SERVFAIL carrying an extended error to a client that
     * cannot read it -- while the same name answered from cache a moment
     * later did not, because the fast path already checked.
     */
    if (t->client_edns)
        (void)elpis_edns_write(&b, &e, t->rcode);
    elpis_bld_finish(&b);
    if (truncated && !t->from_tcp)
        elpis_put16(w->txbuf + 2, (uint16_t)(flags | ELPIS_FLAG_TC));

    if (t->from_tcp && t->conn != NULL) {
        tcp_queue(t->conn, w->txbuf, b.len);
        if (t->conn->pending)
            t->conn->pending--;
    } else {
        /*
         * Response rate limiting.  Over the limit we answer truncated rather
         * than silently dropping: a real client just retries over TCP, which
         * a spoofed source cannot do because it never completes a handshake.
         */
        if (elpis_rrl_decide(w, &t->client, t->rcode, 0)) {
            uint8_t tc[ELPIS_HDR_LEN + ELPIS_MAX_NAME + 4];
            size_t tl = ELPIS_HDR_LEN + (size_t)t->client_qnamelen + 4u;
            memcpy(tc, w->txbuf, ELPIS_HDR_LEN);
            elpis_put16(tc + 2, (uint16_t)(flags | ELPIS_FLAG_TC));
            elpis_put16(tc + 6, 0);
            elpis_put16(tc + 8, 0);
            elpis_put16(tc + 10, 0);
            memcpy(tc + ELPIS_HDR_LEN, t->client_qname, t->client_qnamelen);
            elpis_put16(tc + ELPIS_HDR_LEN + t->client_qnamelen, t->orig_qtype);
            elpis_put16(tc + ELPIS_HDR_LEN + t->client_qnamelen + 2, t->qclass);
            send_udp(w, t->listen_fd, tc, tl, &t->client, &t->local);
            elpis_stat_inc(&w->stats.truncated, 1);
        } else {
            send_udp(w, t->listen_fd, w->txbuf, b.len, &t->client, &t->local);
        }
    }

    elpis_stat_inc(&w->stats.answers, 1);
    if (t->rcode == ELPIS_RC_NXDOMAIN)
        elpis_stat_inc(&w->stats.nxdomain, 1);
    else if (t->rcode == ELPIS_RC_SERVFAIL)
        elpis_stat_inc(&w->stats.servfail, 1);

    if (w->ctx->conf.log_replies) {
        char nb[ELPIS_MAX_NAME * 4];
        char ab[80];
        elpis_info("reply %s %s %s -> %s dnssec=%s len=%zu",
                   elpis_addr_str(&t->client, ab, sizeof ab),
                   elpis_name_str(&t->orig_qname, nb, sizeof nb),
                   elpis_type_name(t->orig_qtype),
                   elpis_rcode_name(t->rcode),
                   elpis_sec_name(t->sec), b.len);
    }
}

/*
 * RFC 7873 section 5.2.3: tell the client its cookie did not check out and
 * hand it a fresh one.  The answer section stays empty, so this cannot be
 * used to amplify.
 */
static void reply_badcookie(elpis_worker_t *w, int fd, const elpis_msg_t *m,
                            const elpis_addr_t *to, const elpis_addr_t *from)
{
    elpis_bld_t b;
    elpis_edns_t e;
    uint8_t full[24];
    uint16_t flags;

    elpis_bld_init(&b, w->txbuf, ELPIS_MAX_MSG, w->ctab, 1);
    /*
     * BADCOOKIE is 23, an extended rcode: its low four bits go in the header
     * and the upper four in the OPT record's TTL field.  Leaving the header
     * nibble at zero turns it into BADVERS, which is a different complaint.
     */
    flags = (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA |
                       (m->hdr.flags & ELPIS_FLAG_RD) |
                       (ELPIS_RC_BADCOOKIE & ELPIS_RCODE_MASK));
    if (elpis_bld_header(&b, m->hdr.id, flags) != ELPIS_OK)
        return;
    if (m->hdr.qdcount == 1)
        elpis_bld_question_raw(&b, m->qname.d, m->qname.len, m->qtype, m->qclass);

    elpis_edns_init(&e, w->ctx->conf.edns_buffer, m->do_bit);
    elpis_cookie_server(m->cookie, to, full);
    memcpy(e.cookie, full, sizeof full);
    e.cookie_len = (uint8_t)sizeof full;
    e.have_cookie = 1;
    elpis_edns_write(&b, &e, ELPIS_RC_BADCOOKIE);
    elpis_bld_finish(&b);

    send_udp(w, fd, w->txbuf, b.len, to, from);
}

/* Short error reply that does not need a task. */
static void reply_error(elpis_worker_t *w, int fd, const elpis_msg_t *m,
                        unsigned rcode, const elpis_addr_t *to,
                        const elpis_addr_t *from, elpis_tcpconn_t *conn)
{
    elpis_bld_t b;
    uint16_t flags;

    elpis_bld_init(&b, w->txbuf, ELPIS_MAX_MSG, w->ctab, 1);
    flags = (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA |
                       (m->hdr.flags & (ELPIS_FLAG_RD | ELPIS_FLAG_CD)) |
                       (m->hdr.flags & ELPIS_OPCODE_MASK) |
                       (rcode & ELPIS_RCODE_MASK));
    if (elpis_bld_header(&b, m->hdr.id, flags) != ELPIS_OK)
        return;
    if (m->hdr.qdcount == 1)
        elpis_bld_question_raw(&b, m->qname.d, m->qname.len, m->qtype, m->qclass);

    if (m->have_opt) {
        elpis_edns_t e;
        elpis_edns_init(&e, w->ctx->conf.edns_buffer, m->do_bit);
        if (w->ctx->conf.use_cookies && m->have_cookie && m->cookie_len >= 8) {
            uint8_t full[24];
            elpis_cookie_server(m->cookie, to, full);
            memcpy(e.cookie, full, sizeof full);
            e.cookie_len = (uint8_t)sizeof full;
            e.have_cookie = 1;
        }
        elpis_edns_write(&b, &e, rcode);
    }
    elpis_bld_finish(&b);

    if (conn != NULL)
        tcp_queue(conn, w->txbuf, b.len);
    else
        send_udp(w, fd, w->txbuf, b.len, to, from);
}

/* ------------------------------------------------------------------ */
/* Query intake                                                        */
/* ------------------------------------------------------------------ */

static int try_cache_fast(elpis_worker_t *w, const elpis_msg_t *m,
                          const elpis_addr_t *to, uint8_t kflags, int over_tcp,
                          uint8_t *out, size_t outcap, size_t *outlen)
{
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_mkey_t k;
    elpis_mserve_t info;
    uint8_t folded[ELPIS_MAX_NAME];
    size_t budget;
    size_t len = 0;
    elpis_bld_t b;
    elpis_edns_t e;
    size_t opt_reserve;

    memcpy(folded, m->qname.d, m->qname.len);
    elpis_simd_lower(folded, folded, m->qname.len);

    k.qname    = folded;
    k.qnamelen = m->qname.len;
    k.qtype    = m->qtype;
    k.qclass   = m->qclass;
    k.kflags   = kflags;
    elpis_mkey_hash(&k);

    if (over_tcp) {
        budget = ELPIS_MAX_MSG;
    } else {
        budget = m->have_opt ? m->edns_bufsize : ELPIS_MAX_UDP_LEGACY;
        if (budget > c->max_udp_size_reply)
            budget = c->max_udp_size_reply;
    }

    opt_reserve = m->have_opt ? 48u : 0u;
    if (budget > opt_reserve)
        budget -= opt_reserve;

    if (elpis_mcache_serve(w->ctx->mcache, &k, m->hdr.id, m->qname.d,
                           (uint16_t)(ELPIS_FLAG_QR | ELPIS_FLAG_RA |
                                      (m->hdr.flags & ELPIS_FLAG_RD) |
                                      (m->hdr.flags & ELPIS_FLAG_CD)),
                           budget, c->serve_stale, c->serve_stale_reply_ttl,
                           c->prefetch ? c->prefetch_pct : 0u,
                           out, outcap, &len, &info) != ELPIS_OK)
        return 0;

    /* Re-open the buffer as a builder so the OPT record can be appended. */
    elpis_bld_init(&b, out, outcap, NULL, 0);
    b.len = len;
    b.counts[0] = 1;
    b.counts[1] = info.ancount;
    b.counts[2] = info.nscount;
    b.counts[3] = info.arcount;

    if (m->have_opt) {
        elpis_edns_init(&e, c->edns_buffer, m->do_bit);
        if (c->nsid[0] != '\0') { e.nsid = c->nsid; e.want_nsid = 1; }
        if (info.stale)
            e.ede_code = ELPIS_EDE_STALE_ANSWER;
        if (c->use_cookies && m->have_cookie && m->cookie_len >= 8) {
            uint8_t full[24];
            elpis_cookie_server(m->cookie, to, full);
            memcpy(e.cookie, full, sizeof full);
            e.cookie_len = (uint8_t)sizeof full;
            e.have_cookie = 1;
        }
        elpis_edns_write(&b, &e, info.rcode);
    }
    elpis_bld_finish(&b);

    /* AD is only meaningful when the client did not ask us to skip checking. */
    if (info.sec == ELPIS_SEC_SECURE && !(kflags & ELPIS_MK_CD))
        elpis_put16(out + 2, (uint16_t)(elpis_get16(out + 2) | ELPIS_FLAG_AD));

    *outlen = b.len;
    elpis_stat_inc(&w->stats.cache_hits, 1);
    if (info.stale)
        elpis_stat_inc(&w->stats.cache_stale, 1);

    /*
     * Refresh in the background.  The client already has its answer; this
     * keeps popular names from ever going cold and is what stops a stale
     * entry being served stale forever.
     */
    if (info.want_prefetch)
        elpis_prefetch_start(w, m, kflags);
    return 1;
}

static void handle_query(elpis_worker_t *w, const uint8_t *wire, size_t len,
                         const elpis_addr_t *from, const elpis_addr_t *to,
                         int fd, elpis_tcpconn_t *conn)
{
    const elpis_conf_t *c = &w->ctx->conf;
    elpis_msg_t m;
    int drop = ELPIS_DROP_NONE;
    int snoop = 0;
    elpis_task_t *t;
    size_t outlen = 0;
    uint8_t kflags;
    /* Only when the status page is on: a cache hit is a few microseconds of
     * work, so the clock read would otherwise be a visible share of it. */
    uint64_t t0 = elpis_tm_enabled ? elpis_now_us() : 0;

    elpis_stat_inc(&w->stats.queries, 1);
    elpis_tm_bytes(&w->tm, len, 0);

    if (elpis_msg_parse(&m, wire, len, ELPIS_PARSE_QUERY, &drop) != ELPIS_OK) {
        elpis_drop_log((elpis_drop_t)drop, from, wire, len, "client query");
        elpis_stat_inc(&w->stats.dropped, 1);
        return;
    }

    if (!elpis_conf_acl_check(c, from, &snoop)) {
        elpis_drop_log(ELPIS_DROP_ACL, from, wire, len, NULL);
        elpis_stat_inc(&w->stats.dropped, 1);
        return;
    }
    if (c->client_qps && !elpis_ratelimit_client(w, from)) {
        elpis_drop_log(ELPIS_DROP_RATELIMIT, from, wire, len, NULL);
        elpis_stat_inc(&w->stats.dropped, 1);
        return;
    }

    if (elpis_msg_opcode(&m) != ELPIS_OP_QUERY) {
        char ab[80];
        elpis_logf_rl(ELPIS_LOG_INFO, ELPIS_DROP_OPCODE, __FILE__, __LINE__,
                      "refusing opcode %s from %s",
                      elpis_opcode_name(elpis_msg_opcode(&m)),
                      elpis_addr_str(from, ab, sizeof ab));
        reply_error(w, fd, &m, ELPIS_RC_NOTIMP, from, to, conn);
        return;
    }
    if (m.hdr.qdcount != 1) {
        elpis_drop_log(ELPIS_DROP_QDCOUNT, from, wire, len, NULL);
        reply_error(w, fd, &m, ELPIS_RC_FORMERR, from, to, conn);
        return;
    }
    if (m.have_opt && m.edns_version != 0) {
        /* RFC 6891 section 6.1.3: answer BADVERS, do not guess. */
        reply_error(w, fd, &m, ELPIS_RC_BADVERS, from, to, conn);
        return;
    }
    if (m.qclass != ELPIS_CLASS_IN && m.qclass != ELPIS_CLASS_CH) {
        reply_error(w, fd, &m, ELPIS_RC_REFUSED, from, to, conn);
        return;
    }
    if (elpis_type_is_meta(m.qtype) && m.qtype != ELPIS_T_ANY) {
        reply_error(w, fd, &m, ELPIS_RC_REFUSED, from, to, conn);
        return;
    }
    /*
     * RFC 7873 cookies.  A client that sends only its own 8-byte half gets a
     * server cookie back so the next query is pre-authenticated.  A client
     * that echoes a server cookie has it checked: an off-path attacker cannot
     * produce one, so a wrong cookie means the source is unverified.
     *
     * Answering BADCOOKIE for that is only done when require-cookie is set,
     * because a client whose address has changed has a legitimately stale
     * cookie and would otherwise see a failure it cannot explain.
     */
    if (c->use_cookies && m.have_cookie && m.cookie_len > 8) {
        if (!elpis_cookie_verify(m.cookie, m.cookie_len, from)) {
            elpis_stat_inc(&w->stats.cookie_bad, 1);
            if (c->require_cookie && conn == NULL) {
                reply_badcookie(w, fd, &m, from, to);
                return;
            }
        } else {
            elpis_stat_inc(&w->stats.cookie_ok, 1);
        }
    }

    if (!(m.hdr.flags & ELPIS_FLAG_RD) && !snoop) {
        /* Not a recursion request and this client may not snoop the cache. */
        reply_error(w, fd, &m, ELPIS_RC_REFUSED, from, to, conn);
        return;
    }

    /* CHAOS TXT and the RFC 6761 special names never leave the process. */
    if (elpis_localzone_static(w, &m, w->txbuf, ELPIS_MAX_MSG, &outlen)) {
        if (conn != NULL)
            tcp_queue(conn, w->txbuf, outlen);
        else
            send_udp(w, fd, w->txbuf, outlen, from, to);
        return;
    }

    if (c->log_queries) {
        char nb[ELPIS_MAX_NAME * 4];
        char ab[80];
        elpis_info("query %s %s %s%s", elpis_addr_str(from, ab, sizeof ab),
                   elpis_name_str(&m.qname, nb, sizeof nb),
                   elpis_type_name(m.qtype), m.do_bit ? " +do" : "");
    }

    kflags = (uint8_t)((m.do_bit ? ELPIS_MK_DO : 0) |
                       ((m.hdr.flags & ELPIS_FLAG_CD) ? ELPIS_MK_CD : 0));

    if (try_cache_fast(w, &m, to, kflags, conn != NULL,
                       w->txbuf, ELPIS_MAX_MSG, &outlen)) {
        /*
         * A cache hit never becomes a task, so this is the only place it can
         * be counted.  Measured in microseconds rather than the resolver's
         * millisecond clock: the whole of it fits inside one tick of that,
         * so it would otherwise read as zero and say nothing.
         */
        unsigned rc = outlen >= 4 ? (unsigned)(elpis_get16(w->txbuf + 2) & 0x0Fu) : 0u;
        elpis_tm_observe(&w->tm, t0 ? elpis_now_us() - t0 : 0, 0);
        elpis_tm_answer(&w->tm, &m.qname, from, rc, 0);
        if (conn != NULL)
            tcp_queue(conn, w->txbuf, outlen);
        else
            send_udp(w, fd, w->txbuf, outlen, from, to);
        return;
    }

    t = elpis_task_new(w);
    if (t == NULL) {
        elpis_drop_log(ELPIS_DROP_RESOURCE, from, wire, len, "no memory");
        reply_error(w, fd, &m, ELPIS_RC_SERVFAIL, from, to, conn);
        return;
    }

    t->has_client       = 1;
    t->from_tcp         = (conn != NULL) ? 1u : 0u;
    t->conn             = conn;
    t->client           = *from;
    t->local            = (to != NULL) ? *to : *from;
    if (to == NULL || to->len == 0)
        memset(&t->local, 0, sizeof t->local);
    t->listen_fd        = fd;
    t->client_id        = m.hdr.id;
    t->client_flags     = m.hdr.flags;
    t->client_rd        = (m.hdr.flags & ELPIS_FLAG_RD) ? 1u : 0u;
    t->client_cd        = (m.hdr.flags & ELPIS_FLAG_CD) ? 1u : 0u;
    t->client_do        = m.do_bit;
    t->client_edns      = m.have_opt;
    t->client_bufsize   = m.have_opt ? m.edns_bufsize : ELPIS_MAX_UDP_LEGACY;
    t->client_qnamelen  = m.qname.len;
    memcpy(t->client_qname, m.qname.d, m.qname.len);
    if (m.have_cookie && m.cookie_len >= 8) {
        memcpy(t->client_cookie, m.cookie, m.cookie_len);
        t->client_cookie_len = m.cookie_len;
    }

    t->qname  = m.qname;
    elpis_name_lower(&t->qname);
    t->qtype  = m.qtype;
    t->qclass = m.qclass;

    if (conn != NULL)
        conn->pending++;

    elpis_stat_inc(&w->stats.recursions, 1);
    elpis_task_start(t);
}

/* ------------------------------------------------------------------ */
/* UDP                                                                 */
/* ------------------------------------------------------------------ */

void elpis_server_udp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_worker_t *w = (elpis_worker_t *)ev->data;
    unsigned budget = 64;

    (void)lp;
    if (!(events & ELPIS_EV_READ))
        return;

    while (budget-- > 0) {
        elpis_addr_t from, to;
        ssize_t n;

        memset(&from, 0, sizeof from);
        memset(&to, 0, sizeof to);
        n = elpis_sock_recv(ev->fd, w->rxbuf, ELPIS_MAX_UDP, &from, &to);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            return;
        }
        if (n < ELPIS_HDR_LEN) {
            elpis_drop_log(ELPIS_DROP_SHORT, &from, w->rxbuf, (size_t)n, NULL);
            continue;
        }
        handle_query(w, w->rxbuf, (size_t)n, &from,
                     to.len ? &to : NULL, ev->fd, NULL);
    }
}

/* ------------------------------------------------------------------ */
/* TCP                                                                 */
/* ------------------------------------------------------------------ */

static void tcp_conn_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);
static void tcp_idle_timeout(elpis_loop_t *lp, elpis_timer_t *tm);

static int tcp_queue(elpis_tcpconn_t *c, const uint8_t *buf, size_t len)
{
    size_t need = c->txlen + len + 2u;

    if (c->closing)
        return ELPIS_ERR;
    if (need > c->txcap) {
        size_t want = c->txcap ? c->txcap : 4096;
        uint8_t *nb;
        while (want < need) {
            if (want > 4u * 1024u * 1024u)
                return ELPIS_ENOMEM;     /* a client that never reads */
            want *= 2u;
        }
        nb = (uint8_t *)elpis_realloc(c->tx, want);
        if (nb == NULL)
            return ELPIS_ENOMEM;
        c->tx = nb;
        c->txcap = want;
    }
    elpis_put16(c->tx + c->txlen, (uint16_t)len);
    memcpy(c->tx + c->txlen + 2, buf, len);
    c->txlen += len + 2u;
    elpis_loop_mod(c->w->loop, &c->ev, ELPIS_EV_READ | ELPIS_EV_WRITE);
    return ELPIS_OK;
}

static void tcp_close(elpis_tcpconn_t *c)
{
    elpis_worker_t *w = c->w;

    if (c->pending > 0) {
        /* Resolutions still reference this connection; mark and let them
         * drain.  The last one to finish closes it. */
        c->closing = 1;
        return;
    }
    elpis_timer_del(w->loop, &c->idle);
    elpis_loop_del(w->loop, &c->ev);
    if (c->fd >= 0)
        close(c->fd);
    if (c->prev) c->prev->next = c->next;
    else         w->conns = c->next;
    if (c->next) c->next->prev = c->prev;
    if (w->n_conns)
        w->n_conns--;
    elpis_free(c->rx);
    elpis_free(c->tx);
    elpis_free(c);
}

static void tcp_idle_timeout(elpis_loop_t *lp, elpis_timer_t *tm)
{
    elpis_tcpconn_t *c = (elpis_tcpconn_t *)tm->data;
    (void)lp;
    tcp_close(c);
}

static void tcp_conn_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_tcpconn_t *c = (elpis_tcpconn_t *)ev->data;
    elpis_worker_t *w = c->w;

    if (events & (ELPIS_EV_ERROR | ELPIS_EV_HUP)) {
        tcp_close(c);
        return;
    }

    if (events & ELPIS_EV_WRITE) {
        while (c->txsent < c->txlen) {
            ssize_t n = write(c->fd, c->tx + c->txsent, c->txlen - c->txsent);
            if (n > 0) {
                c->txsent += (size_t)n;
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            if (n < 0 && errno == EINTR)
                continue;
            tcp_close(c);
            return;
        }
        if (c->txsent >= c->txlen) {
            c->txlen = c->txsent = 0;
            elpis_loop_mod(lp, &c->ev, ELPIS_EV_READ);
            if (c->closing && c->pending == 0) {
                tcp_close(c);
                return;
            }
        }
    }

    if (!(events & ELPIS_EV_READ))
        return;

    for (;;) {
        ssize_t n;

        if (c->rxcap == 0) {
            c->rxcap = 2048;
            c->rx = (uint8_t *)elpis_malloc(c->rxcap);
            if (c->rx == NULL) {
                tcp_close(c);
                return;
            }
        }
        if (c->rxwant != 0 && c->rxwant + 2u > c->rxcap) {
            uint8_t *nb = (uint8_t *)elpis_realloc(c->rx, c->rxwant + 2u);
            if (nb == NULL) {
                tcp_close(c);
                return;
            }
            c->rx = nb;
            c->rxcap = c->rxwant + 2u;
        }

        n = read(c->fd, c->rx + c->rxlen, c->rxcap - c->rxlen);
        if (n == 0) {
            tcp_close(c);
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            tcp_close(c);
            return;
        }
        c->rxlen += (size_t)n;

        for (;;) {
            if (c->rxwant == 0) {
                if (c->rxlen < 2)
                    break;
                c->rxwant = elpis_get16(c->rx);
                if (c->rxwant < ELPIS_HDR_LEN) {
                    elpis_drop_log(ELPIS_DROP_SHORT, &c->peer, c->rx, c->rxlen,
                                   "tcp length prefix");
                    tcp_close(c);
                    return;
                }
                continue;
            }
            if (c->rxlen < c->rxwant + 2u)
                break;

            elpis_stat_inc(&w->stats.tcp_queries, 1);
            handle_query(w, c->rx + 2, c->rxwant, &c->peer, &c->local, c->fd, c);

            /* Slide any pipelined remainder to the front (RFC 7766). */
            memmove(c->rx, c->rx + 2 + c->rxwant, c->rxlen - (c->rxwant + 2u));
            c->rxlen -= c->rxwant + 2u;
            c->rxwant = 0;
        }
    }

    elpis_timer_add(w->loop, &c->idle, w->ctx->conf.tcp_idle_ms,
                    tcp_idle_timeout, c);
}

void elpis_server_tcp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events)
{
    elpis_worker_t *w = (elpis_worker_t *)ev->data;
    unsigned budget = 32;

    if (!(events & ELPIS_EV_READ))
        return;

    while (budget-- > 0) {
        elpis_addr_t peer;
        socklen_t sl = (socklen_t)sizeof peer.u.ss;
        int fd;
        elpis_tcpconn_t *c;

        memset(&peer, 0, sizeof peer);
        fd = accept(ev->fd, &peer.u.sa, &sl);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            return;
        }
        peer.len = sl;

        if (w->n_conns >= w->ctx->conf.tcp_max_conn) {
            close(fd);
            elpis_drop_log(ELPIS_DROP_RESOURCE, &peer, NULL, 0,
                           "tcp connection limit");
            continue;
        }
        {
            int snoop;
            if (!elpis_conf_acl_check(&w->ctx->conf, &peer, &snoop)) {
                close(fd);
                elpis_drop_log(ELPIS_DROP_ACL, &peer, NULL, 0, "tcp");
                continue;
            }
        }

        elpis_sock_cloexec(fd);
        if (elpis_sock_nonblock(fd) != ELPIS_OK) {
            close(fd);
            continue;
        }
        elpis_sock_tune_tcp(fd);

        c = (elpis_tcpconn_t *)elpis_calloc(1, sizeof *c);
        if (c == NULL) {
            close(fd);
            continue;
        }
        c->w    = w;
        c->fd   = fd;
        c->peer = peer;
        {
            socklen_t ll = (socklen_t)sizeof c->local.u.ss;
            if (getsockname(fd, &c->local.u.sa, &ll) == 0)
                c->local.len = ll;
        }
        if (elpis_loop_add(lp, &c->ev, fd, ELPIS_EV_READ,
                           tcp_conn_event, c) != ELPIS_OK) {
            close(fd);
            elpis_free(c);
            continue;
        }
        c->next = w->conns;
        if (w->conns)
            w->conns->prev = c;
        w->conns = c;
        w->n_conns++;
        elpis_timer_add(w->loop, &c->idle, w->ctx->conf.tcp_idle_ms,
                        tcp_idle_timeout, c);
    }
}
