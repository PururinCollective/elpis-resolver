/*
 * elpis/resolver.h -- workers, tasks and the iterative resolution engine.
 *
 * One worker per thread owns an event loop, a listening socket set (via
 * SO_REUSEPORT so the kernel spreads load), a pool of outbound UDP sockets on
 * random ports, and every task it started.  Nothing inside a worker is shared,
 * so the only synchronisation in the hot path is the cache shard lock.
 */
#ifndef ELPIS_RESOLVER_H
#define ELPIS_RESOLVER_H

#include "elpis/ctx.h"
#include "elpis/loop.h"
#include "elpis/rrlist.h"
#include "elpis/msg.h"
#include "elpis/edns.h"
#include "elpis/telemetry.h"

typedef struct elpis_worker  elpis_worker_t;
typedef struct elpis_task    elpis_task_t;
typedef struct elpis_outq    elpis_outq_t;
typedef struct elpis_tcpconn elpis_tcpconn_t;

/* ------------------------------------------------------------------ */
/* Outbound                                                            */
/* ------------------------------------------------------------------ */

#define ELPIS_OUT_HASH_BITS 12
#define ELPIS_OUT_HASH (1u << ELPIS_OUT_HASH_BITS)

typedef struct {
    int             fd;
    elpis_ev_t      ev;
    int             family;
    elpis_worker_t *w;
    unsigned        inflight;
    uint16_t        port;
} elpis_osock_t;

struct elpis_outq {
    elpis_outq_t  *hnext;
    elpis_task_t  *task;
    elpis_worker_t *w;

    elpis_addr_t   server;
    uint16_t       id;
    uint16_t       qtype, qclass;
    uint8_t        qname_wire[ELPIS_MAX_NAME];   /* exactly as sent      */
    uint8_t        qnamelen;
    uint8_t        cookie[8];

    int            sockidx;
    uint64_t       sent_ms;
    uint16_t       edns_size;
    unsigned       used_edns   : 1;
    unsigned       used_cookie : 1;
    unsigned       sent_server_cookie : 1;
    unsigned       cookie_retry : 1;  /* already resent once for BADCOOKIE */
    unsigned       over_tcp    : 1;
    unsigned       dead        : 1;
    /*
     * Nobody is waiting for the answer any more -- it lost a race, or its
     * task went away -- but the round trip is still worth having: it is how
     * a server we have never used gets measured.  A probe updates the infra
     * cache when it lands or times out, and is then freed.
     */
    unsigned       probe       : 1;
    unsigned       used_0x20   : 1;   /* the name went out case-randomised */
    unsigned       caps_test   : 1;   /* sent as-is to see if 0x20 is why  */
    /* Timed out, and kept a while longer in case the answer is only late. */
    unsigned       late        : 1;
    uint32_t       timeout_ms;

    elpis_timer_t  timer;

    /* TCP fallback state */
    int            tcpfd;
    elpis_ev_t     tcpev;
    uint8_t       *txbuf;
    size_t         txlen, txsent;
    uint8_t       *rxbuf;
    size_t         rxlen, rxwant, rxcap;
};

/* ------------------------------------------------------------------ */
/* Tasks                                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    ELPIS_TS_INIT = 0,
    ELPIS_TS_LOOKUP,
    ELPIS_TS_DELEG,
    ELPIS_TS_SEND,
    ELPIS_TS_WAIT,
    ELPIS_TS_NSADDR,
    ELPIS_TS_VALIDATE,
    ELPIS_TS_FINISH,
    ELPIS_TS_DEAD
} elpis_tstate_t;

typedef void (*elpis_task_done_fn)(elpis_task_t *child, void *ctx);

#define ELPIS_MAX_TRIED 24
#define ELPIS_MAX_DEPTH 8

struct elpis_task {
    elpis_worker_t *w;
    elpis_task_t   *parent;
    /*
     * Children are tracked explicitly so a task that finishes early -- on its
     * own deadline, say -- can detach whatever it spawned instead of leaving
     * dangling parent pointers behind.
     */
    elpis_task_t   *children;
    elpis_task_t   *sib_next, *sib_prev;
    unsigned        depth;
    unsigned        nchild;
    elpis_task_done_fn done_cb;
    void           *done_ctx;

    /* ---- client side (top-level tasks only) ---- */
    unsigned         has_client : 1;
    unsigned         from_tcp   : 1;
    elpis_tcpconn_t *conn;
    elpis_addr_t     client, local;
    int              listen_fd;
    uint16_t         client_id;
    uint16_t         client_flags;
    uint16_t         client_bufsize;
    uint8_t          client_qname[ELPIS_MAX_NAME];
    uint8_t          client_qnamelen;
    unsigned         client_do : 1, client_cd : 1, client_rd : 1;
    unsigned         client_edns : 1, client_cookie_ok : 1;
    uint8_t          client_cookie[40];
    uint8_t          client_cookie_len;

    /* ---- what is being resolved right now ---- */
    elpis_name_t    qname;
    uint16_t        qtype, qclass;
    elpis_name_t    orig_qname;
    uint16_t        orig_qtype;

    /* ---- iteration ---- */
    elpis_deleg_t   deleg;
    unsigned        have_deleg : 1;
    unsigned        forwarding : 1;   /* talking to a forwarder, RD set   */
    /*
     * The delegation came from a forward-zone or stub-zone rather than from
     * the network, so it belongs to the configuration and must never be
     * written back into the delegation cache.
     */
    unsigned        deleg_from_route : 1;
    unsigned        referrals, restarts, sends;
    elpis_addr_t    tried[ELPIS_MAX_TRIED];
    unsigned        ntried;
    unsigned        rounds;     /* times every server here has been tried */

    /* ---- QNAME minimisation (RFC 9156) ---- */
    unsigned        qmin_labels;
    unsigned        qmin_active : 1;
    unsigned        qmin_probe  : 1;   /* the in-flight query is a probe */

    /* ---- results ---- */
    elpis_rrlist_t  ans;
    unsigned        rcode;
    elpis_sec_t     sec;
    int             ede;
    unsigned        aa : 1;
    unsigned        answered : 1;
    unsigned        from_cache : 1;
    unsigned        prefetch : 1;   /* background refresh of cached data  */
    unsigned        warming : 1;    /* priming / TLD warming, no client   */
    unsigned        dns64_tried : 1;
    unsigned        dns64_synth : 1;
    unsigned        revalidate : 1;   /* cache hit whose status is unknown */
    /*
     * The chain of trust could not be checked because DNSKEY or DS data was
     * unreachable -- distinct from "the signatures are wrong".  Both end in
     * SERVFAIL, but only one of them is an attack.
     */
    unsigned        val_unavailable : 1;

    /* ---- DNSSEC working state ---- */
    void           *val;

    uint64_t        start_ms;
    elpis_timer_t   deadline;
    elpis_timer_t   kick;       /* defers the first step out of the caller */
    elpis_outq_t   *out;
    elpis_outq_t   *race;       /* the same question, to a second server */
    elpis_tstate_t  state;
};

/* ------------------------------------------------------------------ */
/* TCP connections from clients                                        */
/* ------------------------------------------------------------------ */

struct elpis_tcpconn {
    elpis_worker_t  *w;
    int              fd;
    elpis_ev_t       ev;
    elpis_addr_t     peer, local;
    elpis_timer_t    idle;
    uint8_t         *rx;
    size_t           rxlen, rxwant, rxcap;
    uint8_t         *tx;
    size_t           txlen, txsent, txcap;
    unsigned         closing : 1;      /* socket gone; freed when pending is 0 */
    unsigned         stalled : 1;      /* not reading until the client reads */
    unsigned         pending;          /* queries still resolving */
    elpis_tcpconn_t *next, *prev;
};

/* ------------------------------------------------------------------ */
/* Workers                                                             */
/* ------------------------------------------------------------------ */

#define ELPIS_MAX_OSOCK 128
#define ELPIS_MAX_LSOCK (ELPIS_MAX_LISTEN * 2)

struct elpis_worker {
    elpis_ctx_t    *ctx;
    unsigned        index;
    elpis_loop_t   *loop;

    int             udp_fd[ELPIS_MAX_LSOCK];
    elpis_ev_t      udp_ev[ELPIS_MAX_LSOCK];
    unsigned        n_udp;
    int             tcp_fd[ELPIS_MAX_LSOCK];
    elpis_ev_t      tcp_ev[ELPIS_MAX_LSOCK];
    unsigned        n_tcp;

    elpis_osock_t   osock[ELPIS_MAX_OSOCK];
    unsigned        n_osock;
    unsigned        osock_rr;

    elpis_outq_t   *outhash[ELPIS_OUT_HASH];
    unsigned        n_out;

    elpis_tcpconn_t *conns;
    unsigned         n_conns;

    unsigned        n_tasks;

    /* Scratch buffers, reused per event; never held across a yield. */
    uint8_t        *rxbuf;      /* ELPIS_MAX_MSG                       */
    uint8_t        *txbuf;
    elpis_cslot_t  *ctab;
    elpis_rrset_buf_t *rrbuf;
    uint32_t       *ttl_off;
    uint32_t       *ttl_val;
    /* Two rdata staging buffers: decompression can need one while another
     * record is still being assembled.  Heap, not stack -- rdlength is a
     * 16-bit field and 64 KiB frames do not belong on a callback path. */
    uint8_t        *rd1;
    uint8_t        *rd2;

    elpis_timer_t   maint;
    elpis_stats_t   stats;
    elpis_wtm_t     tm;          /* status-page tallies, worker-local */

    /* Last second of event-loop behaviour; see report_spin() in main.c. */
    uint64_t        loop_turns, loop_idle, loop_nosleep;
    uint32_t        loop_slowest;
    unsigned        loop_timers;
};

/* ---- lifecycle ---- */
int  elpis_worker_init(elpis_worker_t *w, elpis_ctx_t *ctx, unsigned index);
void elpis_worker_fini(elpis_worker_t *w);
void elpis_worker_run(elpis_worker_t *w);

/* ---- server side (server.c) ---- */
void elpis_server_udp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);
void elpis_server_tcp_event(elpis_loop_t *lp, elpis_ev_t *ev, unsigned events);
void elpis_task_respond(elpis_task_t *t);

/* ---- resolution (resolver.c) ---- */
elpis_task_t *elpis_task_new(elpis_worker_t *w);
void elpis_task_free(elpis_task_t *t);
void elpis_task_start(elpis_task_t *t);
void elpis_task_step(elpis_task_t *t);
void elpis_task_fail(elpis_task_t *t, unsigned rcode, int ede);
/* Spawn a dependent resolution; `cb` runs when it finishes. */
elpis_task_t *elpis_task_child(elpis_task_t *parent, const elpis_name_t *qname,
                               uint16_t qtype, elpis_task_done_fn cb, void *ctx);

/* ---- outbound (outbound.c) ---- */
int  elpis_out_init(elpis_worker_t *w);
void elpis_out_fini(elpis_worker_t *w);
int  elpis_out_send(elpis_task_t *t, const elpis_addr_t *server, int force_tcp);
/* Ask the question just sent by elpis_out_send() of a second server too; the
 * first usable answer is the one the task gets.  UDP only. */
int  elpis_out_race(elpis_task_t *t, const elpis_addr_t *server);
/* The same question again, only to measure the server: nobody waits on it. */
int  elpis_out_probe(elpis_task_t *t, const elpis_addr_t *server);
void elpis_out_cancel(elpis_task_t *t);
void elpis_out_free(elpis_worker_t *w, elpis_outq_t *q);

/* Called by outbound.c when a response (or failure) arrives. */
void elpis_resolver_on_response(elpis_task_t *t, elpis_outq_t *q,
                                const elpis_msg_t *m);
void elpis_resolver_on_timeout(elpis_task_t *t, elpis_outq_t *q);
void elpis_resolver_on_error(elpis_task_t *t, elpis_outq_t *q, int ede);
/* The question in flight, again, to the same server (BADCOOKIE, TC). */
int  elpis_task_resend(elpis_task_t *t, const elpis_addr_t *server,
                       int force_tcp);

/* ---- DNSSEC (dnssec.c) ---- */
/* Returns non-zero when the validator suspended on a child lookup. */
int  elpis_val_start(elpis_task_t *t);
void elpis_val_free(elpis_task_t *t);

/* ---- DNS64 (dns64.c) ---- */
/* RFC 6052 section 2.2: embed an IPv4 address in a DNS64 prefix. */
void elpis_dns64_embed(const elpis_prefix_t *p, const uint8_t v4[4],
                       uint8_t out[16]);
int  elpis_dns64_needed(elpis_task_t *t);
int  elpis_dns64_start(elpis_task_t *t);
void elpis_dns64_apply(elpis_task_t *t);

/* ---- local data (localzone.c) ---- */
int  elpis_localzone_answer(elpis_task_t *t);
int  elpis_localzone_static(elpis_worker_t *w, const elpis_msg_t *m,
                            uint8_t *out, size_t cap, size_t *outlen);

/* ---- rate limiting (ratelimit.c, rrl.c) ---- */
int  elpis_ratelimit_client(elpis_worker_t *w, const elpis_addr_t *a);
int  elpis_rrl_allow(elpis_worker_t *w, const elpis_addr_t *a, unsigned rcode);
int  elpis_rrl_decide(elpis_worker_t *w, const elpis_addr_t *client,
                      unsigned rcode, int over_tcp);

/* ---- priming and warming (roots.c, tld.c, axfr.c) ---- */
int  elpis_prime_start(elpis_worker_t *w);
int  elpis_tld_warm_start(elpis_worker_t *w);
int  elpis_axfr_root(elpis_ctx_t *ctx);
int  elpis_probe_roots(elpis_ctx_t *ctx);
/* Find our public addresses and network, through our own recursion. */
int  elpis_selfinfo_start(elpis_worker_t *w);

/* ---- helpers shared between the modules ---- */
uint32_t elpis_clamp_ttl(const elpis_conf_t *c, uint32_t ttl);
uint32_t elpis_clamp_neg_ttl(const elpis_conf_t *c, uint32_t ttl);
/* The status of an answer so far (`chain`) once `link` is added to it: the
 * weakest of the two, where unchecked outranks nothing and bogus everything. */
elpis_sec_t elpis_sec_link(elpis_sec_t chain, elpis_sec_t link);

#endif /* ELPIS_RESOLVER_H */
