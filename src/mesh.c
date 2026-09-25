/*
 * mesh.c -- the mesh thread: connections, the handshake, name lists and peer
 * exchange.  See elpis/mesh.h for what it is for.
 *
 * One thread and one poll() loop.  Nothing is shared with the workers but
 * the message cache a list is read out of and the warm-up queue a list is
 * handed to.  Every connection is a session:
 *
 *   CONNECTING   our dial, waiting for TCP
 *   HANDSHAKE    Noise messages 1 and 2 (noise.h), each carrying a hello
 *   UP           framed, encrypted messages both ways
 *
 * On the wire every message, handshake or not, is a two-byte length and then
 * that many bytes.  Inside the encryption each message is a type byte and a
 * body:
 *
 *   LIST_REQ   u32 most names wanted
 *   LIST_PART  entries: u32 hits, u16 ms, u8 DO/CD, u16 type, u8 len, name
 *   LIST_END   u32 entries sent
 *   PEERS      u8 count, then per peer: u8 4 or 6, the address, u16 port
 *   PING/PONG  u64 token
 *
 * A message of a type this version does not know is skipped, so a later one
 * can add more.
 */
#include "elpis/mesh.h"
#include "elpis/noise.h"
#include "elpis/checkpoint.h"
#include "elpis/store.h"
#include "elpis/crypto.h"
#include "elpis/sock.h"
#include "elpis/util.h"
#include "elpis/log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define MESH_PROLOGUE        "elpis mesh 1"
#define MESH_VERSION         1u
#define MESH_MAX_SESSIONS    64u
#define MESH_MAX_KNOWN       256u
#define MESH_FRAME_MAX       65535u
#define MESH_PLAIN_MAX       (MESH_FRAME_MAX - ELPIS_NOISE_TAG)
/* A peer that has not read this much of what it asked for is not reading. */
#define MESH_OUT_MAX         (16u * 1024u * 1024u)
#define MESH_HANDSHAKE_MS    5000u
#define MESH_IDLE_MS         120000u
#define MESH_PING_MS         30000u
/* At startup, how long to wait for the peers' lists before warming. */
#define MESH_GATHER_MS       3000u
/* Lists are asked for only this soon after a start: after that the cache is
 * this instance's own, and another's list would only dilute it. */
#define MESH_ASK_WINDOW_MS   (5u * 60u * 1000u)
#define MESH_SERVE_EVERY_MS  60000u
#define MESH_PEX_EVERY_MS    (5u * 60u * 1000u)
#define MESH_RETRY_MIN_MS    2000u
#define MESH_RETRY_MAX_MS    (5u * 60u * 1000u)
/* A peer only heard of is forgotten after this many failed dials. */
#define MESH_LEARNED_TRIES   5u

enum { MSG_LIST_REQ = 1, MSG_LIST_PART = 2, MSG_LIST_END = 3, MSG_PEERS = 4,
       MSG_PING = 5, MSG_PONG = 6 };
enum { S_CONNECTING, S_HANDSHAKE, S_UP };

/* The hello each handshake message carries: version, flags, the port this
 * instance takes connections on (0 for none), and its node id. */
#define HELLO_LEN    20u
#define HELLO_SHARES 0x01u         /* answers list requests */

typedef struct session {
    struct session   *next;
    int               fd;
    int               state;
    unsigned          initiator : 1;
    unsigned          dead      : 1;
    unsigned          was_up    : 1;
    unsigned          quiet     : 1;   /* its end is no news            */
    unsigned          asked     : 1;   /* we asked for its list        */
    unsigned          got_list  : 1;
    unsigned          shares    : 1;   /* its hello says it answers    */
    unsigned          has_listen: 1;
    elpis_addr_t      addr;            /* the far end of the socket     */
    elpis_addr_t      dial;            /* what we dialled, as initiator */
    elpis_addr_t      listen;          /* where it takes connections    */
    uint8_t           node[16];
    elpis_noise_hs_t  hs;
    elpis_noise_cs_t  tx, rx;
    uint8_t          *in;
    size_t            inlen, incap;
    uint8_t          *out;
    size_t            outlen, outoff, outcap;
    uint64_t          deadline, last_rx, last_ping, last_pex, last_served;
    uint32_t          rtt_ms;
    const char       *why;             /* why it closed                  */
    elpis_ckpt_list_t incoming;
    char              name[64];
} session_t;

typedef struct {
    elpis_addr_t a;
    unsigned     bridge    : 1;        /* named in mesh-peer:           */
    unsigned     self      : 1;        /* it turned out to be us        */
    unsigned     attempted : 1;        /* one dial has run its course   */
    unsigned     fails;
    uint32_t     backoff;
    uint64_t     next_try;
} known_t;

static elpis_ctx_t *g_ctx;
static uint8_t      g_psk[32];
static uint8_t      g_node[16];
static int          g_lfd[ELPIS_MESH_MAX_LISTEN];
static unsigned     g_nlfd;
static uint16_t     g_port;            /* what the hello announces      */
static session_t   *g_sessions;
static unsigned     g_nsessions;
static known_t      g_known[MESH_MAX_KNOWN];
static unsigned     g_nknown;
static uint64_t     g_t0;
/* Startup: the checkpoint, and the peers' lists as they arrive. */
static elpis_ckpt_list_t g_gather;
static int          g_gathering;
static unsigned     g_gather_peers;
static int          g_gather_local;
/* One plaintext message and its ciphertext at a time: one thread. */
static uint8_t      g_plain[MESH_FRAME_MAX];
static uint8_t      g_cipher[2u + MESH_FRAME_MAX];

/* ------------------------------------------------------------------ */
/* Small pieces                                                        */
/* ------------------------------------------------------------------ */

static void hex8(const uint8_t *p, char out[9])
{
    static const char k[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 4; i++) {
        out[2 * i]     = k[p[i] >> 4];
        out[2 * i + 1] = k[p[i] & 15];
    }
    out[8] = '\0';
}

static int hexdig(int ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int elpis_mesh_psk_parse(const char *text, uint8_t psk[32])
{
    const char *p = text;
    unsigned nd = 0;
    int at_line = 1, hi = -1;

    for (; *p != '\0'; p++) {
        int v;
        if (at_line && *p == '#') {
            while (*p != '\0' && *p != '\n')
                p++;
            if (*p == '\0')
                break;
            continue;               /* the newline starts the next line */
        }
        at_line = (*p == '\n');
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            continue;
        v = hexdig((unsigned char)*p);
        if (v < 0 || nd >= 64)
            return ELPIS_ERR;       /* anything else, or too much of it */
        if (hi < 0) {
            hi = v;
        } else {
            psk[nd / 2] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
        nd++;
    }
    return nd == 64 ? ELPIS_OK : ELPIS_ERR;
}

int elpis_mesh_gen_psk(void)
{
    uint8_t k[32];
    unsigned i;

    elpis_random_bytes(k, sizeof k);
    printf("# elpis mesh key: every instance in the mesh gets this same file,\n"
           "# readable by root alone.  Point mesh-psk: at it.\n");
    for (i = 0; i < sizeof k; i++)
        printf("%02x", k[i]);
    printf("\n");
    elpis_memzero(k, sizeof k);
    return 0;
}

static const uint8_t *addr_ip(const elpis_addr_t *a, unsigned *len)
{
    if (elpis_addr_family(a) == AF_INET) {
        *len = 4;
        return (const uint8_t *)&a->u.v4.sin_addr;
    }
    *len = 16;
    return (const uint8_t *)&a->u.v6.sin6_addr;
}

/* An IPv4 address, or the one inside a v4-mapped IPv6, as four bytes. */
static const uint8_t *ip4_of(const elpis_addr_t *a)
{
    static const uint8_t mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
    unsigned len;
    const uint8_t *ip = addr_ip(a, &len);

    if (len == 4)
        return ip;
    return memcmp(ip, mapped, 12) == 0 ? ip + 12 : NULL;
}

static int addr_loopback(const elpis_addr_t *a)
{
    static const uint8_t one[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
    const uint8_t *v4 = ip4_of(a);
    unsigned len;

    if (v4 != NULL)
        return v4[0] == 127;
    return memcmp(addr_ip(a, &len), one, 16) == 0;
}

int elpis_mesh_addr_private(const elpis_addr_t *a)
{
    const uint8_t *v4 = ip4_of(a);
    const uint8_t *ip;
    unsigned len;

    if (addr_loopback(a))
        return 1;
    if (v4 != NULL)
        return v4[0] == 10 ||
               (v4[0] == 172 && (v4[1] & 0xF0) == 16) ||
               (v4[0] == 192 && v4[1] == 168) ||
               (v4[0] == 100 && (v4[1] & 0xC0) == 64) ||    /* RFC 6598 */
               (v4[0] == 169 && v4[1] == 254);
    ip = addr_ip(a, &len);
    return (ip[0] & 0xFE) == 0xFC ||                         /* ULA */
           (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80);        /* link-local */
}

int elpis_mesh_may_tell(const elpis_addr_t *about, const elpis_addr_t *to)
{
    if (addr_loopback(about))
        return addr_loopback(to);
    if (elpis_mesh_addr_private(about))
        return elpis_mesh_addr_private(to);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Setup                                                               */
/* ------------------------------------------------------------------ */

static int load_psk(const char *path)
{
    char buf[4096];
    struct stat st;
    ssize_t n;
    int fd, rc;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        elpis_error("mesh: cannot read %s: %s", path, strerror(errno));
        return ELPIS_ERR;
    }
    if (fstat(fd, &st) == 0 && (st.st_mode & 077) != 0)
        elpis_warn("mesh: %s can be read by others than its owner; anyone who "
                   "can read it can join the mesh", path);
    n = read(fd, buf, sizeof buf - 1u);
    close(fd);
    if (n < 0) {
        elpis_error("mesh: cannot read %s: %s", path, strerror(errno));
        return ELPIS_ERR;
    }
    buf[n] = '\0';
    rc = elpis_mesh_psk_parse(buf, g_psk);
    elpis_memzero(buf, sizeof buf);
    if (rc != ELPIS_OK)
        elpis_error("mesh: %s does not hold a key: 64 hex digits, as "
                    "elpis --gen-psk writes", path);
    return rc;
}

void elpis_mesh_init(elpis_ctx_t *ctx)
{
    elpis_conf_t *c = &ctx->conf;
    char buf[80], id[9];
    unsigned i;

    g_ctx = ctx;
    g_nlfd = 0;
    if (!c->mesh)
        return;

    if (c->mesh_psk_file[0] == '\0') {
        elpis_error("mesh: 'mesh: yes' needs 'mesh-psk:'; the mesh is off");
        c->mesh = 0;
        return;
    }
    if (c->n_mesh_listen == 0 && c->n_mesh_peer == 0) {
        elpis_error("mesh: neither 'mesh-listen:' nor 'mesh-peer:' is set, so "
                    "there is no one to talk to; the mesh is off");
        c->mesh = 0;
        return;
    }
    if (load_psk(c->mesh_psk_file) != ELPIS_OK) {
        elpis_error("mesh: the mesh is off");
        c->mesh = 0;
        return;
    }

    for (i = 0; i < c->n_mesh_listen; i++) {
        int fd;
        if (elpis_sock_tcp_listen(&c->mesh_listen[i], 0, 64, &fd) != ELPIS_OK) {
            elpis_error("mesh: cannot listen on %s",
                        elpis_addr_str(&c->mesh_listen[i], buf, sizeof buf));
            continue;
        }
        g_lfd[g_nlfd++] = fd;
        if (g_port == 0)
            g_port = elpis_addr_port(&c->mesh_listen[i]);
    }
    if (g_nlfd == 0 && c->n_mesh_peer == 0) {
        elpis_error("mesh: no mesh-listen address could be bound and there "
                    "is no mesh-peer; the mesh is off");
        elpis_memzero(g_psk, sizeof g_psk);
        c->mesh = 0;
        return;
    }
    elpis_random_bytes(g_node, sizeof g_node);
    hex8(g_node, id);
    elpis_info("mesh: node %s, %u listener%s, %u bridge%s", id,
               g_nlfd, g_nlfd == 1 ? "" : "s",
               c->n_mesh_peer, c->n_mesh_peer == 1 ? "" : "s");
}

void elpis_mesh_fini(void)
{
    unsigned i;

    for (i = 0; i < g_nlfd; i++)
        close(g_lfd[i]);
    g_nlfd = 0;
    elpis_ckpt_list_free(&g_gather);
    elpis_memzero(g_psk, sizeof g_psk);
}

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */

static known_t *known_find(const elpis_addr_t *a)
{
    unsigned i;
    for (i = 0; i < g_nknown; i++)
        if (elpis_addr_eq(&g_known[i].a, a))
            return &g_known[i];
    return NULL;
}

static known_t *known_add(const elpis_addr_t *a, int bridge)
{
    known_t *k = known_find(a);

    if (k != NULL)
        return k;
    if (g_nknown >= MESH_MAX_KNOWN)
        return NULL;
    k = &g_known[g_nknown++];
    memset(k, 0, sizeof *k);
    k->a = *a;
    k->bridge = bridge ? 1u : 0u;
    k->backoff = MESH_RETRY_MIN_MS;
    return k;
}

static session_t *session_new(int fd, int initiator, const elpis_addr_t *addr)
{
    session_t *s = (session_t *)elpis_calloc(1, sizeof *s);

    if (s == NULL)
        return NULL;
    s->fd = fd;
    s->initiator = initiator ? 1u : 0u;
    s->addr = *addr;
    elpis_addr_str(addr, s->name, sizeof s->name);
    elpis_ckpt_list_init(&s->incoming);
    elpis_noise_init(&s->hs, initiator, g_psk, (const uint8_t *)MESH_PROLOGUE,
                     sizeof MESH_PROLOGUE - 1u);
    s->last_rx = elpis_now_ms();
    s->deadline = s->last_rx + MESH_HANDSHAKE_MS;
    s->next = g_sessions;
    g_sessions = s;
    g_nsessions++;
    return s;
}

static uint64_t g_last_refusal;     /* one handshake complaint a minute */

static void session_close(session_t *s, const char *why)
{
    uint64_t now = elpis_now_ms();

    if (s->dead)
        return;
    s->dead = 1;
    s->why = why;
    if (s->quiet)
        elpis_debug("mesh: %s: %s", s->name, why);
    else if (s->was_up)
        elpis_info("mesh: %s is gone: %s", s->name, why);
    else if (!s->initiator && s->state == S_HANDSHAKE &&
             now - g_last_refusal >= 60000u) {
        /* Whoever knocks without the key: worth a line, not a line each. */
        g_last_refusal = now;
        elpis_info("mesh: refused %s: %s", s->name, why);
    } else {
        elpis_debug("mesh: %s: %s", s->name, why);
    }
}

static void session_free(session_t *s)
{
    if (s->fd >= 0)
        close(s->fd);
    elpis_free(s->in);
    elpis_free(s->out);
    elpis_ckpt_list_free(&s->incoming);
    elpis_noise_wipe(&s->hs);
    elpis_memzero(&s->tx, sizeof s->tx);
    elpis_memzero(&s->rx, sizeof s->rx);
    elpis_free(s);
}

/* What a closing dial means for the next one to the same address. */
static void known_after(session_t *s, uint64_t now)
{
    known_t *k;

    if (!s->initiator || (k = known_find(&s->dial)) == NULL)
        return;
    k->attempted = 1;
    if (s->was_up) {
        k->backoff = MESH_RETRY_MIN_MS;     /* it worked: come back soon */
        k->fails = 0;
    } else if (!s->quiet) {
        k->fails++;
        if (k->bridge && k->fails == 1)
            elpis_info("mesh: bridge %s: %s; retrying", s->name,
                       s->why ? s->why : "no answer");
        k->backoff = k->backoff * 2u > MESH_RETRY_MAX_MS ? MESH_RETRY_MAX_MS
                                                         : k->backoff * 2u;
    }
    k->next_try = now + k->backoff;
}

static void reap(uint64_t now)
{
    session_t **pp = &g_sessions;

    while (*pp != NULL) {
        session_t *s = *pp;
        if (!s->dead) {
            pp = &s->next;
            continue;
        }
        *pp = s->next;
        g_nsessions--;
        known_after(s, now);
        session_free(s);
    }
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

static void flush(session_t *s)
{
    while (s->outoff < s->outlen) {
        ssize_t n = send(s->fd, s->out + s->outoff, s->outlen - s->outoff,
                         MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            session_close(s, strerror(errno));
            return;
        }
        s->outoff += (size_t)n;
    }
    s->outoff = s->outlen = 0;
}

static int queue(session_t *s, const uint8_t *p, size_t n)
{
    if (s->dead)
        return ELPIS_ERR;
    if (s->outlen - s->outoff + n > MESH_OUT_MAX) {
        session_close(s, "not reading what it asked for");
        return ELPIS_ERR;
    }
    if (s->outoff > 0 && s->outoff == s->outlen)
        s->outoff = s->outlen = 0;
    if (s->outlen + n > s->outcap) {
        size_t nc = s->outcap ? s->outcap : 4096u;
        void *q;
        while (nc < s->outlen + n)
            nc *= 2u;
        q = elpis_realloc(s->out, nc);
        if (q == NULL) {
            session_close(s, "out of memory");
            return ELPIS_ERR;
        }
        s->out = (uint8_t *)q;
        s->outcap = nc;
    }
    memcpy(s->out + s->outlen, p, n);
    s->outlen += n;
    return ELPIS_OK;
}

/* A handshake message: the length, then the bytes as they are. */
static int queue_raw_frame(session_t *s, const uint8_t *p, size_t n)
{
    uint8_t len[2];

    elpis_put16(len, (uint16_t)n);
    if (queue(s, len, 2) != ELPIS_OK)
        return ELPIS_ERR;
    return queue(s, p, n);
}

/* An application message: type and body, sealed. */
static int send_msg(session_t *s, uint8_t type, const uint8_t *body, size_t n)
{
    if (s->state != S_UP || n + 1u > MESH_PLAIN_MAX)
        return ELPIS_ERR;
    /* body may already sit in g_plain: a PONG echoes the PING it read */
    if (n > 0)
        memmove(g_plain + 1, body, n);
    g_plain[0] = type;
    elpis_noise_encrypt(&s->tx, g_plain, n + 1u, g_cipher + 2);
    elpis_put16(g_cipher, (uint16_t)(n + 1u + ELPIS_NOISE_TAG));
    return queue(s, g_cipher, n + 3u + ELPIS_NOISE_TAG);
}

/* ------------------------------------------------------------------ */
/* Name lists                                                          */
/* ------------------------------------------------------------------ */

static void send_list(session_t *s, uint32_t want)
{
    const elpis_conf_t *c = &g_ctx->conf;
    elpis_ckpt_list_t l;
    uint8_t body[MESH_PLAIN_MAX];
    uint8_t end[4];
    size_t used = 0;
    unsigned i, sent = 0;
    uint64_t now = elpis_now_ms();

    elpis_ckpt_list_init(&l);
    /*
     * A peer gets a list at most once a minute, and none at all when this
     * instance keeps its clients' questions to itself.  An empty end is the
     * polite way to say either.
     */
    if (c->mesh_share && (s->last_served == 0 ||
                          now - s->last_served >= MESH_SERVE_EVERY_MS)) {
        s->last_served = now;
        if (want > c->checkpoint_names)
            want = c->checkpoint_names;
        if (elpis_ckpt_collect(g_ctx->mcache, c->mesh_share_min_hits,
                               want ? want : 1u, &l) != ELPIS_OK)
            elpis_ckpt_list_free(&l);
    }

    for (i = 0; i < l.n; i++) {
        const elpis_ckpt_ent_t *e = &l.ent[i];
        uint8_t *p;

        if (used + 10u + e->namelen > sizeof body - 1u) {
            if (send_msg(s, MSG_LIST_PART, body, used) != ELPIS_OK)
                goto out;
            used = 0;
        }
        p = body + used;
        elpis_put32(p, e->hits > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)e->hits);
        elpis_put16(p + 4, e->cost_ms);
        p[6] = e->kflags;
        elpis_put16(p + 7, e->qtype);
        p[9] = e->namelen;
        memcpy(p + 10, elpis_ckpt_name(&l, e), e->namelen);
        used += 10u + e->namelen;
        sent++;
    }
    if (used > 0 && send_msg(s, MSG_LIST_PART, body, used) != ELPIS_OK)
        goto out;
    elpis_put32(end, sent);
    send_msg(s, MSG_LIST_END, end, sizeof end);
    if (sent > 0)
        elpis_info("mesh: sent %u names to %s", sent, s->name);
out:
    elpis_ckpt_list_free(&l);
}

static void recv_list_part(session_t *s, const uint8_t *p, size_t n)
{
    size_t off = 0;

    /* Only what was asked for, and only as much as was asked for. */
    if (!s->asked || s->got_list)
        return;
    while (off + 10u <= n) {
        uint32_t hits = elpis_get32(p + off);
        uint16_t cost = elpis_get16(p + off + 4);
        uint8_t  kf   = p[off + 6];
        uint16_t qt   = elpis_get16(p + off + 7);
        uint8_t  nl   = p[off + 9];
        elpis_name_t name;
        size_t used;

        if (off + 10u + nl > n)
            break;
        if (s->incoming.n < g_ctx->conf.checkpoint_names && nl > 0 &&
            qt != 0 && !elpis_type_is_meta(qt) &&
            elpis_name_parse_nocomp(&name, p + off + 10, nl, &used) == ELPIS_OK &&
            used == nl) {
            elpis_name_lower(&name);
            elpis_ckpt_list_add(&s->incoming, name.d, name.len, qt, kf, hits,
                                cost);
        }
        off += 10u + nl;
    }
}

static void gather_close(void)
{
    char what[96];
    const elpis_conf_t *c = &g_ctx->conf;

    g_gathering = 0;
    if (g_gather_local && g_gather_peers > 0)
        snprintf(what, sizeof what, "the checkpoint and %u peer%s",
                 g_gather_peers, g_gather_peers == 1 ? "" : "s");
    else if (g_gather_peers > 0)
        snprintf(what, sizeof what, "%u peer%s", g_gather_peers,
                 g_gather_peers == 1 ? "" : "s");
    else
        elpis_strlcpy(what, "the checkpoint", sizeof what);
    elpis_ckpt_rank(&g_gather, c->checkpoint_names);
    elpis_warmup_submit(&g_gather, what);
    elpis_ckpt_list_free(&g_gather);
}

static void recv_list_end(session_t *s)
{
    const elpis_conf_t *c = &g_ctx->conf;
    unsigned i, n;

    if (!s->asked || s->got_list)
        return;
    s->got_list = 1;
    n = s->incoming.n;
    if (n == 0) {
        elpis_info("mesh: %s had no names to share", s->name);
        return;
    }
    elpis_info("mesh: %u names from %s", n, s->name);
    if (g_gathering) {
        /* A peer's counts weigh half of ours: they are its clients, not
         * these. */
        if (elpis_ckpt_merge(&g_gather, &s->incoming, 2) == ELPIS_OK)
            g_gather_peers++;
    } else {
        char what[96];
        /* The same half weight a peer's counts get in the gathering. */
        for (i = 0; i < n; i++)
            s->incoming.ent[i].hits = (s->incoming.ent[i].hits + 1u) / 2u;
        elpis_ckpt_rank(&s->incoming, c->checkpoint_names);
        snprintf(what, sizeof what, "peer %s", s->name);
        elpis_warmup_submit(&s->incoming, what);
    }
    elpis_ckpt_list_free(&s->incoming);
}

/* ------------------------------------------------------------------ */
/* Peer exchange                                                       */
/* ------------------------------------------------------------------ */

static void send_peers(session_t *to)
{
    uint8_t body[1u + 64u * 19u];
    size_t used = 1;
    unsigned count = 0;
    session_t *s;

    for (s = g_sessions; s != NULL && count < 64u; s = s->next) {
        const uint8_t *ip;
        unsigned len;

        if (s == to || s->dead || s->state != S_UP || !s->has_listen)
            continue;
        if (!elpis_mesh_may_tell(&s->listen, &to->addr))
            continue;
        ip = addr_ip(&s->listen, &len);
        body[used] = (uint8_t)(len == 4 ? 4 : 6);
        memcpy(body + used + 1, ip, len);
        elpis_put16(body + used + 1 + len, elpis_addr_port(&s->listen));
        used += 3u + len;
        count++;
    }
    body[0] = (uint8_t)count;
    if (count > 0)
        send_msg(to, MSG_PEERS, body, used);
    to->last_pex = elpis_now_ms();
}

static void recv_peers(session_t *s, const uint8_t *p, size_t n)
{
    unsigned count, i;
    size_t off = 1;

    if (n < 1)
        return;
    count = p[0];
    for (i = 0; i < count; i++) {
        elpis_addr_t a;
        unsigned len;

        if (off + 1u > n)
            return;
        len = p[off] == 4 ? 4u : p[off] == 6 ? 16u : 0u;
        if (len == 0 || off + 3u + len > n)
            return;
        if (len == 4)
            elpis_addr_from4(&a, p + off + 1, elpis_get16(p + off + 1 + len));
        else
            elpis_addr_from6(&a, p + off + 1, elpis_get16(p + off + 1 + len));
        off += 3u + len;
        /* The same rule the sender should have kept, in case it did not. */
        if (elpis_addr_port(&a) == 0 || !elpis_mesh_may_tell(&a, &s->addr))
            continue;
        if (known_find(&a) == NULL && known_add(&a, 0) != NULL) {
            char buf[64];
            elpis_debug("mesh: heard of %s from %s",
                        elpis_addr_str(&a, buf, sizeof buf), s->name);
        }
    }
}

/* ------------------------------------------------------------------ */
/* The handshake                                                       */
/* ------------------------------------------------------------------ */

static void hello_make(uint8_t out[HELLO_LEN])
{
    out[0] = (uint8_t)MESH_VERSION;
    out[1] = g_ctx->conf.mesh_share ? HELLO_SHARES : 0u;
    elpis_put16(out + 2, g_port);
    memcpy(out + 4, g_node, 16);
}

static session_t *session_by_node(const uint8_t node[16], const session_t *not)
{
    session_t *s;
    for (s = g_sessions; s != NULL; s = s->next)
        if (s != not && !s->dead && s->state == S_UP &&
            memcmp(s->node, node, 16) == 0)
            return s;
    return NULL;
}

/* The node that dialled this session. */
static const uint8_t *dialler(const session_t *s)
{
    return s->initiator ? g_node : s->node;
}

static void session_up(session_t *s, const uint8_t *hello, size_t n)
{
    const elpis_conf_t *c = &g_ctx->conf;
    session_t *twin;
    char id[9];
    uint64_t now = elpis_now_ms();

    if (n < HELLO_LEN || hello[0] != MESH_VERSION) {
        session_close(s, "speaks another version of the mesh");
        return;
    }
    memcpy(s->node, hello + 4, 16);
    if (memcmp(s->node, g_node, 16) == 0) {
        known_t *k = s->initiator ? known_find(&s->dial) : NULL;
        if (k != NULL)
            k->self = 1;            /* never dial ourselves again */
        s->quiet = 1;
        session_close(s, "this is us");
        return;
    }
    elpis_noise_split(&s->hs, &s->tx, &s->rx);
    s->state = S_UP;
    s->was_up = 1;
    s->shares = (hello[1] & HELLO_SHARES) ? 1u : 0u;
    if (elpis_get16(hello + 2) != 0) {
        s->listen = s->addr;
        if (elpis_addr_family(&s->listen) == AF_INET)
            s->listen.u.v4.sin_port = htons(elpis_get16(hello + 2));
        else
            s->listen.u.v6.sin6_port = htons(elpis_get16(hello + 2));
        s->has_listen = 1;
        /* Known by where it takes connections, not by a passing port. */
        elpis_addr_str(&s->listen, s->name, sizeof s->name);
    }
    if (s->initiator) {
        known_t *k = known_find(&s->dial);
        if (k != NULL) {
            k->attempted = 1;
            k->fails = 0;
            k->backoff = MESH_RETRY_MIN_MS;
        }
    }

    /*
     * Two sessions with one node -- both sides dialled at once.  Both ends
     * keep the one dialled by the smaller node id, so they agree on which
     * without saying a word; a redial from the same side replaces the old.
     */
    twin = session_by_node(s->node, s);
    if (twin != NULL) {
        int c1 = memcmp(dialler(s), dialler(twin), 16);
        if (c1 <= 0) {
            twin->quiet = 1;                    /* not a loss: s replaces it */
            session_close(twin, "replaced by a newer session");
        } else {
            s->quiet = 1;
            session_close(s, "already connected");
            return;
        }
    }

    hex8(s->node, id);
    elpis_info("mesh: up with %s (node %s, %s)", s->name, id,
               s->initiator ? "we dialled" : "it dialled");
    s->last_ping = now;

    if (c->warm_rate > 0 && s->shares && now - g_t0 < MESH_ASK_WINDOW_MS) {
        uint8_t want[4];
        elpis_put32(want, c->checkpoint_names);
        if (send_msg(s, MSG_LIST_REQ, want, sizeof want) == ELPIS_OK)
            s->asked = 1;
    }
    send_peers(s);
}

static void on_frame(session_t *s, const uint8_t *p, size_t n)
{
    uint8_t hello[HELLO_LEN], out[HELLO_LEN + ELPIS_NOISE_HS_OVERHEAD];
    size_t plen, olen;

    s->last_rx = elpis_now_ms();

    if (s->state == S_HANDSHAKE) {
        if (n > HELLO_LEN + 64u + ELPIS_NOISE_HS_OVERHEAD ||
            elpis_noise_read(&s->hs, p, n, g_plain, sizeof g_plain,
                             &plen) != ELPIS_OK) {
            /* The one thing a wrong PSK looks like from either end. */
            session_close(s, "handshake failed (a different mesh-psk?)");
            return;
        }
        if (!s->initiator) {
            hello_make(hello);
            if (elpis_noise_write(&s->hs, hello, sizeof hello, out, sizeof out,
                                  &olen) != ELPIS_OK ||
                queue_raw_frame(s, out, olen) != ELPIS_OK) {
                session_close(s, "handshake failed");
                return;
            }
            /* Out now: if this turns out to be us, our dialling side has
             * to read it to learn so. */
            flush(s);
        }
        session_up(s, g_plain, plen);
        return;
    }

    if (s->state != S_UP)
        return;
    if (n < 1u + ELPIS_NOISE_TAG ||
        elpis_noise_decrypt(&s->rx, p, n, g_plain) != ELPIS_OK) {
        session_close(s, "a message that does not decrypt");
        return;
    }
    plen = n - ELPIS_NOISE_TAG;

    switch (g_plain[0]) {
    case MSG_LIST_REQ:
        send_list(s, plen >= 5u ? elpis_get32(g_plain + 1) : 0u);
        break;
    case MSG_LIST_PART:
        recv_list_part(s, g_plain + 1, plen - 1u);
        break;
    case MSG_LIST_END:
        recv_list_end(s);
        break;
    case MSG_PEERS:
        recv_peers(s, g_plain + 1, plen - 1u);
        break;
    case MSG_PING:
        if (plen >= 9u)
            send_msg(s, MSG_PONG, g_plain + 1, 8);
        break;
    case MSG_PONG:
        if (plen >= 9u) {
            uint64_t sent = ((uint64_t)elpis_get32(g_plain + 1) << 32) |
                            elpis_get32(g_plain + 5);
            uint64_t now = elpis_now_ms();
            if (sent <= now)
                s->rtt_ms = (uint32_t)(now - sent);
        }
        break;
    default:
        break;                      /* a later version's message */
    }
}

static void on_readable(session_t *s)
{
    for (;;) {
        ssize_t n;

        if (s->incap - s->inlen < 4096u) {
            size_t nc = s->incap ? s->incap * 2u : 8192u;
            void *q;
            if (nc > 4u + 2u * MESH_FRAME_MAX)
                nc = 4u + 2u * MESH_FRAME_MAX;
            if (nc <= s->incap) {
                session_close(s, "sent more than one message can hold");
                return;
            }
            q = elpis_realloc(s->in, nc);
            if (q == NULL) {
                session_close(s, "out of memory");
                return;
            }
            s->in = (uint8_t *)q;
            s->incap = nc;
        }
        n = recv(s->fd, s->in + s->inlen, s->incap - s->inlen, 0);
        if (n == 0) {
            session_close(s, s->state == S_UP ? "closed"
                             : "closed during the handshake (a different "
                               "mesh-psk?)");
            return;
        }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                session_close(s, strerror(errno));
            break;
        }
        s->inlen += (size_t)n;

        /* Every whole frame in the buffer. */
        {
            size_t off = 0;
            while (!s->dead && s->inlen - off >= 2u) {
                size_t flen = elpis_get16(s->in + off);
                if (flen == 0) {
                    session_close(s, "an empty message");
                    break;
                }
                if (s->inlen - off < 2u + flen)
                    break;
                on_frame(s, s->in + off + 2, flen);
                off += 2u + flen;
            }
            if (off > 0) {
                memmove(s->in, s->in + off, s->inlen - off);
                s->inlen -= off;
            }
        }
        if (s->dead)
            return;
    }
}

/* Our dial connected: say message 1. */
static void on_connected(session_t *s)
{
    uint8_t hello[HELLO_LEN], out[HELLO_LEN + ELPIS_NOISE_HS_OVERHEAD];
    int err = 0;
    socklen_t len = sizeof err;
    size_t olen;

    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
        session_close(s, strerror(err ? err : errno));
        return;
    }
    s->state = S_HANDSHAKE;
    hello_make(hello);
    if (elpis_noise_write(&s->hs, hello, sizeof hello, out, sizeof out,
                          &olen) != ELPIS_OK ||
        queue_raw_frame(s, out, olen) != ELPIS_OK) {
        session_close(s, "handshake failed");
        return;
    }
    flush(s);
}

/* ------------------------------------------------------------------ */
/* The loop                                                            */
/* ------------------------------------------------------------------ */

static int known_connected(const known_t *k)
{
    const session_t *s;
    for (s = g_sessions; s != NULL; s = s->next) {
        if (s->dead)
            continue;
        if (s->initiator && elpis_addr_eq(&s->dial, &k->a))
            return 1;
        if (s->state == S_UP && s->has_listen && elpis_addr_eq(&s->listen, &k->a))
            return 1;
    }
    return 0;
}

static void dial_due(uint64_t now)
{
    unsigned i;
    uint32_t max = g_ctx->conf.mesh_max_peers;

    for (i = 0; i < g_nknown && g_nsessions < max; i++) {
        known_t *k = &g_known[i];
        session_t *s;
        int fd;

        if (k->self || now < k->next_try || known_connected(k))
            continue;
        if (!k->bridge && k->fails >= MESH_LEARNED_TRIES)
            continue;
        k->next_try = now + k->backoff;     /* until this dial says otherwise */
        if (elpis_sock_tcp_connect(&k->a, NULL, &fd) != ELPIS_OK) {
            k->fails++;
            k->attempted = 1;
            continue;
        }
        s = session_new(fd, 1, &k->a);
        if (s == NULL) {
            close(fd);
            continue;
        }
        s->dial = k->a;
        s->state = S_CONNECTING;
    }
}

static void on_accept(int lfd)
{
    for (;;) {
        elpis_addr_t a;
        int fd;

        memset(&a, 0, sizeof a);
        a.len = sizeof a.u.ss;
        fd = accept(lfd, &a.u.sa, &a.len);
        if (fd < 0)
            return;
        if (g_nsessions >= MESH_MAX_SESSIONS ||
            elpis_sock_nonblock(fd) != ELPIS_OK) {
            close(fd);
            continue;
        }
        elpis_sock_cloexec(fd);
        elpis_sock_tune_tcp(fd);
        {
            session_t *s = session_new(fd, 0, &a);
            if (s == NULL)
                close(fd);
            else
                s->state = S_HANDSHAKE;
        }
    }
}

static void timers(uint64_t now)
{
    session_t *s;

    for (s = g_sessions; s != NULL; s = s->next) {
        if (s->dead)
            continue;
        if (s->state != S_UP) {
            if (now >= s->deadline)
                session_close(s, s->state == S_CONNECTING ? "no answer"
                                                           : "handshake timed out");
            continue;
        }
        if (now - s->last_rx >= MESH_IDLE_MS) {
            session_close(s, "silent too long");
            continue;
        }
        if (now - s->last_ping >= MESH_PING_MS) {
            uint8_t tok[8];
            elpis_put32(tok, (uint32_t)(now >> 32));
            elpis_put32(tok + 4, (uint32_t)now);
            send_msg(s, MSG_PING, tok, sizeof tok);
            s->last_ping = now;
        }
        if (now - s->last_pex >= MESH_PEX_EVERY_MS)
            send_peers(s);
    }

    /*
     * The startup gathering ends when its time is up, or sooner once every
     * bridge has had a try and every peer asked has answered.  Without
     * bridges the peers have to find this instance, so it waits it out.
     */
    if (g_gathering) {
        int ready = now - g_t0 >= MESH_GATHER_MS;
        if (!ready && g_ctx->conf.n_mesh_peer > 0) {
            unsigned i;
            ready = 1;
            for (i = 0; i < g_nknown && ready; i++)
                if (g_known[i].bridge && !g_known[i].self && !g_known[i].attempted)
                    ready = 0;
            for (s = g_sessions; s != NULL && ready; s = s->next)
                if (!s->dead && (s->state != S_UP || (s->asked && !s->got_list)))
                    ready = 0;
        }
        if (ready)
            gather_close();
    }
}

void *elpis_mesh_main(void *arg)
{
    elpis_ctx_t *ctx = (elpis_ctx_t *)arg;
    const elpis_conf_t *c = &ctx->conf;
    struct pollfd pf[ELPIS_MESH_MAX_LISTEN + MESH_MAX_SESSIONS];
    session_t *ps[MESH_MAX_SESSIONS];
    unsigned i;

    g_t0 = elpis_now_ms();
    for (i = 0; i < c->n_mesh_peer; i++)
        known_add(&c->mesh_peer[i], 1);

    elpis_ckpt_take_startup(&g_gather);
    g_gather_local = g_gather.n > 0;
    g_gathering = c->warm_rate > 0;
    if (!g_gathering)
        elpis_ckpt_list_free(&g_gather);

    while (!ctx->shutdown) {
        uint64_t now = elpis_now_ms();
        unsigned nf = 0, ns = 0, l;
        session_t *s;
        int n;

        dial_due(now);
        timers(now);
        reap(now);

        for (l = 0; l < g_nlfd; l++) {
            pf[nf].fd = g_lfd[l];
            pf[nf].events = POLLIN;
            pf[nf].revents = 0;
            nf++;
        }
        for (s = g_sessions; s != NULL && ns < MESH_MAX_SESSIONS; s = s->next) {
            pf[nf].fd = s->fd;
            pf[nf].events = POLLIN;
            if (s->state == S_CONNECTING || s->outlen > s->outoff)
                pf[nf].events |= POLLOUT;
            pf[nf].revents = 0;
            ps[ns++] = s;
            nf++;
        }

        n = poll(pf, nf, 250);
        if (n <= 0)
            continue;

        for (l = 0; l < g_nlfd; l++)
            if (pf[l].revents & POLLIN)
                on_accept(g_lfd[l]);
        for (i = 0; i < ns; i++) {
            short ev = pf[g_nlfd + i].revents;
            s = ps[i];
            if (ev == 0 || s->dead)
                continue;
            if (s->state == S_CONNECTING) {
                if (ev & (POLLOUT | POLLERR | POLLHUP))
                    on_connected(s);
                continue;
            }
            if (ev & (POLLIN | POLLHUP | POLLERR))
                on_readable(s);
            if (!s->dead && s->outlen > s->outoff)
                flush(s);
        }
        reap(elpis_now_ms());
    }

    while (g_sessions != NULL) {
        session_t *s = g_sessions;
        g_sessions = s->next;
        session_free(s);
    }
    g_nsessions = 0;
    return NULL;
}
