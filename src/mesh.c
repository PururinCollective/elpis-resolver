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
 *
 * Peers are found three ways: the bridges in mesh-peer:, the peers those
 * report (PEERS), and on the local segment by multicast (see "Local service
 * discovery" below).  All three only say where to dial; the handshake is
 * what lets anyone in.
 */
#include "elpis/mesh.h"
#include "elpis/noise.h"
#include "elpis/checkpoint.h"
#include "elpis/store.h"
#include "elpis/crypto.h"
#include "elpis/sock.h"
#include "elpis/util.h"
#include "elpis/log.h"
#include "elpis/licence.h"
#include "elpis/simd.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
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
/* The largest handshake message: a hello and a certificate, with keys. */
#define MESH_HS_MAX          2048u
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
       MSG_PING = 5, MSG_PONG = 6, MSG_LOOKUP_KEY = 7, MSG_DIGEST = 8 };
/* S_CONFIRM: a licensed dialler's handshake is done on its side, and it
 * waits for the first word back to know its certificate was taken. */
enum { S_CONNECTING, S_HANDSHAKE, S_CONFIRM, S_UP };

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
    unsigned          loud      : 1;   /* its end is always news        */
    unsigned          asked     : 1;   /* we asked for its list        */
    unsigned          got_list  : 1;
    unsigned          shares    : 1;   /* its hello says it answers    */
    unsigned          has_listen: 1;
    unsigned          has_want  : 1;   /* we dialled a known node id    */
    elpis_addr_t      addr;            /* the far end of the socket     */
    elpis_addr_t      dial;            /* what we dialled, as initiator */
    elpis_addr_t      listen;          /* where it takes connections    */
    uint8_t           node[16];
    uint8_t           want[16];        /* the node id we expect, if known */
    elpis_noise_hs_t  hs;
    elpis_noise_cs_t  tx, rx;
    uint8_t          *in;
    size_t            inlen, incap;
    uint8_t          *out;
    size_t            outlen, outoff, outcap;
    uint64_t          deadline, last_rx, last_ping, last_pex, last_served;
    uint32_t          rtt_ms;          /* 0 until measured               */
    uint32_t          cert_serial;     /* its certificate, when licensed */
    char              whybuf[128];
    uint64_t          last_digest;
    /* A digest arriving in parts. */
    uint8_t          *dg;
    uint32_t          dg_seq, dg_got;
    const char       *why;             /* why it closed                  */
    elpis_ckpt_list_t incoming;
    char              name[64];
} session_t;

typedef struct {
    elpis_addr_t a;
    unsigned     bridge    : 1;        /* named in mesh-peer:           */
    unsigned     self      : 1;        /* it turned out to be us        */
    unsigned     attempted : 1;        /* one dial has run its course   */
    unsigned     has_node  : 1;        /* announced on the segment      */
    uint8_t      node[16];
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
/*
 * A licensed mesh (mesh-require-licence): this instance's static key, and
 * what its certificate says.  The certificate itself is conf.mesh_cert.
 */
static int          g_licensed;
static uint8_t      g_skey[32], g_spub[32];
static char         g_cert_org[ELPIS_LICENCE_MAX_ORG + 1];
/* Local service discovery: a socket per family, and the announcement key. */
static int          g_lsd4 = -1, g_lsd6 = -1;
/* The port each family's announcement names: that family's listener, or 0
 * when it has none the segment could reach -- nothing to announce. */
static uint16_t     g_lsd_port4, g_lsd_port6;
static uint8_t      g_lsd_key[32];
static uint64_t     g_lsd_next;
static unsigned     g_lsd_sent;
/* Startup: the checkpoint, and the peers' lists as they arrive. */
static elpis_ckpt_list_t g_gather;
static int          g_gathering;
static unsigned     g_gather_peers;
static int          g_gather_local;
/*
 * One thread, so one buffer each: a message being built (g_plain, then
 * g_cipher) and a message received (g_rx).  Apart, because handling what
 * arrives can mean sending something -- a PONG, or everything a session
 * sends once it is ready -- before the received message has been read.
 */
static uint8_t      g_plain[MESH_FRAME_MAX];
static uint8_t      g_cipher[2u + MESH_FRAME_MAX];
static uint8_t      g_rx[MESH_FRAME_MAX];

/*
 * What the workers need to ask a peer, kept apart from the sessions (which
 * are this thread's alone) behind a read-write lock: every worker reads it on
 * a miss, and this thread changes it when a peer comes or goes, sends a key,
 * or sends a digest.
 */
typedef struct {
    uint8_t      node[16];
    elpis_addr_t addr;             /* its mesh port, over UDP           */
    uint32_t     rtt_ms;           /* 0 until measured                  */
    uint32_t     key_id;
    uint8_t      key[32];
    unsigned     has_key : 1;
    uint8_t     *bloom;
    uint32_t     bloom_bits;
    uint8_t      bloom_k;
} ptab_t;

static pthread_rwlock_t g_ptab_lock = PTHREAD_RWLOCK_INITIALIZER;
static ptab_t   g_ptab[MESH_MAX_SESSIONS];
static unsigned g_nptab;

/* This instance's own lookup keys: the current one, and the one before it
 * for the minutes after a rotation while peers still use it. */
#define MESH_LQ_ROTATE_MS (60u * 60u * 1000u)
static uint8_t  g_lqkey[2][32];
static uint32_t g_lqid[2];
static uint64_t g_lq_rotated;
static int      g_lqfd[ELPIS_MESH_MAX_LISTEN];
static unsigned g_nlqfd;

/* The digest last built from the message cache, and when. */
#define DIGEST_EVERY_MS 30000u
#define DIGEST_K        7u
#define DIGEST_MIN_BITS (1u << 13)
#define DIGEST_MAX_BITS (1u << 24)
#define DIGEST_CHUNK    60000u
static uint8_t *g_digest;
static uint32_t g_digest_bits, g_digest_seq;
static uint64_t g_digest_at;

static void lq_new_key(void);

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

static int addr_v6_linklocal(const elpis_addr_t *a)
{
    unsigned len;
    const uint8_t *ip = addr_ip(a, &len);
    return len == 16 && ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80;
}

int elpis_mesh_may_tell(const elpis_addr_t *about, const elpis_addr_t *to)
{
    /* An IPv6 link-local address means nothing without its interface, and
     * the interface is this host's, not the listener's. */
    if (addr_v6_linklocal(about))
        return 0;
    if (addr_loopback(about))
        return addr_loopback(to);
    if (elpis_mesh_addr_private(about))
        return elpis_mesh_addr_private(to);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Local service discovery: the packet and the sockets                 */
/* ------------------------------------------------------------------ */

/*
 * On one network segment the instances need no mesh-peer: at all.  Each one
 * that takes connections announces itself to a multicast group, at startup
 * and then every half minute, and the others dial it.
 *
 * Not BitTorrent's LSD group: a torrent client would get these, and this
 * would get theirs.  239.255.78.78 is administratively scoped (RFC 2365) and
 * ff12::7878 is link-local with the transient flag, which is what a group
 * nobody assigned is meant to use; a hop limit of 1 keeps both on the segment.
 *
 * An announcement is 44 bytes:
 *
 *   "ELPISLSD", u8 version, u8 flags, u16 mesh port, node id[16], tag[16]
 *
 * The tag is HMAC-SHA256, cut to 16 bytes, under a key derived from the PSK,
 * so only an instance of this mesh can make the others dial it: one from
 * another mesh or from a stranger is dropped unread.  A copy replayed from
 * another address makes an instance dial that address, at the announced
 * port, now and then -- a connection that fails its handshake.
 */
#define LSD_PORT      7878
#define LSD_GROUP4    "239.255.78.78"
#define LSD_GROUP6    "ff12::7878"
#define LSD_MAGIC     "ELPISLSD"
#define LSD_EVERY_MS  30000u

void elpis_mesh_lsd_key(const uint8_t psk[32], uint8_t key[32])
{
    static const char label[] = "elpis mesh lsd 1";
    /* A key of its own, so the PSK is never used directly in two places. */
    elpis_hmac_sha256(psk, 32, (const uint8_t *)label, sizeof label - 1u, key);
}

void elpis_mesh_lsd_make(const uint8_t key[32], const uint8_t node[16],
                         uint16_t port, uint8_t out[ELPIS_MESH_LSD_LEN])
{
    uint8_t mac[32];

    memcpy(out, LSD_MAGIC, 8);
    out[8] = (uint8_t)MESH_VERSION;
    out[9] = 0;
    elpis_put16(out + 10, port);
    memcpy(out + 12, node, 16);
    elpis_hmac_sha256(key, 32, out, 28, mac);
    memcpy(out + 28, mac, 16);
}

int elpis_mesh_lsd_check(const uint8_t key[32], const uint8_t *p, size_t n,
                         uint8_t node[16], uint16_t *port)
{
    uint8_t mac[32];

    if (n != ELPIS_MESH_LSD_LEN || memcmp(p, LSD_MAGIC, 8) != 0 ||
        p[8] != MESH_VERSION)
        return ELPIS_ERR;
    elpis_hmac_sha256(key, 32, p, 28, mac);
    if (!elpis_ct_eq(mac, p + 28, 16))
        return ELPIS_ERR;
    *port = elpis_get16(p + 10);
    memcpy(node, p + 12, 16);
    return *port != 0 ? ELPIS_OK : ELPIS_ERR;
}

/*
 * One socket per family, bound to the group's port with SO_REUSEPORT so every
 * instance on a host hears every announcement, including its own (which it
 * recognises by node id).  `ifaddr` is the IPv4 address to send and listen
 * on, or NULL for the one the routing table picks.
 */
static int lsd_open(int family, const elpis_addr_t *ifaddr)
{
    int fd, one = 1, hops = 1;
    elpis_addr_t any;

    fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    elpis_sock_cloexec(fd);
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    if (family == AF_INET) {
        struct ip_mreq mr;
        uint8_t zero[4] = { 0, 0, 0, 0 };
        unsigned char ttl = 1, loop = 1;

        elpis_addr_from4(&any, zero, LSD_PORT);
        if (bind(fd, &any.u.sa, any.len) != 0)
            goto fail;
        memset(&mr, 0, sizeof mr);
        inet_pton(AF_INET, LSD_GROUP4, &mr.imr_multiaddr);
        mr.imr_interface.s_addr = htonl(INADDR_ANY);
        if (ifaddr != NULL) {
            mr.imr_interface = ifaddr->u.v4.sin_addr;
            (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                             &mr.imr_interface, sizeof mr.imr_interface);
        }
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr) != 0)
            goto fail;
        (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
        (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop);
    } else {
        struct ipv6_mreq mr;
        uint8_t zero[16];
        unsigned loop = 1;

        memset(zero, 0, sizeof zero);
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        elpis_addr_from6(&any, zero, LSD_PORT);
        if (bind(fd, &any.u.sa, any.len) != 0)
            goto fail;
        memset(&mr, 0, sizeof mr);
        inet_pton(AF_INET6, LSD_GROUP6, &mr.ipv6mr_multiaddr);
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr, sizeof mr) != 0)
            goto fail;
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof hops);
        (void)setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof loop);
    }
    if (elpis_sock_nonblock(fd) != ELPIS_OK)
        goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Setup                                                               */
/* ------------------------------------------------------------------ */

/* A 32-byte key from a file of 64 hex digits, as --gen-psk and
 * --mesh-keygen write them.  `made_by` names which, for the error. */
static int load_key32(const char *path, uint8_t out[32], const char *made_by)
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
        elpis_warn("mesh: %s can be read by others than its owner, and it "
                   "is a secret", path);
    n = read(fd, buf, sizeof buf - 1u);
    close(fd);
    if (n < 0) {
        elpis_error("mesh: cannot read %s: %s", path, strerror(errno));
        return ELPIS_ERR;
    }
    buf[n] = '\0';
    rc = elpis_mesh_psk_parse(buf, out);
    elpis_memzero(buf, sizeof buf);
    if (rc != ELPIS_OK)
        elpis_error("mesh: %s does not hold a key: 64 hex digits, as %s "
                    "writes", path, made_by);
    return rc;
}

int elpis_mesh_gen_key(void)
{
    uint8_t k[32], pub[32];
    unsigned i;

    elpis_random_bytes(k, sizeof k);
    elpis_x25519_base(pub, k);
    printf("# elpis mesh instance key: this instance's alone, readable by root\n"
           "# alone.  Point mesh-key: at it.\n");
    for (i = 0; i < sizeof k; i++)
        printf("%02x", k[i]);
    printf("\n");
    fprintf(stderr, "public key, for the licence issuer to certify:\n\n  ");
    for (i = 0; i < sizeof pub; i++)
        fprintf(stderr, "%02x", pub[i]);
    fprintf(stderr, "\n\n  elpis-licence issue --key issuer.key --org \"...\" "
            "--mesh-key <that key> --days 365\n");
    elpis_memzero(k, sizeof k);
    return 0;
}

/*
 * mesh-require-licence: this instance's key, and a certificate for it that
 * this build's issuer signed, has not expired, and names that same key.
 * Anything less and there is nothing to show a peer, so the mesh stays off.
 */
static int licensed_setup(const elpis_conf_t *c)
{
    elpis_meshcert_t cert;
    char when[32];

    if (!elpis_licence_enabled()) {
        elpis_error("mesh: mesh-require-licence needs a build that carries the "
                    "licence issuer's key, and this one has none");
        return ELPIS_ERR;
    }
    if (c->mesh_key_file[0] == '\0' || c->mesh_cert[0] == '\0') {
        elpis_error("mesh: mesh-require-licence needs mesh-key: (from elpis "
                    "--mesh-keygen) and mesh-cert: (from the issuer)");
        return ELPIS_ERR;
    }
    if (load_key32(c->mesh_key_file, g_skey, "elpis --mesh-keygen") != ELPIS_OK)
        return ELPIS_ERR;
    elpis_x25519_base(g_spub, g_skey);
    if (elpis_meshcert_parse(c->mesh_cert, elpis_wall_s(), &cert) != ELPIS_OK) {
        elpis_error("mesh: mesh-cert does not verify: %s", cert.why);
        return ELPIS_ERR;
    }
    elpis_licence_date(cert.expires, when, sizeof when);
    if (cert.expired) {
        elpis_error("mesh: mesh-cert expired on %s; the issuer can make a new "
                    "one for the same key", when);
        return ELPIS_ERR;
    }
    if (memcmp(cert.key, g_spub, 32) != 0) {
        elpis_error("mesh: mesh-cert was issued for another key than the one "
                    "in %s", c->mesh_key_file);
        return ELPIS_ERR;
    }
    elpis_strlcpy(g_cert_org, cert.org, sizeof g_cert_org);
    g_licensed = 1;
    elpis_info("mesh: licensed to \"%s\" (certificate %lu, expires %s); "
               "peers must be too", cert.org, (unsigned long)cert.serial, when);
    return ELPIS_OK;
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
    if (c->n_mesh_listen == 0 && c->n_mesh_peer == 0 && !c->mesh_lsd) {
        elpis_error("mesh: no 'mesh-listen:', no 'mesh-peer:' and 'mesh-lsd: "
                    "no', so there is no one to talk to; the mesh is off");
        c->mesh = 0;
        return;
    }
    if (load_key32(c->mesh_psk_file, g_psk, "elpis --gen-psk") != ELPIS_OK) {
        elpis_error("mesh: the mesh is off");
        c->mesh = 0;
        return;
    }
    if (c->mesh_require_licence && licensed_setup(c) != ELPIS_OK) {
        elpis_error("mesh: the mesh is off");
        elpis_memzero(g_psk, sizeof g_psk);
        elpis_memzero(g_skey, sizeof g_skey);
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
        /* Lookups arrive on the same address and port, over UDP. */
        if (elpis_sock_udp_listen(&c->mesh_listen[i], 0, &fd) == ELPIS_OK)
            g_lqfd[g_nlqfd++] = fd;
        else
            elpis_warn("mesh: cannot take lookups on UDP %s",
                       elpis_addr_str(&c->mesh_listen[i], buf, sizeof buf));
        /* Loopback cannot be reached from the segment, so it is not
         * announced there. */
        if (!addr_loopback(&c->mesh_listen[i])) {
            uint16_t *pp = elpis_addr_family(&c->mesh_listen[i]) == AF_INET
                           ? &g_lsd_port4 : &g_lsd_port6;
            if (*pp == 0)
                *pp = elpis_addr_port(&c->mesh_listen[i]);
        }
    }
    if (c->mesh_lsd) {
        /* Announce from, and listen on, the listener's own IPv4 address when
         * it names one, so the others dial the address it is on. */
        const elpis_addr_t *ifa = NULL;
        for (i = 0; i < c->n_mesh_listen; i++) {
            const elpis_addr_t *a = &c->mesh_listen[i];
            if (elpis_addr_family(a) == AF_INET &&
                a->u.v4.sin_addr.s_addr != htonl(INADDR_ANY)) {
                ifa = a;
                break;
            }
        }
        g_lsd4 = lsd_open(AF_INET, ifa);
        g_lsd6 = lsd_open(AF_INET6, NULL);
        if (g_lsd4 < 0 && g_lsd6 < 0)
            elpis_warn("mesh: cannot join the local discovery groups (UDP %u): "
                       "only mesh-peer: will find peers", (unsigned)LSD_PORT);
        elpis_mesh_lsd_key(g_psk, g_lsd_key);
    }
    if (g_nlfd == 0 && c->n_mesh_peer == 0 && g_lsd4 < 0 && g_lsd6 < 0) {
        elpis_error("mesh: no mesh-listen address could be bound, there is no "
                    "mesh-peer and no local discovery; the mesh is off");
        elpis_memzero(g_psk, sizeof g_psk);
        c->mesh = 0;
        return;
    }
    elpis_random_bytes(g_node, sizeof g_node);
    lq_new_key();
    g_lq_rotated = elpis_now_ms();
    hex8(g_node, id);
    elpis_info("mesh: node %s, %u listener%s, %u bridge%s, local discovery %s",
               id, g_nlfd, g_nlfd == 1 ? "" : "s",
               c->n_mesh_peer, c->n_mesh_peer == 1 ? "" : "s",
               g_lsd4 >= 0 && g_lsd6 >= 0 ? "on IPv4 and IPv6"
               : g_lsd4 >= 0 ? "on IPv4" : g_lsd6 >= 0 ? "on IPv6" : "off");
}

void elpis_mesh_fini(void)
{
    unsigned i;

    for (i = 0; i < g_nlfd; i++)
        close(g_lfd[i]);
    g_nlfd = 0;
    if (g_lsd4 >= 0)
        close(g_lsd4);
    if (g_lsd6 >= 0)
        close(g_lsd6);
    g_lsd4 = g_lsd6 = -1;
    for (i = 0; i < g_nlqfd; i++)
        close(g_lqfd[i]);
    g_nlqfd = 0;
    elpis_free(g_digest);
    g_digest = NULL;
    pthread_rwlock_wrlock(&g_ptab_lock);
    for (i = 0; i < g_nptab; i++)
        elpis_free(g_ptab[i].bloom);
    elpis_memzero(g_ptab, sizeof g_ptab);
    g_nptab = 0;
    pthread_rwlock_unlock(&g_ptab_lock);
    elpis_memzero(g_lqkey, sizeof g_lqkey);
    elpis_memzero(g_skey, sizeof g_skey);
    elpis_memzero(g_lsd_key, sizeof g_lsd_key);
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
    elpis_noise_init(&s->hs, g_licensed ? ELPIS_NOISE_XX_PSK0 : ELPIS_NOISE_NN_PSK0,
                     initiator, g_psk, (const uint8_t *)MESH_PROLOGUE,
                     sizeof MESH_PROLOGUE - 1u);
    if (g_licensed)
        elpis_noise_set_static(&s->hs, g_skey);
    s->last_rx = elpis_now_ms();
    s->deadline = s->last_rx + MESH_HANDSHAKE_MS;
    s->next = g_sessions;
    g_sessions = s;
    g_nsessions++;
    return s;
}

static session_t *session_by_node(const uint8_t node[16], const session_t *not);
static void ptab_down(const uint8_t node[16]);

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
    else if (!s->initiator && s->state == S_HANDSHAKE && s->loud)
        /* One that holds the PSK and still is not let in: always news. */
        elpis_info("mesh: refused %s: %s", s->name, why);
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
    elpis_free(s->dg);
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
        /* A replacement for the same node keeps its place in the table. */
        if (s->was_up && session_by_node(s->node, s) == NULL)
            ptab_down(s->node);
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
    if (n > 0)
        memcpy(g_plain + 1, body, n);
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
/* Live lookups: the peer table, digests, and answering                */
/* ------------------------------------------------------------------ */


uint64_t elpis_mesh_qhash(const uint8_t *qname, uint8_t len, uint16_t qtype,
                          uint8_t kflags)
{
    uint64_t h = 0xCBF29CE484222325ull;
    unsigned i;

    for (i = 0; i < len; i++)
        h = (h ^ qname[i]) * 0x100000001B3ull;
    h = (h ^ (uint8_t)(qtype >> 8)) * 0x100000001B3ull;
    h = (h ^ (uint8_t)qtype) * 0x100000001B3ull;
    h = (h ^ (kflags & ELPIS_MK_DO)) * 0x100000001B3ull;
    /* FNV's high bits are weak and the filter uses both halves: finish
     * with the splitmix64 mixer. */
    h ^= h >> 30;
    h *= 0xBF58476D1CE4E5B9ull;
    h ^= h >> 27;
    h *= 0x94D049BB133111EBull;
    h ^= h >> 31;
    return h;
}

void elpis_bloom_set(uint8_t *bits, uint32_t nbits, unsigned k, uint64_t h)
{
    uint32_t h1 = (uint32_t)h, h2 = (uint32_t)(h >> 32) | 1u;
    unsigned i;

    for (i = 0; i < k; i++) {
        uint32_t b = (h1 + i * h2) & (nbits - 1u);
        bits[b >> 3] |= (uint8_t)(1u << (b & 7u));
    }
}

int elpis_bloom_test(const uint8_t *bits, uint32_t nbits, unsigned k,
                     uint64_t h)
{
    uint32_t h1 = (uint32_t)h, h2 = (uint32_t)(h >> 32) | 1u;
    unsigned i;

    for (i = 0; i < k; i++) {
        uint32_t b = (h1 + i * h2) & (nbits - 1u);
        if (!(bits[b >> 3] & (1u << (b & 7u))))
            return 0;
    }
    return 1;
}

size_t elpis_mesh_lq_seal(const uint8_t key[32], uint32_t key_id,
                          const uint8_t *pt, size_t n, uint8_t *out)
{
    elpis_put32(out, key_id);
    elpis_random_bytes(out + 4, 12);
    /* The key id travels in the clear, so it is bound in as associated data. */
    elpis_aead_seal(key, out + 4, out, 4, pt, n, out + 16);
    return n + ELPIS_MESH_LQ_OVERHEAD;
}

int elpis_mesh_lq_open(const uint8_t key[32], const uint8_t *dg, size_t n,
                       uint8_t *out, size_t *outlen)
{
    if (n < ELPIS_MESH_LQ_OVERHEAD)
        return ELPIS_ERR;
    if (elpis_aead_open(key, dg + 4, dg, 4, dg + 16, n - 16u, out) != ELPIS_OK)
        return ELPIS_ERR;
    *outlen = n - ELPIS_MESH_LQ_OVERHEAD;
    return ELPIS_OK;
}

/* The entry for `node`, under the lock, or -1. */
static int ptab_find(const uint8_t node[16])
{
    unsigned i;
    for (i = 0; i < g_nptab; i++)
        if (memcmp(g_ptab[i].node, node, 16) == 0)
            return (int)i;
    return -1;
}

/* A peer is up, and takes connections: it can be asked. */
static void ptab_up(const session_t *s)
{
    int i;

    if (!s->has_listen)
        return;
    pthread_rwlock_wrlock(&g_ptab_lock);
    i = ptab_find(s->node);
    if (i < 0 && g_nptab < MESH_MAX_SESSIONS) {
        i = (int)g_nptab++;
        memset(&g_ptab[i], 0, sizeof g_ptab[i]);
        memcpy(g_ptab[i].node, s->node, 16);
    }
    if (i >= 0)
        g_ptab[i].addr = s->listen;
    pthread_rwlock_unlock(&g_ptab_lock);
}

static void ptab_down(const uint8_t node[16])
{
    uint8_t *old = NULL;
    int i;

    pthread_rwlock_wrlock(&g_ptab_lock);
    i = ptab_find(node);
    if (i >= 0) {
        old = g_ptab[i].bloom;
        elpis_memzero(g_ptab[i].key, sizeof g_ptab[i].key);
        g_ptab[i] = g_ptab[--g_nptab];
    }
    pthread_rwlock_unlock(&g_ptab_lock);
    elpis_free(old);
}

static void ptab_rtt(const uint8_t node[16], uint32_t rtt_ms)
{
    int i;
    pthread_rwlock_wrlock(&g_ptab_lock);
    if ((i = ptab_find(node)) >= 0)
        g_ptab[i].rtt_ms = rtt_ms;
    pthread_rwlock_unlock(&g_ptab_lock);
}

static void ptab_key(const uint8_t node[16], uint32_t id, const uint8_t key[32])
{
    int i;
    pthread_rwlock_wrlock(&g_ptab_lock);
    if ((i = ptab_find(node)) >= 0) {
        g_ptab[i].key_id = id;
        memcpy(g_ptab[i].key, key, 32);
        g_ptab[i].has_key = 1;
    }
    pthread_rwlock_unlock(&g_ptab_lock);
}

/* Takes ownership of `bits`. */
static void ptab_bloom(const uint8_t node[16], uint8_t *bits, uint32_t nbits,
                       uint8_t k)
{
    uint8_t *old = bits;
    int i;

    pthread_rwlock_wrlock(&g_ptab_lock);
    if ((i = ptab_find(node)) >= 0) {
        old = g_ptab[i].bloom;
        g_ptab[i].bloom = bits;
        g_ptab[i].bloom_bits = nbits;
        g_ptab[i].bloom_k = k;
    }
    pthread_rwlock_unlock(&g_ptab_lock);
    elpis_free(old);                /* no reader can hold it: they lock */
}

int elpis_mesh_pick(uint64_t qhash, elpis_mesh_pick_t *out)
{
    uint32_t max;
    int best = -1;
    unsigned i;

    if (g_ctx == NULL || !g_ctx->conf.mesh || !g_ctx->conf.mesh_lookup)
        return ELPIS_ENOTFOUND;
    max = g_ctx->conf.mesh_lookup_rtt;
    pthread_rwlock_rdlock(&g_ptab_lock);
    for (i = 0; i < g_nptab; i++) {
        const ptab_t *p = &g_ptab[i];
        if (!p->has_key || p->bloom == NULL || p->rtt_ms == 0 || p->rtt_ms > max)
            continue;
        if (!elpis_bloom_test(p->bloom, p->bloom_bits, p->bloom_k, qhash))
            continue;
        if (best < 0 || p->rtt_ms < g_ptab[best].rtt_ms)
            best = (int)i;
    }
    if (best >= 0) {
        out->addr   = g_ptab[best].addr;
        out->key_id = g_ptab[best].key_id;
        out->rtt_ms = g_ptab[best].rtt_ms;
        memcpy(out->key, g_ptab[best].key, 32);
    }
    pthread_rwlock_unlock(&g_ptab_lock);
    return best >= 0 ? ELPIS_OK : ELPIS_ENOTFOUND;
}

static void send_lookup_key(session_t *s)
{
    uint8_t body[36];

    if (!g_ctx->conf.mesh_share || g_nlqfd == 0)
        return;                     /* not answering, so nothing to hand out */
    elpis_put32(body, g_lqid[0]);
    memcpy(body + 4, g_lqkey[0], 32);
    send_msg(s, MSG_LOOKUP_KEY, body, sizeof body);
    elpis_memzero(body, sizeof body);
}

static void lq_new_key(void)
{
    elpis_random_bytes(g_lqkey[0], 32);
    do
        elpis_random_bytes(&g_lqid[0], sizeof g_lqid[0]);
    while (g_lqid[0] == g_lqid[1]);
}

/* A fresh key every hour; the last one keeps working until the next. */
static void lq_rotate(uint64_t now)
{
    session_t *s;

    memcpy(g_lqkey[1], g_lqkey[0], 32);
    g_lqid[1] = g_lqid[0];
    lq_new_key();
    g_lq_rotated = now;
    for (s = g_sessions; s != NULL; s = s->next)
        if (!s->dead && s->state == S_UP)
            send_lookup_key(s);
}

/*
 * What goes in a digest: answers a peer's client could be given.  NOERROR
 * with no records (NODATA) is one of them -- most names have no HTTPS record
 * and many no AAAA, and a browser waits on those as long as on the A.
 * NXDOMAIN is not.
 */
static int digest_eligible(const elpis_mview_t *v)
{
    return v->qclass == ELPIS_CLASS_IN && v->rcode == ELPIS_RC_NOERROR &&
           !(v->kflags & ELPIS_MK_CD) && v->ttl_left >= 3u;
}

typedef struct {
    uint8_t  *bits;
    uint32_t  nbits;
    unsigned  n;
} dbuild_t;

static void digest_count(const elpis_mview_t *v, void *arg)
{
    if (digest_eligible(v))
        ((dbuild_t *)arg)->n++;
}

static void digest_fill(const elpis_mview_t *v, void *arg)
{
    dbuild_t *b = (dbuild_t *)arg;
    if (digest_eligible(v))
        elpis_bloom_set(b->bits, b->nbits, DIGEST_K,
                        elpis_mesh_qhash(v->qname, v->qnamelen, v->qtype,
                                         v->kflags));
}

/*
 * Ten bits an entry and seven probes: about one false positive in a hundred,
 * which costs a peer one lookup it cannot answer.  Past 2^24 bits (2 MiB)
 * the rate climbs rather than the size.
 */
static void digest_build(uint64_t now)
{
    dbuild_t b;
    uint32_t nbits = DIGEST_MIN_BITS;

    memset(&b, 0, sizeof b);
    elpis_mcache_walk(g_ctx->mcache, digest_count, &b);
    while ((uint64_t)nbits < (uint64_t)b.n * 10u && nbits < DIGEST_MAX_BITS)
        nbits <<= 1;
    b.bits = (uint8_t *)elpis_calloc(nbits / 8u, 1);
    if (b.bits == NULL)
        return;
    b.nbits = nbits;
    elpis_mcache_walk(g_ctx->mcache, digest_fill, &b);
    elpis_free(g_digest);
    g_digest = b.bits;
    g_digest_bits = nbits;
    g_digest_seq++;
    g_digest_at = now;
}

static void digest_send(session_t *s, uint64_t now)
{
    static uint8_t body[17u + DIGEST_CHUNK];
    uint32_t total = g_digest_bits / 8u, off;

    for (off = 0; off < total; off += DIGEST_CHUNK) {
        uint32_t len = total - off < DIGEST_CHUNK ? total - off : DIGEST_CHUNK;
        elpis_put32(body, g_digest_seq);
        elpis_put32(body + 4, g_digest_bits);
        body[8] = (uint8_t)DIGEST_K;
        elpis_put32(body + 9, total);
        elpis_put32(body + 13, off);
        memcpy(body + 17, g_digest + off, len);
        if (send_msg(s, MSG_DIGEST, body, 17u + len) != ELPIS_OK)
            return;
    }
    s->last_digest = now;
}

static void recv_digest(session_t *s, const uint8_t *p, size_t n)
{
    uint32_t seq, bits, total, off, len;
    uint8_t k;

    if (!g_ctx->conf.mesh_lookup || n < 17u)
        return;                     /* not asking, so no use for it */
    seq = elpis_get32(p);
    bits = elpis_get32(p + 4);
    k = p[8];
    total = elpis_get32(p + 9);
    off = elpis_get32(p + 13);
    len = (uint32_t)(n - 17u);
    if (bits < DIGEST_MIN_BITS || bits > DIGEST_MAX_BITS ||
        (bits & (bits - 1u)) != 0 || total != bits / 8u || k == 0 || k > 16 ||
        off > total || len > total - off)
        return;
    if (off == 0) {
        elpis_free(s->dg);
        s->dg = (uint8_t *)elpis_malloc(total);
        s->dg_seq = seq;
        s->dg_got = 0;
        if (s->dg == NULL)
            return;
    } else if (s->dg == NULL || seq != s->dg_seq || off != s->dg_got) {
        return;                     /* a part out of place: wait for the next */
    }
    memcpy(s->dg + off, p + 17, len);
    s->dg_got += len;
    if (s->dg_got == total) {
        ptab_bloom(s->node, s->dg, bits, k);
        s->dg = NULL;
    }
}

static int from_a_peer(const elpis_addr_t *a)
{
    const session_t *s;
    for (s = g_sessions; s != NULL; s = s->next)
        if (!s->dead && s->state == S_UP && elpis_addr_eq_ip(&s->addr, a))
            return 1;
    return 0;
}

/*
 * A peer's lookup: answered from the message cache only, never by resolving,
 * and only when the answer is one a client could be given -- NOERROR, with
 * records or without (NODATA), fresh, whole.  Only a source address one of our sessions comes from gets an
 * answer, so a query replayed from a forged address cannot aim a reply,
 * twenty times its size, at somebody else.
 */
static void lq_serve(int fd)
{
    for (;;) {
        uint8_t dg[ELPIS_MESH_LQ_MAX + 64], pt[ELPIS_MESH_LQ_MAX + 64];
        uint8_t ans[ELPIS_MESH_LQ_MAX], out[ELPIS_MESH_LQ_MAX + 64];
        uint8_t folded[ELPIS_MAX_NAME];
        size_t ptlen, rlen = 0;
        elpis_addr_t from;
        elpis_mserve_t info;
        elpis_msg_t m;
        elpis_mkey_t k;
        uint32_t id;
        ssize_t n;
        int idx, drop = 0, found = 0;

        memset(&from, 0, sizeof from);
        from.len = sizeof from.u.ss;
        n = recvfrom(fd, dg, sizeof dg, 0, &from.u.sa, &from.len);
        if (n < 0)
            return;
        if ((size_t)n < ELPIS_MESH_LQ_OVERHEAD + ELPIS_MESH_LQ_HDR ||
            !from_a_peer(&from))
            continue;
        id = elpis_get32(dg);
        /* The previous key only once there has been one: before the first
         * rotation its slot is all zeros, a key anyone could use. */
        idx = id == g_lqid[0] ? 0
            : (g_lqid[1] != 0 && id == g_lqid[1]) ? 1 : -1;
        if (idx < 0 ||
            elpis_mesh_lq_open(g_lqkey[idx], dg, (size_t)n, pt, &ptlen) != ELPIS_OK ||
            ptlen < ELPIS_MESH_LQ_HDR || pt[0] != ELPIS_MESH_LQ_ASK ||
            elpis_msg_parse(&m, pt + ELPIS_MESH_LQ_HDR, ptlen - ELPIS_MESH_LQ_HDR,
                            ELPIS_PARSE_QUERY, &drop) != ELPIS_OK ||
            m.qclass != ELPIS_CLASS_IN)
            continue;

        memcpy(folded, m.qname.d, m.qname.len);
        elpis_simd_lower(folded, folded, m.qname.len);
        k.qname    = folded;
        k.qnamelen = m.qname.len;
        k.qtype    = m.qtype;
        k.qclass   = ELPIS_CLASS_IN;
        k.kflags   = (uint8_t)(pt[1] & ELPIS_MK_DO);    /* never CD */
        elpis_mkey_hash(&k);
        if (g_ctx->conf.mesh_share &&
            elpis_mcache_serve(g_ctx->mcache, &k, 0, m.qname.d, ELPIS_FLAG_QR,
                               sizeof ans - ELPIS_MESH_LQ_HDR -
                                   ELPIS_MESH_LQ_OVERHEAD,
                               0, 0, 0, ans, sizeof ans, &rlen, &info) == ELPIS_OK &&
            info.rcode == ELPIS_RC_NOERROR &&
            (info.ancount > 0 || info.nscount > 0) &&
            !info.truncated && !info.stale && info.ttl >= 3u)
            found = 1;

        pt[0] = (uint8_t)ELPIS_MESH_LQ_ANSWER;
        pt[1] = (uint8_t)found;
        /* pt[2..9]: the token, sent back as it came */
        if (found)
            memcpy(pt + ELPIS_MESH_LQ_HDR, ans, rlen);
        else
            rlen = 0;
        n = (ssize_t)elpis_mesh_lq_seal(g_lqkey[idx], id, pt,
                                        ELPIS_MESH_LQ_HDR + rlen, out);
        (void)sendto(fd, out, (size_t)n, 0, &from.u.sa, from.len);
        if (found)
            elpis_stat_inc(&g_ctx->stats.peer_served, 1);
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

static void session_closef(session_t *s, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(s->whybuf, sizeof s->whybuf, fmt, ap);
    va_end(ap);
    session_close(s, s->whybuf);
}

/* XX messages 2 and 3: a hello, then u16 length and the certificate. */
static int write_licensed(session_t *s)
{
    uint8_t pl[HELLO_LEN + 2u + ELPIS_LICENCE_MAX_TOKEN];
    uint8_t out[sizeof pl + 128u];
    size_t cl = strlen(g_ctx->conf.mesh_cert), olen;

    hello_make(pl);
    elpis_put16(pl + HELLO_LEN, (uint16_t)cl);
    memcpy(pl + HELLO_LEN + 2u, g_ctx->conf.mesh_cert, cl);
    if (elpis_noise_write(&s->hs, pl, HELLO_LEN + 2u + cl, out, sizeof out,
                          &olen) != ELPIS_OK ||
        queue_raw_frame(s, out, olen) != ELPIS_OK) {
        session_close(s, "handshake failed");
        return ELPIS_ERR;
    }
    return ELPIS_OK;
}

/*
 * The other side's certificate: signed by this build's issuer, not expired,
 * for the static key the handshake just proved it holds, and for our own
 * organisation.  Any one missing and it does not get in.
 */
static int check_peer(session_t *s, const uint8_t *pl, size_t n)
{
    const uint8_t *rs = elpis_noise_remote_static(&s->hs);
    char tok[ELPIS_LICENCE_MAX_TOKEN], when[32];
    elpis_meshcert_t c;
    size_t cl;

    s->loud = 1;                    /* it got this far: it holds the PSK */
    cl = n >= HELLO_LEN + 2u ? elpis_get16(pl + HELLO_LEN) : 0u;
    if (cl == 0 || cl >= sizeof tok || HELLO_LEN + 2u + cl > n) {
        session_close(s, "no certificate (an instance without "
                         "mesh-require-licence?)");
        return ELPIS_ERR;
    }
    memcpy(tok, pl + HELLO_LEN + 2u, cl);
    tok[cl] = '\0';
    if (elpis_meshcert_parse(tok, elpis_wall_s(), &c) != ELPIS_OK) {
        session_closef(s, "its certificate does not verify: %s", c.why);
        return ELPIS_ERR;
    }
    if (c.expired) {
        elpis_licence_date(c.expires, when, sizeof when);
        session_closef(s, "its certificate expired on %s", when);
        return ELPIS_ERR;
    }
    if (rs == NULL || memcmp(c.key, rs, 32) != 0) {
        session_close(s, "its certificate is for a key it did not prove");
        return ELPIS_ERR;
    }
    if (strcmp(c.org, g_cert_org) != 0) {
        session_closef(s, "its certificate is for \"%s\", not \"%s\"",
                       c.org, g_cert_org);
        return ELPIS_ERR;
    }
    s->cert_serial = c.serial;
    s->loud = 0;
    return ELPIS_OK;
}

static void session_ready(session_t *s);

/* The handshake is done on this side: keys, and what the hello says. */
static void session_up(session_t *s, const uint8_t *hello, size_t n)
{
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

    /*
     * In XX the dialler writes the last message, so its handshake ends before
     * the other side has judged its certificate.  It is up when that side
     * first says something; until then it sends nothing and tells no one.
     */
    if (g_licensed && s->initiator) {
        s->state = S_CONFIRM;
        s->deadline = elpis_now_ms() + MESH_HANDSHAKE_MS;
        return;
    }
    session_ready(s);
}

/* Both sides have let each other in. */
static void session_ready(session_t *s)
{
    const elpis_conf_t *c = &g_ctx->conf;
    session_t *twin;
    char id[9];
    uint64_t now = elpis_now_ms();

    s->state = S_UP;
    s->was_up = 1;
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
    if (g_licensed)
        elpis_info("mesh: up with %s (node %s, %s, certificate %lu)", s->name,
                   id, s->initiator ? "we dialled" : "it dialled",
                   (unsigned long)s->cert_serial);
    else
        elpis_info("mesh: up with %s (node %s, %s)", s->name, id,
                   s->initiator ? "we dialled" : "it dialled");
    s->last_ping = 0;               /* ping at once: lookups need the RTT */
    ptab_up(s);
    send_lookup_key(s);

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
        if (n > MESH_HS_MAX ||
            elpis_noise_read(&s->hs, p, n, g_rx, sizeof g_rx,
                             &plen) != ELPIS_OK) {
            /* What a wrong PSK looks like from either end -- and so does a
             * licensed mesh meeting one that is not. */
            session_close(s, g_licensed
                ? "handshake failed (a different mesh-psk, or an instance "
                  "without mesh-require-licence?)"
                : "handshake failed (a different mesh-psk, or an instance "
                  "with mesh-require-licence?)");
            return;
        }
        if (!g_licensed) {
            /* NN: message 1 carries the initiator's hello, 2 the responder's. */
            if (!s->initiator) {
                hello_make(hello);
                if (elpis_noise_write(&s->hs, hello, sizeof hello, out,
                                      sizeof out, &olen) != ELPIS_OK ||
                    queue_raw_frame(s, out, olen) != ELPIS_OK) {
                    session_close(s, "handshake failed");
                    return;
                }
                /* Out now: if this turns out to be us, our dialling side
                 * has to read it to learn so. */
                flush(s);
            }
            session_up(s, g_rx, plen);
            return;
        }
        /*
         * XX: message 1 carries nothing; 2 and 3 each carry a hello and the
         * certificate for the static key that message has just proved.
         */
        if (!s->initiator && s->hs.step == 1) {
            if (write_licensed(s) == ELPIS_OK)
                flush(s);
            return;
        }
        if (check_peer(s, g_rx, plen) != ELPIS_OK)
            return;
        if (s->initiator && write_licensed(s) != ELPIS_OK)
            return;
        session_up(s, g_rx, plen);
        return;
    }

    if (s->state != S_UP && s->state != S_CONFIRM)
        return;
    if (n < 1u + ELPIS_NOISE_TAG ||
        elpis_noise_decrypt(&s->rx, p, n, g_rx) != ELPIS_OK) {
        session_close(s, "a message that does not decrypt");
        return;
    }
    if (s->state == S_CONFIRM) {
        /* The first word back: it took our certificate. */
        session_ready(s);
        if (s->dead)
            return;
    }
    plen = n - ELPIS_NOISE_TAG;

    switch (g_rx[0]) {
    case MSG_LIST_REQ:
        send_list(s, plen >= 5u ? elpis_get32(g_rx + 1) : 0u);
        break;
    case MSG_LIST_PART:
        recv_list_part(s, g_rx + 1, plen - 1u);
        break;
    case MSG_LIST_END:
        recv_list_end(s);
        break;
    case MSG_PEERS:
        recv_peers(s, g_rx + 1, plen - 1u);
        break;
    case MSG_PING:
        if (plen >= 9u)
            send_msg(s, MSG_PONG, g_rx + 1, 8);
        break;
    case MSG_PONG:
        if (plen >= 9u) {
            uint64_t sent = ((uint64_t)elpis_get32(g_rx + 1) << 32) |
                            elpis_get32(g_rx + 5);
            uint64_t now = elpis_now_us();
            if (sent <= now && now - sent < 60000000u) {
                /* Rounded up, so a LAN's fraction of a millisecond is 1 and
                 * not 0, which means not yet measured; then smoothed. */
                uint32_t ms = (uint32_t)((now - sent + 999u) / 1000u);
                s->rtt_ms = s->rtt_ms ? (s->rtt_ms * 3u + ms + 3u) / 4u : ms;
                ptab_rtt(s->node, s->rtt_ms);
            }
        }
        break;
    case MSG_LOOKUP_KEY:
        if (plen >= 37u)
            ptab_key(s->node, elpis_get32(g_rx + 1), g_rx + 5);
        break;
    case MSG_DIGEST:
        recv_digest(s, g_rx + 1, plen - 1u);
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
                             : g_licensed
                             ? "closed during the handshake (a different "
                               "mesh-psk, or it refused our certificate?)"
                             : "closed during the handshake (a different "
                               "mesh-psk, or a mesh that requires licences?)");
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
    /* A licensed mesh says nothing in message 1: its hello goes with the
     * certificate, once there is a key to send them under. */
    if (elpis_noise_write(&s->hs, hello, g_licensed ? 0 : sizeof hello, out,
                          sizeof out, &olen) != ELPIS_OK ||
        queue_raw_frame(s, out, olen) != ELPIS_OK) {
        session_close(s, "handshake failed");
        return;
    }
    flush(s);
}

/* ------------------------------------------------------------------ */
/* Local service discovery: announcing and hearing                     */
/* ------------------------------------------------------------------ */

static void lsd_send(int fd, const char *group, const uint8_t *pkt, int *warned)
{
    elpis_addr_t g;

    if (fd < 0 || elpis_addr_parse(&g, group, LSD_PORT) != 0)
        return;
    if (sendto(fd, pkt, ELPIS_MESH_LSD_LEN, 0, &g.u.sa, g.len) < 0 && !*warned) {
        *warned = 1;
        elpis_info("mesh: cannot announce to %s: %s", group, strerror(errno));
    }
}

/* Three announcements close together at startup, in case one is lost, and
 * then one every half minute.  Only an instance that takes connections. */
static void lsd_announce(uint64_t now)
{
    static int warned4, warned6;
    uint8_t pkt[ELPIS_MESH_LSD_LEN];

    if (now < g_lsd_next)
        return;
    /* Each family names its own listener, so a dial that follows the
     * announcement lands on a socket that is there. */
    if (g_lsd_port4 != 0) {
        elpis_mesh_lsd_make(g_lsd_key, g_node, g_lsd_port4, pkt);
        lsd_send(g_lsd4, LSD_GROUP4, pkt, &warned4);
    }
    if (g_lsd_port6 != 0) {
        elpis_mesh_lsd_make(g_lsd_key, g_node, g_lsd_port6, pkt);
        lsd_send(g_lsd6, LSD_GROUP6, pkt, &warned6);
    }
    g_lsd_sent++;
    g_lsd_next = now + (g_lsd_sent == 1 ? 1000u : g_lsd_sent == 2 ? 2000u
                                                                   : LSD_EVERY_MS);
}

static void lsd_on_readable(int fd)
{
    for (;;) {
        uint8_t buf[128], node[16];
        elpis_addr_t from;
        uint16_t port;
        known_t *k;
        ssize_t n;

        memset(&from, 0, sizeof from);
        from.len = sizeof from.u.ss;
        n = recvfrom(fd, buf, sizeof buf, 0, &from.u.sa, &from.len);
        if (n < 0)
            return;
        /* Another mesh, a stranger, or noise: not a word about it. */
        if (elpis_mesh_lsd_check(g_lsd_key, buf, (size_t)n, node, &port) != ELPIS_OK)
            continue;
        if (memcmp(node, g_node, 16) == 0 || session_by_node(node, NULL) != NULL)
            continue;               /* our own, looped back, or already up */

        if (elpis_addr_family(&from) == AF_INET)
            from.u.v4.sin_port = htons(port);
        else
            from.u.v6.sin6_port = htons(port);
        k = known_find(&from);
        if (k == NULL) {
            char name[64];
            unsigned i, seen = 0;
            /* One line per instance, not one per address it announces on. */
            for (i = 0; i < g_nknown && !seen; i++)
                seen = g_known[i].has_node && !memcmp(g_known[i].node, node, 16);
            if ((k = known_add(&from, 0)) == NULL)
                continue;
            if (!seen)
                elpis_info("mesh: found %s on the local network",
                           elpis_addr_str(&from, name, sizeof name));
        }
        memcpy(k->node, node, 16);
        k->has_node = 1;
        /* Still announcing after the dials to it gave up: it is there, so
         * one more try -- but no more often than the backoff allows. */
        if (k->fails >= MESH_LEARNED_TRIES && elpis_now_ms() >= k->next_try)
            k->fails = MESH_LEARNED_TRIES - 1u;
    }
}

/* ------------------------------------------------------------------ */
/* The loop                                                            */
/* ------------------------------------------------------------------ */

/*
 * Whether a known address already has a session: by address, or -- for one
 * announced on the segment, which may be the same instance a bridge already
 * reached another way -- by node id.
 */
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
        if (k->has_node &&
            ((s->state == S_UP && memcmp(s->node, k->node, 16) == 0) ||
             (s->has_want && memcmp(s->want, k->node, 16) == 0)))
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
        if (k->has_node) {
            memcpy(s->want, k->node, 16);
            s->has_want = 1;
        }
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
                                 : s->state == S_CONFIRM
                                 ? "it did not take our certificate"
                                 : "handshake timed out");
            continue;
        }
        if (now - s->last_rx >= MESH_IDLE_MS) {
            session_close(s, "silent too long");
            continue;
        }
        if (now - s->last_ping >= MESH_PING_MS) {
            uint8_t tok[8];
            uint64_t us = elpis_now_us();
            elpis_put32(tok, (uint32_t)(us >> 32));
            elpis_put32(tok + 4, (uint32_t)us);
            send_msg(s, MSG_PING, tok, sizeof tok);
            s->last_ping = now;
        }
        if (now - s->last_pex >= MESH_PEX_EVERY_MS)
            send_peers(s);
        /*
         * A digest every half minute, to the peers near enough to ask us --
         * the RTT is the same both ways -- and only while answering them.
         */
        if (g_ctx->conf.mesh_share && g_nlqfd > 0 && s->rtt_ms != 0 &&
            s->rtt_ms <= g_ctx->conf.mesh_lookup_rtt &&
            now - s->last_digest >= DIGEST_EVERY_MS) {
            if (g_digest == NULL || now - g_digest_at >= DIGEST_EVERY_MS)
                digest_build(now);
            if (g_digest != NULL)
                digest_send(s, now);
        }
    }
    if (g_nlqfd > 0 && now - g_lq_rotated >= MESH_LQ_ROTATE_MS)
        lq_rotate(now);

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
    struct pollfd pf[2u * ELPIS_MESH_MAX_LISTEN + 2u + MESH_MAX_SESSIONS];
    int lsd[2];
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

    lsd[0] = g_lsd4;
    lsd[1] = g_lsd6;

    while (!ctx->shutdown) {
        uint64_t now = elpis_now_ms();
        unsigned nf = 0, ns = 0, l, base;
        session_t *s;
        int n;

        lsd_announce(now);
        dial_due(now);
        timers(now);
        reap(now);

        for (l = 0; l < g_nlfd; l++) {
            pf[nf].fd = g_lfd[l];
            pf[nf].events = POLLIN;
            pf[nf].revents = 0;
            nf++;
        }
        /* Both discovery sockets always take a slot, -1 when not open, which
         * poll() passes over: the sessions then start at a fixed place. */
        for (l = 0; l < 2; l++) {
            pf[nf].fd = lsd[l];
            pf[nf].events = POLLIN;
            pf[nf].revents = 0;
            nf++;
        }
        for (l = 0; l < g_nlqfd; l++) {
            pf[nf].fd = g_lqfd[l];
            pf[nf].events = POLLIN;
            pf[nf].revents = 0;
            nf++;
        }
        base = nf;
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
        for (l = 0; l < 2; l++)
            if (pf[g_nlfd + l].revents & POLLIN)
                lsd_on_readable(lsd[l]);
        for (l = 0; l < g_nlqfd; l++)
            if (pf[g_nlfd + 2u + l].revents & POLLIN)
                lq_serve(g_lqfd[l]);
        for (i = 0; i < ns; i++) {
            short ev = pf[base + i].revents;
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
