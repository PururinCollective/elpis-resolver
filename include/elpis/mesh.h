/*
 * elpis/mesh.h -- instances of one operator, telling each other what their
 * clients ask.
 *
 * A restarted instance with no checkpoint, or one just spun up, asks the
 * instances it can reach for the questions their clients ask most, merges
 * those with its own checkpoint if it has one, and warms the lot before its
 * clients ask.  Names only, never answers: every name is resolved and
 * validated here as usual, so the worst a peer can do is spend some of this
 * instance's warm-up on names nobody here wanted.  It is how an operator with
 * a no-log policy gets a warm restart without writing anything to disk.
 *
 * Peers are found through the bridges named in mesh-peer:, through the peers
 * those know (peer exchange), and on the local segment by multicast.  Every
 * connection is TCP under Noise_NNpsk0 (see noise.h), keyed by one PSK the
 * operator gives every instance; without it nothing gets past the first
 * message.
 */
#ifndef ELPIS_MESH_H
#define ELPIS_MESH_H

#include "elpis/ctx.h"

/*
 * Before privileges are dropped: read the PSK (so its file can be readable
 * by root alone) and bind mesh-listen.  On any failure the mesh is turned
 * off, with the reason logged, and the resolver runs on without it.
 */
void  elpis_mesh_init(elpis_ctx_t *ctx);
/* The mesh thread; only when ctx->conf.mesh is still set after init. */
void *elpis_mesh_main(void *ctx);
void  elpis_mesh_fini(void);

/* --gen-psk: print a new key in the form mesh-psk: files take. */
int   elpis_mesh_gen_psk(void);
/* --mesh-keygen: print a new instance key for mesh-key:, and its public half
 * for the licence issuer to certify. */
int   elpis_mesh_gen_key(void);

/* ---- exposed for the tests ---------------------------------------- */
/* 64 hex digits, anywhere in the text; lines starting '#' are comments. */
int   elpis_mesh_psk_parse(const char *text, uint8_t psk[32]);
/* Loopback, RFC 1918, shared address space, link-local and ULA. */
int   elpis_mesh_addr_private(const elpis_addr_t *a);
/*
 * Whether to tell a peer at `to` about an instance at `about`.  An address
 * only a private network can reach is passed only to peers on one, and a
 * loopback one only to peers on loopback: anyone else could not use it.
 */
int   elpis_mesh_may_tell(const elpis_addr_t *about, const elpis_addr_t *to);

/*
 * Local service discovery: the announcement an instance multicasts to its
 * segment, tagged under a key derived from the PSK.  check() returns
 * ELPIS_OK, with the node id and mesh port, only for one made under the
 * same key.
 */
#define ELPIS_MESH_LSD_LEN 44u
void  elpis_mesh_lsd_key(const uint8_t psk[32], uint8_t key[32]);
void  elpis_mesh_lsd_make(const uint8_t key[32], const uint8_t node[16],
                          uint16_t port, uint8_t out[ELPIS_MESH_LSD_LEN]);
int   elpis_mesh_lsd_check(const uint8_t key[32], const uint8_t *p, size_t n,
                           uint8_t node[16], uint16_t *port);

/* ---- live lookups: meshq.c asks, mesh.c answers ------------------- */
/*
 * With mesh-lookup: yes, a worker that misses asks one nearby peer's cache
 * while its own resolution runs, and whichever answers first goes to the
 * client.  Only NOERROR, with records or without (NODATA), is shared.  Which
 * peer: the nearest within mesh-lookup-rtt whose digest -- a Bloom filter of
 * its cache, sent every half minute -- says it probably has the answer.
 * Lookups are UDP datagrams sealed with ChaCha20-Poly1305 under a key the
 * answering instance chose and handed out inside the Noise session, so they
 * have that session's forward secrecy.
 */
typedef struct {
    elpis_addr_t addr;          /* where it answers lookups (UDP)       */
    uint8_t      key[32];       /* the lookup key it gave us            */
    uint32_t     key_id;
    uint32_t     rtt_ms;
    uint8_t      node[16];      /* for elpis_mesh_tally()               */
} elpis_mesh_pick_t;

/* The question as the digests hash it: folded name, type, DO/CD bits. */
uint64_t elpis_mesh_qhash(const uint8_t *qname, uint8_t len, uint16_t qtype,
                          uint8_t kflags);
/* The peer worth asking, or ELPIS_ENOTFOUND.  Any thread. */
int      elpis_mesh_pick(uint64_t qhash, elpis_mesh_pick_t *out);
/* Count a lookup against the peer it went to, for the status page. */
#define ELPIS_MESH_T_ASKED 0u
#define ELPIS_MESH_T_FOUND 1u
#define ELPIS_MESH_T_USED  2u
void     elpis_mesh_tally(const uint8_t node[16], unsigned what);

/*
 * A lookup datagram: u32 key id, a 12-byte nonce, then the sealed
 * plaintext -- u8 kind, u8 flags, an 8-byte token, and a DNS message: the
 * question when asking (flags: the DO bit), the cached response when
 * answering (flags: 1 when found).
 */
#define ELPIS_MESH_LQ_ASK      1u
#define ELPIS_MESH_LQ_ANSWER   2u
#define ELPIS_MESH_LQ_HDR      10u
#define ELPIS_MESH_LQ_OVERHEAD (4u + 12u + 16u)
/* Largest datagram either way: no fragmentation on any real path. */
#define ELPIS_MESH_LQ_MAX      1232u
size_t   elpis_mesh_lq_seal(const uint8_t key[32], uint32_t key_id,
                            const uint8_t *pt, size_t n, uint8_t *out);
/* ELPIS_OK with the plaintext in `out` (n - overhead bytes). */
int      elpis_mesh_lq_open(const uint8_t key[32], const uint8_t *dg, size_t n,
                            uint8_t *out, size_t *outlen);

/* ---- the status page's Mesh Network window (webui.c) --------------- */
/*
 * What the mesh thread last published, about once a second and only while
 * the status page is on: sessions belong to that thread, so the page gets a
 * copy rather than a look at the live ones.
 */
/* How a peer came to be known, and what we hold of it: a peer's flags. */
#define ELPIS_MESH_F_BRIDGE 0x001u     /* named in mesh-peer:            */
#define ELPIS_MESH_F_PEX    0x002u     /* heard of from another peer     */
#define ELPIS_MESH_F_LSD    0x004u     /* found on the local segment     */
#define ELPIS_MESH_F_IN     0x008u     /* it dialled us                  */
#define ELPIS_MESH_F_OUT    0x010u     /* we dialled it                  */
#define ELPIS_MESH_F_CERT   0x020u     /* its certificate checked out    */
#define ELPIS_MESH_F_KEY    0x040u     /* we hold its lookup key         */
#define ELPIS_MESH_F_DIGEST 0x080u     /* we hold its cache digest       */
#define ELPIS_MESH_F_SHARES 0x100u     /* it answers list requests       */

#define ELPIS_MESH_VIEW_PEERS 64u
#define ELPIS_MESH_VIEW_KNOWN 48u

typedef struct {
    char     host[64];                 /* what it calls itself           */
    char     version[64];              /* its elpis version, and build   */
    char     addr[64];                 /* the address it talks from      */
    uint16_t port;                     /* where it takes connections     */
    char     node[9];
    unsigned flags;
    uint32_t rtt_ms;                   /* 0 until measured               */
    uint64_t up_s;
    uint32_t cert_serial;
    uint64_t rx_bytes, tx_bytes;
    uint64_t names_in, names_out;      /* list entries each way          */
    uint64_t asked, found, used;       /* our lookups to it              */
    uint64_t served;                   /* its lookups we answered        */
    uint32_t digest_bits;
} elpis_mesh_peer_view_t;

/* An address to dial, and where the mesh is with it. */
#define ELPIS_MESH_KS_IDLE   0
#define ELPIS_MESH_KS_UP     1
#define ELPIS_MESH_KS_RETRY  2
#define ELPIS_MESH_KS_SELF   3
#define ELPIS_MESH_KS_GIVEN  4         /* heard of, and given up on      */

typedef struct {
    char     addr[64];
    unsigned via;                      /* BRIDGE, PEX, LSD bits          */
    int      state;
    unsigned fails;
    uint32_t retry_s;
    char     why[96];                  /* why the last dial failed       */
} elpis_mesh_known_view_t;

typedef struct {
    int      requested;                /* mesh: yes in the config        */
    int      on;                       /* and it is running              */
    char     node[9];
    uint64_t up_s;
    int      licensed;
    char     org[65];
    uint32_t cert_serial;
    char     cert_expires[32];
    unsigned nlisten;
    char     listen[ELPIS_MESH_MAX_LISTEN][64];
    unsigned nbridges;
    int      share, lookup, gathering;
    uint32_t share_min_hits, lookup_rtt, max_peers;
    /* discovery */
    int      lsd, lsd4, lsd6;          /* configured, and joined per family */
    uint16_t lsd_port4, lsd_port6;     /* announced; 0 = not announcing  */
    uint64_t lsd_sent, lsd_heard, lsd_foreign, lsd_found;
    uint32_t lsd_next_s;
    uint64_t pex_sent, pex_heard, pex_learned;
    /* exchange */
    uint64_t lists_asked, lists_in, names_in, lists_out, names_out;
    uint64_t digests_sent, digests_in;
    uint32_t digest_bits, digest_entries, digest_age_s;
    uint32_t lq_key_age_s;
    uint64_t asked, found, used, served;
    unsigned npeers;
    elpis_mesh_peer_view_t  peers[ELPIS_MESH_VIEW_PEERS];
    unsigned nknown;
    elpis_mesh_known_view_t known[ELPIS_MESH_VIEW_KNOWN];
} elpis_mesh_view_t;

void elpis_mesh_view(elpis_mesh_view_t *out);

/*
 * The Content tab: the most recent exchanges -- names asked of peers and by
 * them, lists and warm-ups -- in a ring kept in memory only, and only while
 * the status page is on.
 */
#define ELPIS_MESH_EV_ASKED   1u       /* we asked a peer about a name   */
#define ELPIS_MESH_EV_SERVED  2u       /* a peer asked us                */
#define ELPIS_MESH_EV_LIST_IN 3u       /* a peer's list arrived          */
#define ELPIS_MESH_EV_LIST_OUT 4u      /* we sent ours                   */
#define ELPIS_MESH_EV_WARM    5u       /* a warm-up finished             */
#define ELPIS_MESH_EV_DROPPED 6u       /* a peer's answer not confirmed  */

#define ELPIS_MESH_R_USED     1u       /* its answer reached the client  */
#define ELPIS_MESH_R_LATE     2u       /* it had it; ours came first     */
#define ELPIS_MESH_R_MISSING  3u       /* it did not have it after all   */
#define ELPIS_MESH_R_NOREPLY  4u       /* no answer before ours          */
#define ELPIS_MESH_R_ANSWERED 5u       /* we had it for them             */
#define ELPIS_MESH_R_NOTHERE  6u       /* we did not                     */

#define ELPIS_MESH_EVENTS 256u

typedef struct {
    uint64_t at;                       /* wall-clock seconds             */
    uint8_t  kind, result;
    uint16_t qtype;
    uint32_t us;                       /* round trip, for lookups        */
    uint32_t count;                    /* names, for lists and warm-ups  */
    char     name[96];                 /* the question, or what it was   */
    char     peer[64];
    char     note[24];                 /* e.g. our own rcode, on a drop  */
} elpis_mesh_event_t;

/* Any thread; nothing is kept while the status page is off. */
void     elpis_mesh_event(unsigned kind, unsigned result, const char *name,
                          uint16_t qtype, const char *peer, uint32_t us,
                          uint32_t count, const char *note);
/* Oldest first; returns how many. */
unsigned elpis_mesh_events(elpis_mesh_event_t *out, unsigned max);

/* Bloom filters of `nbits`, a power of two, probed `k` times. */
void     elpis_bloom_set(uint8_t *bits, uint32_t nbits, unsigned k, uint64_t h);
int      elpis_bloom_test(const uint8_t *bits, uint32_t nbits, unsigned k,
                          uint64_t h);

#endif /* ELPIS_MESH_H */
