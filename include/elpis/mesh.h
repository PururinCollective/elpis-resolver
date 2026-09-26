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
 * its cache, sent every half minute -- says it probably has the answer.  Lookups are UDP datagrams sealed with ChaCha20-Poly1305 under
 * a key the answering instance chose and handed out inside the Noise
 * session, so they have that session's forward secrecy.
 */
typedef struct {
    elpis_addr_t addr;          /* where it answers lookups (UDP)       */
    uint8_t      key[32];       /* the lookup key it gave us            */
    uint32_t     key_id;
    uint32_t     rtt_ms;
} elpis_mesh_pick_t;

/* The question as the digests hash it: folded name, type, DO/CD bits. */
uint64_t elpis_mesh_qhash(const uint8_t *qname, uint8_t len, uint16_t qtype,
                          uint8_t kflags);
/* The peer worth asking, or ELPIS_ENOTFOUND.  Any thread. */
int      elpis_mesh_pick(uint64_t qhash, elpis_mesh_pick_t *out);

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

/* Bloom filters of `nbits`, a power of two, probed `k` times. */
void     elpis_bloom_set(uint8_t *bits, uint32_t nbits, unsigned k, uint64_t h);
int      elpis_bloom_test(const uint8_t *bits, uint32_t nbits, unsigned k,
                          uint64_t h);

#endif /* ELPIS_MESH_H */
