# 🔩 Internals

Why the hot paths are built the way they are, and what is deliberately missing.

## 🧵 The shape of it

```
                ┌─────────────────────── one process ───────────────────────┐
                │                                                           │
  clients ─────►│  worker 1      worker 2      ...      worker N            │
  UDP / TCP     │  ┌────────┐    ┌────────┐             ┌────────┐          │
  (SO_REUSEPORT)│  │ loop   │    │ loop   │             │ loop   │          │
                │  │ tasks  │    │ tasks  │             │ tasks  │          │
                │  │ sockets│    │ sockets│             │ sockets│          │
                │  │ DoT    │    │ DoT    │             │ DoT    │          │
                │  └───┬────┘    └───┬────┘             └───┬────┘          │
                │      └─────────────┼──────────────────────┘               │
                │                    ▼                                      │
                │   shared caches: message · RRset · delegation · infra     │
                │   (sharded, shared read locks)                            │
                │                                                           │
                │   status page: its own thread, one connection at a time   │
                └───────────────────────────────────────────────────────────┘
```

- **One worker per thread.** Each owns an event loop, its listening sockets
  (the kernel spreads load over them with `SO_REUSEPORT`), a pool of outbound
  UDP sockets on random ports, its DoT connections, and every task it started.
- **Nothing inside a worker is shared**, so the only lock on the hot path is
  the cache shard lock.

## 📡 Measuring the roots

At startup Elpis asks all 26 root addresses (13 names, IPv4 and IPv6) the same
small question a few times, and seeds the round-trip estimates from the
answers. The first real recursion then goes to the closest server instead of a
default guess.

<sub>On this host that cut cold TLD lookups from 11.9 s to 6.7 s.</sub>

```
root probe: 26 of 26 addresses answered (IPv4 13/13, IPv6 13/13), 3 rounds
   1. e.root-servers.net.    192.203.230.10:53          11 ms  (3/3)
   2. m.root-servers.net.    [2001:dc3::35]:53          11 ms  (3/3)
   ...
  26. c.root-servers.net.    [2001:500:2::c]:53        209 ms  (3/3)
```

A host whose IPv6 is configured but not working is caught the same way, and
outbound IPv6 is turned off for the run rather than burning a timeout on every
other query. The probe tells the two failures apart:

| | means |
|---|---|
| **no route** | the kernel refused to send: this host's configuration |
| **sent, no reply** | the packets left and nothing came back: a firewall somewhere |

```
   -- a.root-servers.net.  [2001:503:ba3e::2:30]:53   sent 3, no reply
WARN  IPv6 probes left this host (13 of 13 had a route) but no root server
      replied. Outbound IPv6 is off for this run.
WARN    the route exists, so this is filtering rather than configuration:
        check UDP/53 egress and the return path in this host's firewall and
        at the provider
```

## 🧗 The awkward parts of resolution

- **CNAME chains that cross zones**, each link signed by a different zone and
  validated against its own chain of trust.
- **DNAME** subtree rewrites, with the synthesised CNAME RFC 6672 asks for.
- **QNAME minimisation**, with a fallback for authorities that answer NXDOMAIN
  for empty non-terminals.
- **DS queries** sent to the parent rather than the child.

## 📐 Design notes

| | why |
|---|---|
| **CLOCK, not LRU** | An LRU splice on every hit needs an exclusive lock, which puts a writer on the hottest path in the program. CLOCK makes a hit a single relaxed byte store, so lookups hold only a shared lock. |
| **Swiss-table probing** | Each group of 16 slots has 16 control bytes carrying a 7-bit tag from the hash, so one SIMD compare tests sixteen candidates, and the entry array is touched only on a tag hit. |
| **No refcounts** | A looked-up entry is valid only while the shard lock is held; callers copy what they need before releasing. No deferred reclamation to get wrong. |
| **0x20 and canonical form** | Randomising the question's case costs an attacker real entropy, but authorities compress rdata against that question, so an NS target comes back as `a.gtld-servers.Net.` because of our own randomisation. Everything that reaches the validator or the cache is folded exactly as RFC 4034 §6.2 says. |
| **TLS in the tree** | The DoT client (`src/net/tls.c`) takes bytes in and gives bytes out, with no socket, so the event loop drives it and the tests replay RFC 8448 through it byte for byte. Its keys and ciphers (`tlscrypto.h`) are constant time; the DNSSEC verifiers work on public data and need not be. |
| **RFC 5011 is deliberately absent** | Automated anchor rollover needs durable state that survives restarts, and a writable state file is a path for walking a resolver onto an attacker's key. Point `trust-anchor-file` at IANA's `root.key` and update it with the rest of the system. |

## 🔗 Linking and portability

<sub>Build targets and CPU tuning are in [COMPILING.md](COMPILING.md).</sub>

- **Vector kernels are picked at runtime.** SSE2/AVX2 and NEON are chosen from
  CPUID, and so are AES-NI and PCLMULQDQ for DoT. The scalar fallbacks are
  always compiled, and the tests check every vector path against them byte for
  byte, so a vectorised build can never answer differently from a portable one.
- **No `getaddrinfo()` or `getpwnam()`.** Address literals and `/etc/passwd`
  are parsed directly, so a static glibc link carries no `dlopen()` surprises.
  <br><sub>A resolver that silently fails to drop privilege is worse than one
  that refuses to start.</sub>

## 🚫 Not here

| | why not |
|---|---|
| **RFC 8198 aggressive NSEC** | Answering from cached denial records needs an ordered index the hash tables can't provide, and a half-implementation that sometimes misses is worse than asking. |
| **DoH, DoT and DoQ for clients** | Elpis answers over UDP and TCP. Put it behind something that terminates the encrypted transports. It does speak DoT itself, outbound, to authoritative servers. |
| **Authoritative service** | No zone files, dynamic update or TSIG signing. This resolves; it does not serve. |

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Licensing](licensing.md)</sub>
