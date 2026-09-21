# Elpis

A recursive DNS resolver in portable C99. No external dependencies: the
crypto, the event loop and the wire format are all in this tree, so it links
into one static binary you can copy to a machine and run.

Built to sit behind AdGuard Home or Pi-hole — they face the network, Elpis
does the recursion.

```
$ make static && ./elpis -d
elpis 1.0.0 starting: avx2, epoll, 7422 MiB RAM detected, cache budget 1484 MiB
root zone: 1438 TLD delegations pinned in cache
listening with 8 workers
```

## What it does

**Caches hard.** Three caches, sized automatically from host memory (and from
the cgroup limit when containerised, which is usually the number that
matters):

| cache | share | holds |
|-------|-------|-------|
| message | 50% | complete prebuilt responses |
| RRset | 32% | individual RRsets with their signatures |
| delegation | 12% | root and TLD nameservers, pinned |
| infra | 6% | per-server round-trip times and EDNS quirks |

A cache hit is a 12-byte header, the client's question echoed back verbatim,
and one `memcpy` of a prebuilt blob with the TTLs patched in place. Nothing is
re-encoded and no name is re-compressed. On a not-especially-quiet eight-core
VM that path measures **600,000–780,000 queries/s** at a 100% hit rate, and
around 200,000 on a single thread.

Entries are refreshed in the background before they expire, so a popular name
never goes cold and stale data is only ever served while a refresh is actually
in flight.

**Never walks back to the root.** Every TLD delegation the resolver learns is
pinned and exempt from eviction, so once `.com` is known a lookup for anything
under it goes straight to a `.com` server. With `root-zone-transfer: yes` it
pulls the whole root zone by AXFR at startup and has all ~1,438 of them before
the first query arrives.

**Follows the awkward parts.** CNAME chains that cross zones (each link signed
by a different zone, each validated against its own chain of trust), DNAME
subtree rewrites with the synthesised CNAME RFC 6672 asks for, QNAME
minimisation with a fallback for authorities that answer NXDOMAIN for empty
non-terminals, and DS queries sent to the parent rather than the child.

**Validates DNSSEC** against the published IANA root anchors, with RSA
(1024–4096), ECDSA P-256/P-384, Ed25519 and **ML-DSA-44/65/87** (FIPS 204)
implemented from scratch. Denial of existence is checked with NSEC and NSEC3,
including opt-out and the RFC 9276 iteration cap. Data that fails validation
gets SERVFAIL and an extended DNS error — it is never handed to the client.

**Authenticates what it can.** DNS cookies (RFC 7873/9018) in both directions:
outbound queries carry one so an off-path attacker cannot forge a reply, and
incoming cookies are verified — with `require-cookie` on, a client echoing a
cookie that does not check out gets BADCOOKIE and a fresh one rather than an
answer. Responses are also matched on transaction ID, source port, the exact
0x20 casing of the question, and the server address.

**Drops malformed input and says so.** Every structural rule in RFC 1035 §4 is
checked before anything reaches the cache: compression pointers must aim
strictly backwards, rdlength must fit, counts must match, no trailing bytes,
per-type rdata layout must parse. Each drop is counted by reason and logged at
a rate limit, so a hostile peer cannot turn the log into its own amplifier.

```
queries=6094088 hits=5332228 (87.5%) recursions=761860 upstream=865
dropped 1503: spoof=1421 rdata=61 compress=21
```

## Standards

Core: 1034, 1035, 2181, 2308, 3596, 3597, 4343, 5452, 6891, 7766, 9619
Security: 4033–4035, 4470, 5155, 6605, 6840, 7873, 8080, 8624, 8914, 9018,
9276, 9715
Behaviour: 6052, 6147, 6303, 6672, 6761, 6762, 7686, 8020, 8482, 8767, 9156,
9210, 9471, 9520

ML-DSA verification follows FIPS 204. The DNSSEC algorithm numbers for it are
not assigned yet (see `draft-ietf-dnsop-dnssec-mldsa`), so they are settings
rather than constants — point `mldsa44-algorithm` at whatever your zone
publishes.

## Build

```sh
make            # the usual build
make static     # one relocatable binary, no shared libraries
make test       # 219 self tests, no network needed
make debug      # -O0 -g3
make asan       # address and UB sanitizers
```

Strict C99 plus POSIX.1-2008. epoll on Linux, kqueue on the BSDs and macOS,
poll everywhere else. SSE2/AVX2 and NEON kernels are selected at runtime from
CPUID; the scalar fallbacks are always compiled and the test suite checks that
every vector path agrees with them byte for byte.

Nothing calls `getaddrinfo()` or `getpwnam()` — address literals and
`/etc/passwd` are parsed directly — so a static glibc link carries no `dlopen()`
surprises. A resolver that silently fails to drop privilege is worse than one
that refuses to start.

## Configure

`elpis.conf` is looked for next to the binary, then in `/etc/elpis/`, then in
`/etc/`. The first that exists wins; without one the defaults are a working
recursive resolver on `127.0.0.1:5353`. The shipped file documents every
setting at its default value.

```
listen: 127.0.0.1@5353
access-control: 127.0.0.0/8 allow

cache-size: auto           # or 2G
serve-stale: 86400         # RFC 8767
prefetch: yes

dnssec: yes
root-zone-transfer: no     # yes = pull every TLD delegation at startup

dns64: no
dns64-prefix: 64:ff9b::/96

forward-zone: internal.example 10.0.0.53@5353   # recursive upstream
stub-zone: corp.example 10.1.0.53               # iterative, treated as authority
```

Behind AdGuard Home, point its upstream at `127.0.0.1:5353` and leave Elpis on
loopback.

## Operating

```
SIGHUP    reopen the log, rotate the DNS cookie secret
SIGUSR1   print statistics
SIGUSR2   flush the caches (root hints are kept)
SIGTERM   shut down
```

`-t` checks the configuration and exits. `-d` stays in the foreground. `-v`
raises verbosity, repeatable.

## Design notes

**CLOCK, not LRU.** An LRU splice on every hit needs an exclusive lock, which
puts a writer on the hottest path in the program. CLOCK makes a hit a single
relaxed byte store, so lookups hold only a shared lock.

**Swiss-table probing.** Each group of 16 slots has 16 control bytes carrying a
7-bit tag from the hash, so one SIMD compare tests sixteen candidates and the
entry array is touched only on a tag hit.

**No refcounts.** A looked-up entry is valid only while the shard lock is held,
and callers copy what they need before releasing. There is no deferred
reclamation to get wrong.

**0x20 and canonical form.** Randomising the case of the question name costs an
attacker real entropy, but authorities compress rdata against that question —
so a decompressed NS target comes back as `a.gtld-servers.Net.` because of our
own randomisation. Everything that reaches the validator or the cache is folded
exactly as RFC 4034 §6.2 specifies.

**RFC 5011 is deliberately absent.** Automated anchor rollover needs durable
state that survives restarts, and a writable state file is a path for walking a
resolver onto an attacker's key. Point `trust-anchor-file` at IANA's `root.key`
and update it with the rest of the system.

## Not here

RFC 8198 aggressive NSEC. Answering from cached denial records needs an
ordered index the hash tables cannot provide, and a half-implementation that
sometimes misses is worse than asking.

DoH, DoT and DoQ. Elpis speaks UDP and TCP. Put it behind something that
terminates the encrypted transports if you need them.

Authoritative service, zone files, dynamic update, TSIG signing. This resolves;
it does not serve.
