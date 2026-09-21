# ΕΛΠΙΣ Resolver

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
never goes cold. The refresh starts when `prefetch-threshold` percent of the
original TTL is left — 10 by default, so a 300-second record is refreshed with
30 seconds to spare.

**A failed refresh never costs you the answer.** The two ways a refresh can go
wrong deserve opposite treatment, and they get it:

| refresh comes back | what it means | what happens |
|---|---|---|
| timeout, SERVFAIL, REFUSED | nothing about the name | keep serving it, retry with backoff |
| authoritative NXDOMAIN | the name is gone | believed, but only after it repeats |

An unusable reply says nothing about the name, so the cached answer stays and
is served under RFC 8767 while the retries back off — 1 second, then 2, 4, 8,
up to a minute. The backoff is the point: the usual reason a refresh fails is
that the far side is rate limiting, and asking once a second is how a brief
limit becomes a permanent one. Measured against an upstream that went dark for
40 seconds, it is the difference between 28 refresh attempts and 5.

An NXDOMAIN is not a failure, though — it is an answer, and one that a
rate-limited server can give by mistake. Believing it immediately would let a
single bad reply take a live name down; ignoring it forever would serve a
deleted name for the whole `serve-stale` window, which is a day by default.
So it has to repeat `refresh-nxdomain-confirmations` times in a row, and
because the attempts are backed off that is really a length of time: 3 is about
seven seconds, 6 about a minute. Below that the glitch is absorbed and no
client ever sees it; above it the records are dropped and the next query
resolves for real.

**Measures the roots before it needs them.** At startup it asks all twenty-six
root addresses — thirteen names on IPv4 and IPv6 — the same small question a
few times and seeds the round-trip estimates from the answers, so the first
real recursion already goes to the closest server instead of a default guess.
On this host that cut cold TLD lookups from 11.9s to 6.7s. A host whose IPv6
is configured but not working is detected the same way, and outbound IPv6 is
disabled for the run rather than burning a timeout on every other query.

The probe separates the two ways that fails, because they have nothing to do
with each other. "No route" means the kernel refused to send — that is this
host's configuration. "Sent, no reply" means the packets left and nothing came
back, which is a firewall somewhere, not a missing route:

```
   -- a.root-servers.net.  [2001:503:ba3e::2:30]:53   sent 3, no reply
WARN  IPv6 probes left this host (13 of 13 had a route) but no root server
      replied. Outbound IPv6 is off for this run.
WARN    the route exists, so this is filtering rather than configuration:
        check UDP/53 egress and the return path in this host's firewall and
        at the provider
```

```
root probe: 26 of 26 addresses answered (IPv4 13/13, IPv6 13/13), 3 rounds
   1. e.root-servers.net.    192.203.230.10:53          11 ms  (3/3)
   2. m.root-servers.net.    [2001:dc3::35]:53          11 ms  (3/3)
   ...
  26. c.root-servers.net.    [2001:500:2::c]:53        209 ms  (3/3)
```

**Never walks back to the root.** Every level of the delegation chain is
cached, so a lookup restarts as deep as anything already known allows:

```
.                 root hints, pinned
com.              pinned, exempt from eviction
example.com.      cached for the delegation's TTL
sub.example.com.  cached the same way, when it is a zone cut of its own
```

Only the root and the TLDs are pinned — there are about 1,438 of the latter,
which is a bounded set worth holding forever, and `root-zone-transfer: yes`
fetches all of them by AXFR at startup so they are there before the first
query. Everything below expires on its own TTL, which is the point: a domain's
nameservers change, and a delegation pinned past its TTL is just a stale answer
that never heals.

A delegation is kept as soon as its nameservers have addresses, whether the
parent supplied glue or not. That distinction matters more than it sounds. A
parent can only glue names inside its own zone, so every domain whose
nameservers live somewhere else — anything on a third-party DNS provider in a
different TLD — arrives glueless. Keeping only the glued ones meant those
domains were rebuilt from scratch on every lookup: back to the TLD for the
referral, then an A and a AAAA for each nameserver, before the real question
could be asked. Now the second name under such a domain starts where the first
one finished:

```
before   datatracker.ietf.org -> start at zone org.        (12 addrs)
after    datatracker.ietf.org -> start at zone ietf.org.   (5 addrs)
```

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

Every RRset is judged against the zone that actually served it, which matters
most for the ones that arrive with no signature at all. A CNAME leaving a
signed zone for an unsigned one is ordinary — half the CDN-hosted internet
looks like that — and the answer is insecure, not forged. An RRset whose own
zone *is* signed arriving without its signature is the stripping attack, and
that is refused with `RRSIGs Missing`. The two are told apart by provenance:
the resolver records which zone produced each record as it accepts it, so the
question is answered from fact rather than inferred from whatever else happens
to share the message.

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

ML-DSA verification follows FIPS 204, and the DNSSEC side follows
`draft-westerbaan-dnssec-mldsa`, which gives ML-DSA-44 algorithm number 18 —
the number the public test zones sign with, and the default here. IANA has not
made it final and the draft assigns nothing to the 65 and 87 parameter sets, so
all three remain settings rather than constants: point `mldsa44-algorithm` at
whatever your zone publishes. The draft's worked example is in the test suite,
so the key tag, the DS digest and a real RRSIG are checked on every build.

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
recursive resolver on `127.0.0.1:5335`. (Not 5353 — that is mDNS, and
avahi-daemon holds it on most Linux hosts; because both sides set
`SO_REUSEADDR` the clash is silent rather than an error.) The shipped file documents every
setting at its default value.

```
listen: 127.0.0.1@5335
access-control: 127.0.0.0/8 allow

cache-size: auto           # or 2G
serve-stale: 86400         # RFC 8767
prefetch: yes
prefetch-threshold: 10     # refresh with 10% of the TTL left
refresh-nxdomain-confirmations: 3

dnssec: yes
root-zone-transfer: no     # yes = pull every TLD delegation at startup

dns64: no
dns64-prefix: 64:ff9b::/96

forward-zone: internal.example 10.0.0.53@5335   # recursive upstream
stub-zone: corp.example 10.1.0.53               # iterative, treated as authority
```

Behind AdGuard Home, point its upstream at `127.0.0.1:5335` and leave Elpis on
loopback.

### Privileged ports

If a `listen` line asks for a port below the system's privileged threshold
(1024, or whatever `net.ipv4.ip_unprivileged_port_start` says), Elpis checks
for the right to bind it *before* opening any socket and, if it is missing,
says so with the port named and the ways to fix it:

```
FATAL cannot listen on 0.0.0.0:53: port 53 is privileged on this system
      (ports below 1024 need root or CAP_NET_BIND_SERVICE), and this
      process is uid 1000 with neither
FATAL   pick one:
FATAL     - grant the capability once: sudo setcap cap_net_bind_service=+ep /usr/local/sbin/elpis
FATAL     - start as root and set 'user:' in elpis.conf so it drops privilege after binding
FATAL     - listen on an unprivileged port instead, e.g. 'listen: 127.0.0.1@5335'
FATAL     - or lower the range system-wide: sysctl net.ipv4.ip_unprivileged_port_start=53
```

Sockets are bound before privileges are dropped, so `user:` works with either
of the first two. Running as root with no `user:` configured is allowed but
warned about once.

### Listening on everything

Two lines, and that is the whole of it:

```
listen: 0.0.0.0@53
listen: [::]@53
```

Both are needed. Every IPv6 listener sets `IPV6_V6ONLY`, so `[::]` carries
IPv6 only — it will not pick up IPv4 the way a dual-stack socket does. That is
deliberate: a dual-stack socket reports IPv4 peers as v4-mapped addresses,
which would make `access-control` rules quietly ambiguous about which family
they matched.

Listing a specific address *as well as* the wildcard is redundant — the kernel
prefers the specific socket, so it works, but it costs descriptors for nothing
and Elpis says so. Startup names every socket it actually bound, which is the
first thing to check when a client cannot reach it:

```
INFO    bound udp 0.0.0.0:53
INFO    bound tcp 0.0.0.0:53
INFO    bound udp [::]:53
INFO    bound tcp [::]:53
INFO  listening with 8 workers
```

### The query arrives but no answer comes back

A resolver that cannot route its reply looks exactly like one that is not
listening: the client times out either way. Elpis separates the two. Every
failed `sendmsg` is logged with the destination, the source address it tried,
and the kernel's reason:

```
WARN  could not send the reply to [2001:db8::5]:34766 from [2001:db8::1]:0:
      No route to host -- the query arrived but this host cannot route the
      answer back
```

If that line appears, the problem is routing, not DNS — `ip -6 route get`
the client address and see what the kernel says.

Replies are normally sent from whatever address the query arrived on, which is
what a multi-homed host wants. On a container whose global address sits on one
interface while the default route sits on another, the kernel rejects that
combination outright. Rather than lose the answer, Elpis drops the pinned
source and retries, letting the kernel choose; for an on-link client it picks
the same address anyway.

The same question applies outbound, so the root probe answers it before it
sends anything:

```
INFO  root probe: IPv4 queries will leave from 192.168.88.118:39698
INFO  root probe: IPv6 queries will leave from [2001:db8::1]:53539
INFO  root probe: 26 of 26 addresses answered (IPv4 13/13, IPv6 13/13), 3 rounds
```

That is a route lookup, not a packet, so it costs nothing and it distinguishes
*this host has no route for that family* from *the packets leave and nothing
comes back*. A host with no IPv6 route says so plainly:

```
INFO  root probe: no IPv6 route to the root servers (Network is unreachable)
```

Having an address is not the same as having a route. An interface can hold a
global IPv6 address and still carry no outbound traffic — `ifconfig` showing
millions of RX packets against a few hundred TX on that interface is the
signature. Use `outgoing-interface:` to pin the source address Elpis sends
from when the kernel's own choice is wrong.

### Something else on port 53

Before opening any socket, Elpis asks the kernel who is already listening on
the addresses it was told to bind, and names the process:

```
FATAL dnsmasq (pid 812) is already listening on 0.0.0.0:53/udp,
      which conflicts with 'listen: 0.0.0.0:53'
FATAL   command: /usr/sbin/dnsmasq --conf-file=/etc/dnsmasq.conf
FATAL   stop it, or move elpis to another port
```

This check is not cosmetic. Elpis sets `SO_REUSEADDR`, and **as root, Linux
lets a UDP socket bind a port another process already holds — with no error**.
Verified on a systemd-resolved host: a bind to `0.0.0.0:53`, and even to
`127.0.0.53:53` itself, succeeds silently while resolved keeps running, and
the kernel then splits arriving queries between the two at random. Waiting for
`bind()` to complain would mean waiting forever.

systemd-resolved is the one case handled automatically, since it is the one
that is both common and safely fixable. Running as root, on a port it holds:

```
WARN  systemd-resolved (pid 460) is listening on 127.0.0.53:53,
      which conflicts with 'listen: 0.0.0.0:53'
INFO  stopping systemd-resolved so the port can be bound cleanly
INFO  systemd-resolved stopped
WARN  /etc/resolv.conf still points at the systemd-resolved stub (127.0.0.53),
      which is no longer listening -- this host cannot resolve names until you
      repoint it
WARN  systemd-resolved will come back on reboot; make it permanent with
      'systemctl disable --now systemd-resolved'
INFO  listening with 8 workers
```

Set `stop-systemd-resolved: no` to have it refuse instead. Nothing else is
ever stopped — an unrelated daemon on the port is reported and Elpis exits.
Under the shipped systemd unit it runs as `elpis`, not root, so it cannot stop
anything; the unit uses `Conflicts=systemd-resolved.service` and lets systemd
do it.

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
