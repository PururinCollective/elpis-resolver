# Internals

Why the hot paths are built the way they are, and what is deliberately
missing.

## Measuring the roots

At startup Elpis asks all twenty-six
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

## The awkward parts of resolution

CNAME chains that cross zones (each link signed
by a different zone, each validated against its own chain of trust), DNAME
subtree rewrites with the synthesised CNAME RFC 6672 asks for, QNAME
minimisation with a fallback for authorities that answer NXDOMAIN for empty
non-terminals, and DS queries sent to the parent rather than the child.

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

## Linking and portability

Build targets and CPU tuning are covered in the [README](../README.md#install).

SSE2/AVX2 and NEON kernels are selected at runtime from CPUID; the scalar
fallbacks are always compiled, and the test suite checks that every vector path
agrees with them byte for byte, so a vectorised build can never answer
differently from a portable one.

Nothing calls `getaddrinfo()` or `getpwnam()` — address literals and
`/etc/passwd` are parsed directly — so a static glibc link carries no `dlopen()`
surprises. A resolver that silently fails to drop privilege is worse than one
that refuses to start.

## Not here

RFC 8198 aggressive NSEC. Answering from cached denial records needs an
ordered index the hash tables cannot provide, and a half-implementation that
sometimes misses is worse than asking.

DoH, DoT and DoQ. Elpis speaks UDP and TCP. Put it behind something that
terminates the encrypted transports if you need them.

Authoritative service, zone files, dynamic update, TSIG signing. This resolves;
it does not serve.

---

[Caching](caching.md) · [Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Troubleshooting](troubleshooting.md)
