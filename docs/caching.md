# Caching

How Elpis stores answers, when it refreshes them, and what it does when a
refresh goes wrong.

## The three caches

Three caches, sized automatically from the memory this process can actually
use. That is the smallest of: what `sysconf` reports, `MemTotal` in
`/proc/meminfo` (which lxcfs replaces inside an LXC container), and every
`memory.max` or `memory.limit_in_bytes` along this process's own cgroup path —
walked upwards, because a limit set on an ancestor binds just as tightly as one
set on the cgroup itself. Reading only the cgroup root finds the limit solely
when the container also has a cgroup namespace putting it there, which LXC does
not; everywhere else the host's whole memory is what gets reported, and the
cache is then sized for RAM that does not exist.

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

### When a refresh fails

A failed refresh never costs you the answer. The two ways a refresh can go
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

## Every level of the delegation chain

Every level of the delegation chain is
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

---

[Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Internals](internals.md) · [Troubleshooting](troubleshooting.md)
