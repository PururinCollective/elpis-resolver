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

## Surviving a restart

A restart empties every cache, and for the first minutes each popular name
pays for its whole referral chain again. With `checkpoint:` set to a path,
Elpis writes down the questions clients ask most and, after a restart, asks
them all again before clients do.

Every message-cache entry counts how often it is asked. The count is a Morris
counter in a byte that was already padding, so an entry is no bigger: a hit
bumps it with a probability that halves every four steps, which keeps it
within about a third of the true count and means a name asked a million times
writes to its entry about seventy times rather than a million. A refresh
carries the count over to the entry that replaces it, along with the slowest
time the name took to resolve.

Every `checkpoint-interval` a thread of its own walks the cache, keeps each
question asked at least `checkpoint-min-hits` times, ranks them, and replaces
the file whole: a temporary file, fsync, rename. Nothing is written at
shutdown, so a restart is no slower than before. The ranking is how often a
name is asked times how long it took cold. A name whose servers are a
millisecond away is cheap to resolve on demand, and one on the other side of
the world is where the first client after a restart would wait:

```
# elpis checkpoint 1
# written 2026-09-25 20:46:13 UTC by elpis 2.0.2, 177 names
#
# The questions clients asked most, in the order a restart warms them:
# estimated hits, slowest resolution in ms, DO/CD bits, type, name.
4 1096 - HTTPS www.baidu.com.
4 1071 - A www.baidu.com.
```

At startup the list is read back and every worker resolves its share, from
the top, at `warm-rate` queries a second between them. It starts three seconds
in, behind root priming, and gives way to clients the way a background refresh
does. Each warmed entry starts with half the count the file carried, so a name
nobody asks for any more fades out over a few restarts.

The file holds names, never answers. An answer read back from disk might be
out of date, and its DNSSEC status would have to be proven all over again; a
name is simply resolved, validated like any other query. A name whose
signatures fail stays SERVFAIL however high it sits in the file. It is still a
list of what clients looked up, though, which is why it is off by default and
written `0600`: leave it off if you keep no logs. And since the path is
rewritten later, a file already there that does not start with the checkpoint
header is neither read nor overwritten, so a typo cannot take out a config
file.

Measured on the data-centre VM, 60 sites (A, AAAA and HTTPS at once, the way a
browser asks) queried after a restart, given the same four and a half seconds
either way:

| after a restart | median | 90th percentile | slowest |
|---|---|---|---|
| cold | 222 ms | 728 ms | 1,580 ms |
| warmed from a checkpoint | 0 ms | 2 ms | 13 ms |

The warm-up itself took 1.3 seconds for 177 questions. A new instance can
start warm too: copy the file from one that has been running, and set
`checkpoint-interval: 0` if it should only read it. Or let the instances ask
each other, with nothing on disk at all: see [Mesh](mesh.md).

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

[Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Internals](internals.md) · [Mesh](mesh.md) · [Troubleshooting](troubleshooting.md)
