# 🧠 Caching

How Elpis stores answers, when it refreshes them, and what it does when a
refresh goes wrong.

## 💽 The caches

Sized automatically from the memory this process can actually use:

```
 ┌─────────────────────────────────┬─────────────────────┬────────────┬──────┐
 │ message 50%                     │ RRset 32%           │ deleg. 12% │ inf. │
 └─────────────────────────────────┴─────────────────────┴────────────┴──────┘
```

| cache | share | holds |
|-------|-------|-------|
| message | 50% | complete prebuilt responses |
| RRset | 32% | individual RRsets with their signatures |
| delegation | 12% | root and TLD nameservers, pinned |
| infra | 6% | per-server round-trip times, EDNS quirks and DoT state |

> [!NOTE]
> "What this process can use" is the smallest of: what `sysconf` reports,
> `MemTotal` in `/proc/meminfo` (which lxcfs replaces inside an LXC container),
> and every `memory.max` or `memory.limit_in_bytes` along this process's own
> cgroup path, walked upwards.
> <br><sub>A limit set on an ancestor binds just as tightly as one on the
> cgroup itself. Reading only the cgroup root finds the limit solely when the
> container also has a cgroup namespace putting it there, which LXC doesn't;
> everywhere else the host's whole memory is reported, and the cache would be
> sized for RAM that doesn't exist.</sub>

**A cache hit is cheap:** a 12-byte header, the client's question echoed back
verbatim, and one `memcpy` of a prebuilt blob with the TTLs patched in place.
Nothing is re-encoded and no name is re-compressed.

| | queries/s at a 100% hit rate |
|---|---|
| eight-core VM, not especially quiet | **600,000–780,000** |
| a single thread | about 200,000 |

### With EDNS Client Subnet on

- An answer an authority **tailored to one client subnet** goes into the
  message cache under that subnet, and never into the RRset cache, where every
  client would find it.
- An answer learned **without a subnet**, from a server that would have taken
  one, is the view from wherever Elpis is. It's kept, but a client with a
  subnet of its own passes it over and asks for one of its own.

<sub>See [EDNS Client Subnet](configuration.md#-edns-client-subnet).</sub>

## 🔄 Refreshed before they expire

A popular name never goes cold: it's refreshed in the background while it's
still being served. The refresh starts when `prefetch-threshold` percent of the
original TTL is left, 10 by default.

```
 a 300-second record

 0s ──────────────────────────────────────────── 270s ──── 300s
 │◄──────────── served from cache ─────────────►│◄─ 30 s ─►│
                                               refresh     would
                                               starts      expire
```

### When a refresh fails

A failed refresh never costs you the answer. The two ways a refresh can go
wrong get opposite treatment:

| refresh comes back | what it means | what happens |
|---|---|---|
| timeout, SERVFAIL, REFUSED | nothing about the name | keep serving it, retry with backoff |
| authoritative NXDOMAIN | the name is gone | believed, but only after it repeats |

**An unusable reply** says nothing about the name. The cached answer stays and
is served under RFC 8767 while the retries back off: 1 s, 2, 4, 8, up to a
minute.

<sub>The backoff is the point: the usual reason a refresh fails is that the far
side is rate limiting, and asking once a second is how a brief limit becomes a
permanent one. Against an upstream that went dark for 40 seconds, it's the
difference between 28 refresh attempts and 5.</sub>

**An NXDOMAIN** is an answer, not a failure, but one a rate-limited server can
give by mistake. So it has to repeat `refresh-nxdomain-confirmations` times in
a row before the records are dropped.

| `refresh-nxdomain-confirmations` | about |
|---|---|
| 3 (default) | seven seconds |
| 6 | a minute |

<sub>Believing it at once would let one bad reply take a live name down;
ignoring it forever would serve a deleted name for the whole `serve-stale`
window, a day by default. The attempts are backed off, so the count is really
a length of time. Below it the glitch is absorbed and no client ever sees it;
above it the records are dropped and the next query resolves for real.</sub>

## 🌳 Every level of the delegation chain

Every level is cached, so a lookup restarts as deep as anything already known
allows:

```
.                 root hints, pinned
com.              pinned, exempt from eviction
example.com.      cached for the delegation's TTL
sub.example.com.  cached the same way, when it is a zone cut of its own
```

- **Only the root and the TLDs are pinned.** There are about 1,438 TLDs, a
  bounded set worth holding forever. `root-zone-transfer: yes` fetches all of
  them by AXFR at startup, so they're there before the first query.
- **Everything below expires on its own TTL.** A domain's nameservers change,
  and a delegation pinned past its TTL is a stale answer that never heals.
- **Glueless delegations are kept too**, as soon as their nameservers have
  addresses.

<sub>A parent can only glue names inside its own zone, so every domain whose
nameservers live elsewhere (anything on a third-party DNS provider in another
TLD) arrives glueless. Keeping only the glued ones meant those domains were
rebuilt from scratch on every lookup: back to the TLD for the referral, then an
A and a AAAA for each nameserver, before the real question could be asked.</sub>

```
before   datatracker.ietf.org -> start at zone org.        (12 addrs)
after    datatracker.ietf.org -> start at zone ietf.org.   (5 addrs)
```

---

<sub>[README](../README.md) · [Compiling](COMPILING.md) · [Configuration](configuration.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
