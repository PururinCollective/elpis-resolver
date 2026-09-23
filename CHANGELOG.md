# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org):
the major number changes when a config file that worked stops working.

Every binary also carries the exact commit it was built from. The About window
on the status page shows it, and so does the identity probe:

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
```

## 1.1.13 — 2026-09-24

### Changed

**A server that has never answered is waited for 376 ms, not 1128.** With no
round trip measured yet, the timer's formula turned the 376 ms starting guess
into more than a second. Every cold lookup meets servers like that, and on a
path that loses one packet in twenty, each loss cost the client over a second
before the next server was tried — two such gaps in a single cold lookup of
an Epic Games name. The timer now waits the guess itself, as Unbound does, and
twice that over TCP for the handshake. A server genuinely further away loses
its first answer and is waited for properly from then on. Which server gets
picked is unchanged.

**Servers are offered 1400 bytes; clients still get at most 1232.** The two
limits used to share one default. They are separate now, because they cover
different paths:

- `edns-buffer-size` is what authoritative servers are offered, over this
  host's own uplink. 1400 is the most RFC 9715 recommends and fits a
  1500-byte link less PPPoE or a typical tunnel.
- `max-udp-reply-size` caps replies to clients, whose networks elpis cannot
  see. A reply too big for a client's path is not truncated, it is lost, and
  the client waits a second or more to ask again. It stays at 1232.

Expect little from the first. A reply is held to the smaller of the two sides'
limits, and many authorities cap their own at 1232 whatever they are offered.
Of 42 zones surveyed, the root and 41 TLDs, 36 have key sets under 1232
anyway. The five that just miss — `org`, `info`, `io`, `me`, `asia`, at
1317–1321 bytes — all cap at 1232 on their side. The root's key set is 1414
bytes and does not fit either way.

**Existing configs keep their old value.** The shipped `elpis.conf` used to say
`edns-buffer-size: 1232` explicitly, and a config seeded from it still does.
Change it to `1400` or `auto` to pick this up.

### Added

**`edns-buffer-size: auto`.** Sizes IPv4 and IPv6 separately at startup, from
the MTU of the route this host would take to the roots: the MTU less 28 bytes
of header for IPv4 or 48 for IPv6, never above 1400. It sends nothing, since
a UDP `connect()` only runs the route lookup, and falls back to 1232 for a
family whose route MTU cannot be read.

```
edns-buffer-size auto: IPv4 1400 (MTU 1500 on enp0s3), IPv6 1400 (MTU 1500 on enp0s3)
```

Use it when the resolver itself sits behind PPPoE or a tunnel: a 1442-byte
route gives IPv6 1394, a 1420-byte WireGuard route 1372. It can only see this
host's own route. A narrower link on a router further along is invisible from
here, so set a number yourself if you know of one.

## 1.1.12 — 2026-09-23

### Fixed

**An answer that came back over TCP in one piece was never read.** Every reply
truncated over UDP is repeated over TCP, and the reader took the length prefix,
then went round for another read before checking whether the message it
announced had already arrived. An authority normally sends the prefix and the
message together, so it usually had: the second read found nothing, the
complete answer sat in the buffer, and the query waited for bytes that were
never coming until its timer gave up on the server. Only replies split across
segments got through.

That made TCP look flaky rather than broken, and it has been this way since the
first release. The replies most likely to need TCP are the ones just over the
1232-byte EDNS limit, and those fit in a single segment — `org. DNSKEY` among
them. Anything served from Amazon's Route 53, whose nameservers live under
`awsdns-NN.org`, needed that key set to be trusted, so a cold lookup walked
every `org` server in turn, a quarter of a second apiece:

```
oRg. DNSKEY  199.249.120.1  TC -> TCP: 1324 bytes read, never parsed, 250 ms
oRG. DNSKEY  199.249.112.1  TC -> TCP: 1324 bytes read, never parsed, 250 ms
org. DNSKEY  199.19.56.1    TC -> ...
```

This is the likeliest reason the Epic Games Launcher would not start: its
dozens of service names all sit behind Route 53, and every one of them waited
on the same key set.

| cold, 23 Epic names × A/AAAA at once | median | slowest | over 2 s |
|---|---|---|---|
| 1.1.11 | 2727 ms | 4.0 s | 28 of 46 |
| 1.1.12 | 646 ms | 2.7 s | 3 of 46 |

With `edns-buffer-size: 512`, which pushes almost every signed answer onto
TCP, 1.1.11 answered `cloudflare.com`, `isc.org`, `ietf.org`, `nlnetlabs.nl`
and `www.gov.uk` with SERVFAIL after 18–20 seconds each. 1.1.12 answers all
five, signed ones with AD set.

A TCP attempt now also gets one round trip more than a UDP one before it is
abandoned, for the handshake. Without it a server much more than 100 ms away
could not answer over TCP inside its own UDP allowance.

**Clients that did not ask for DNSSEC records no longer get them from the
cache.** RRSIGs are fetched whenever validation is on, and were stripped from
the reply for a client without the DO bit — after the reply had been stored.
The first such client got a clean answer and every one after it was served the
signatures out of the cache. The cache entry is now built the same way as the
reply that was sent. A client that asks for RRSIG, NSEC or NSEC3 by type still
gets them.

**Answers no longer carry the random case of our own queries.** An authority
answers with the question as it was sent, which with 0x20 on meant the records
at the end of a CNAME chain came back as

```
DIsTrO-gatEWAy-pROd.OL.EPicGAMEs.CoM.cdN.CLOudflaRE.nEt. 202 IN A 104.18.13.27
```

beneath a CNAME pointing at the lowercase name — a casing no zone ever had.
Owner names are now folded as they come off the wire, as the RRset cache
already did, so the same chain reads the same whether it was just fetched or
served from cache. A client's own casing of its question is still echoed.

## 1.1.11 — 2026-09-23

### Fixed

**A reply whose OPT record sits on the wrong owner name is no longer thrown
away.** `dnsleaktest.com` would not resolve at all: its nameservers put the
question's name in the OPT owner field instead of the root, and the whole
reply was dropped for it.

```
WARN  drop reason=edns from=23.239.16.110:53 detail=upstream response
```

RFC 6891 section 6.1.2 does say the owner must be root, but that field carries
nothing — the payload size is in CLASS, the version and flags in TTL, the
options in the rdata. A server that fills it in wrongly has produced something
ugly, not something ambiguous, and refusing it made the zone unresolvable
through this resolver and no other.

Replies like this are now accepted and noted once in the log. Queries are
unchanged: there the resolver is the server, and a client sending a malformed
OPT still gets nothing back.

## 1.1.10 — 2026-09-23

### Added

- **Signature verifications, counted and reported.** The lifetime total and a
  rate on `SIGUSR1`, a per-second graph in the Queries window, and the total in
  Overview.

  ```
  dnssec verifies=34 (3.1/s over 11s of uptime)
  ```

  Public-key verification is the expensive thing a validating resolver does,
  so a rate here is the closest the resolver comes to reporting what the
  machine underneath it can take. Counted in `verify_with_key()`, which every
  algorithm passes through, and folded into the worker's statistics on that
  worker's own thread.

  Unlike the rest of the status-page counters this one is kept whether the page
  is on or not, because the point of it is to be readable from the log.

## 1.1.9 — 2026-09-23

### Added

- **Layout window.** The desktop as one line, to carry an arrangement to
  another browser. The layout lives in `localStorage`, which is per browser
  and per origin, so the same resolver reached through a tunnel and reached
  directly are two separate desktops with nothing between them. This is the
  way across. The text is produced and read in the browser and never sent
  anywhere.
- **The compiler that built the binary**, on the startup line, in About, and
  in the Task Manager's CPU pane. Two builds of one commit are not the same
  binary.

### Fixed

- `GET /?v=1` returned 404. A query string on the page URL is the client's
  business, and refusing it turns an ordinary cache-buster into a dead page.
- `make static` did not seed `bin/elpis.conf`, so a tuned build on a fresh
  clone produced a binary with no config beside it.
- The generated status-page header is now built by `make` from
  `web/index.html` rather than by hand. Regenerating it within the same second
  as the previous build left the old page compiled in, which is a very quiet
  way to spend an afternoon testing the wrong thing.

## 1.1.8 — 2026-09-23

### Fixed

**"Answered from cache" was the average over every query, not over cache
hits.** Each query was added to the cache figure and recursions were then
added to the upstream figure as well, so the number labelled as the cache's
was the mean of both. At a 70% hit rate it read around 138 ms for answers that
take microseconds — the recursions in it were doing all the work.

Each query now lands in exactly one of the two.

**Cache hits are measured in microseconds.** They were recorded as a flat
zero, on the grounds that the whole of a hit fits inside one tick of the
resolver's millisecond clock — true, but it makes the panel say nothing. The
clock is read for real on that path now, and only while the status page is on,
so a hit costs nothing extra when nobody is looking.

A cache hit reads about **9 µs** of resolver time. A `dig` against loopback
reporting 1 ms is measuring the round trip, not the lookup.

### Changed

- Latency figures carry their unit: microseconds below a millisecond,
  milliseconds above. `9 µs` rather than `0.01 ms`.

## 1.1.7 — 2026-09-22

### Fixed

**Unsigned children of signed parents were refused.** `forums.linuxmint.com`
and anything shaped like it returned SERVFAIL with `EDE 10 (RRSIGs Missing)`
while every other resolver answered.

`linuxmint.com` is signed; `forums.linuxmint.com` is delegated to an unsigned
child; both live on `ns1.loopiagroup.com`. Ask that server for the child's
address and it answers authoritatively for the child — `AA` set, no referral —
so nothing on the wire says a zone cut was crossed. The validator placed the
answer in the signed parent, found no signatures, and called it forged.

Telling the two apart needs the NSEC bitmap at the delegation: a zone cut is
**NS present, SOA absent**, and only then does a missing DS mean the child is
unsigned. `DS google.com`, `DS forums.linuxmint.com` and a name in a signed
zone with its signatures stripped all answer `NODATA` identically — two must be
served, one must be refused, and without the bitmap no rule gets all three
right.

The proof was being thrown away. Negative answers were cached as the SOA alone,
so by the time the descent saw "no DS here" the records proving it were gone.
They are now kept with the marker and checked against the keys of the zone
above — the same check a positive DS on that path already gets. Nothing is
believed that has not been verified.

## 1.1.6 — 2026-09-22

### Fixed

**Validation collapsed the moment serve-stale started working.** About a
quarter of an hour after start — however long a DS TTL happens to be — every
signed zone began failing with `no DS for <zone> after 2 attempts`, on a
resolver that had been validating correctly since boot.

The answer path serves expired data while a refresh is in flight, which is the
whole point of RFC 8767. The validator did not: it asked the cache for
validation material with serve-stale switched off, so the instant a DS or
DNSKEY expired it could no longer see the record sitting right there, retried
twice, and gave up. The client got the stale answer marked `EDE 3 (Stale
Answer)` while the validator behind it was told the DS did not exist.

Whether a DS or DNSKEY is still good is decided by the inception and expiration
on the signature over it, not by how long it has sat in the cache — those dates
are checked either way. The validator now reads stale material under the same
serve-stale budget as everything else. The one moment the resolver is designed
to keep working was the one this made it stop.

## 1.1.5 — 2026-09-22

### Fixed

**1.1.4 shipped half of its own fix — do not run it.** The field that records
which task owns a deduplicated lookup was added, and so was the check that
reads it, but the three lines that ever *set* it were lost between testing and
committing. The field stayed null, the check was therefore always true, and
every validation waiting on a shared lookup was abandoned instead of resumed.
That is worse than the bug 1.1.4 set out to fix, and it is immediate rather
than after a quarter of an hour.

1.1.5 is 1.1.4 as it was meant to be: slots record their owner, are retired
when that owner goes or no waiter is left, and a child reporting into a
recycled slot no longer wakes the wrong lookup.

## 1.1.4 — 2026-09-22

### Fixed

**Superseded by 1.1.5 — this release is incomplete and should not be run.**

**Validation stopped working after some minutes of uptime.** DS lookups began
failing in bulk — `no DS for google.com. after 2 attempts`, hundreds a
minute — for names that resolve perfectly well, on a resolver that had been
answering correctly since start.

Lookups that several validations want at once are deduplicated through a small
table: the first asks, the rest wait on its answer. The child doing the asking
belongs to the task that started it, so when that task goes away — its deadline
fires, the client gives up — the child goes with it and the callback that frees
the table slot never runs. The slot stayed occupied for the life of the
process, and from then on every validation wanting that name joined a lookup
that had already died, waited for nothing, and gave up. Popular names went
first, because they are the ones most likely to be in flight when a task is
abandoned.

Slots are now retired when the task that owns the lookup goes away or when
nobody is left waiting, and a child reporting into a slot that has since been
handed to a different lookup no longer wakes that lookup's waiters.

## 1.1.3 — 2026-09-22

### Fixed

**A DS lookup that failed was treated as proof that no DS exists.** An empty
result carries a denial — NXDOMAIN or NODATA — when the absence is real. A
lookup that simply did not come back carries nothing, and the validator could
not tell the two apart: it walked straight past the zone cut, concluded the
zone was unsigned, and served whatever arrived, forged signatures included.

Harmless while lookups succeed. When DS lookups start failing in bulk — which
they do on a busy resolver — every signed zone turns insecure at the same
moment, and a validator that was working a minute ago quietly stops. The log
says what is happening if you know to look for it:

```
WARN  dnssec: no DS for google.com. after 2 attempts (+145 suppressed in the last 10s)
WARN  dnssec: no DS for test-alg13.dnscheck.tools. after 2 attempts
```

Unknown now fails closed: a DS that could not be fetched is indeterminate, and
the answer is SERVFAIL rather than served unvalidated.

## 1.1.2 — 2026-09-22

### Fixed

**Data that failed validation stayed in the cache and was served.** The first
client to ask for a forged name got SERVFAIL, correctly. Every client after it
was handed the forged records straight from the cache, unvalidated, until the
TTL ran out.

RRsets are cached as a message is parsed, which happens long before the chain
has been walked. When the verdict came back bogus the answer was dropped from
the reply but left in the cache with no verdict attached, and a cached RRset is
served without revalidating. One query refused and the rest allowed is the
worst of both: from the outside it looks like validation is working.

Bogus answers are now taken back out of the RRset cache before the SERVFAIL is
sent. This is what dnscheck.tools reports as the Missing row, and it has failed
since the first release — 1.0.0 served such records on every query including
the first, so the earlier work in 1.1.0 and 1.1.1 made the cold query correct
without closing the hole behind it.

## 1.1.1 — 2026-09-22

### Fixed

**Negative answers were never validated.** A signed zone saying "that name does
not exist" was taken on trust: no NXDOMAIN and no NODATA ever carried AD, and
the NSEC and NSEC3 proof code, though present and correct, was never reached.

The resolver copied only the SOA out of a negative answer and discarded the
NSEC, the NSEC3 and every authority-section signature. An unsigned SOA made the
verdict *insecure*, and that verdict was returned before the denial check ran.
The SOA also carried no record of which zone it came from, so a denial with its
proof stripped was filed as merely unsigned rather than as an attack.

That is the hole DNSSEC exists to close. Anyone able to put a response on the
wire could deny any name in any signed zone and be believed — a way to make a
signed name disappear without forging a signature.

Denial records now reach the validator with their signatures and with the same
zone provenance answer records get. Negative answers in signed zones validate
and carry AD, matching what other validating resolvers return, and a denial
whose proof has been removed is refused with `EDE 10 (RRSIGs Missing)` instead
of served.

## 1.1.0 — 2026-09-22

The first release with a status page, and the one where DNSSEC validation
stopped costing far more than it should.

### Added

**A read-only status page**, off by default, `webgui: yes` to turn on. Windows
open from desktop icons and can be dragged, resized and tiled; a window whose
content does not fit grows to show it, and the desktop you leave — which
windows, where, how big, which in front — is the one you come back to.

| | |
|---|---|
| Task Manager | CPU, memory, network and queries in one window, sparklines on the left and the selected one drawn large |
| Overview | cache hit rate, response times, every counter, and how this host looks from outside: public IPv4, IPv6, AS number and AS name |
| CPU | utilisation across all cores, processor model, worker count, SIMD kernels, resolver and host uptime |
| Memory | resident size against the memory the resolver may use, and each cache's entries, bytes and hit rate |
| Network | throughput and the addresses actually bound |
| Queries | queries, SERVFAIL, bogus, cache hits and upstream, per second |
| Top names / Top clients | most queried, failing, bogus, and upstreams that stopped answering |
| Root servers | the roots ranked by the round trip this resolver has measured |
| Log | recent warnings and errors, holding your scroll position |
| About | version, build commit, edition and licence, and which ML-DSA parameter sets are live |

Counts are exact rather than sampled. Nothing is counted at all while the page
is off.

**An identity probe.** One TXT name answering what this resolver is, to a
client the access-control list already admits:

```
"elpis=1.1.0" "edition=community" "build=7c9c48d…" "uptime=3601"
"workers=8" "simd=avx2" "dnssec=validating"
```

The default name sits in an undelegated TLD, so it cannot be reached through a
forwarder chain and no scan of the DNS finds it. No address is ever in the
answer; the OS, kernel and hostname are behind `identity-system:`.

**Signed deployment licences.** `edition:` alone is self-declared. A licence is
the same claim carried by an Ed25519 signature from whoever issues licences for
a build, checkable offline. Issued with `make licence-tool` and
`elpis-licence`. It is not enforcement: the check runs once at startup, never
touches how a query is answered, and an expired licence is reported and
otherwise ignored. See [docs/licensing.md](docs/licensing.md) for what a
signature can and cannot prove.

**Build provenance.** `make` stamps the commit into the binary, with a `-dirty`
marker when the tree had uncommitted changes.

**`elpis --hash-password`**, for deployments whose config file is read-only —
which under the shipped systemd unit it is.

**Root server ranking and startup probing**, so the first recursions go to the
closest root rather than a default guess.

**Port conflict detection**, including stopping `systemd-resolved` when it
holds a port elpis was told to listen on, and only then.

**Delegation caching at every level**, so a lookup under a known zone starts
from the deepest cut already known instead of walking back toward the root.

### Fixed

**DNSSEC validation burned most of a CPU.** Under load it spiked to 400–700%
five minutes after every start. Four separate causes: a Montgomery context
rebuilt for every RSA signature, chain verdicts not recorded so proven work was
redone on every validation, 21 KiB buffer copies to carry a hundred bytes, and
child tasks created without bound — 84,684 per client query at its worst. Now
13.6 tasks per query and 0.7–2.7% CPU.

**A retry budget that could never be spent.** A DNSKEY that could not be
fetched cost the whole 20-second query budget and seven upstream fetches
instead of two attempts and a verdict, because the counter was reset by an
unrelated cached lookup landing between two failures. It also reported `EDE 22
(No Reachable Authority)`, which was untrue — the authority answered every
time, it just had no DNSKEY. Now `EDE 9 (DNSKEY Missing)`, and the log names
the record that failed.

**Signed answers wrongly called bogus.** Unsigned RRsets were compared against
other RRsets in the same message, which made a signed CNAME into an unsigned
zone look like tampering and caused a SERVFAIL storm across roughly 25 domains.
Provenance is now recorded per record at the moment it is accepted.

**ML-DSA-44 answered to the wrong algorithm number** — 24 rather than the 18
that `draft-westerbaan-dnssec-mldsa` assigns and the deployed test zones sign
with.

**Memory limits inside a container.** The resolver sized its cache from the
host's RAM rather than the cgroup limit — 128 GiB seen where 4 GiB was allowed.
It now walks `/proc/self/cgroup` and reads what lxcfs reports.

**Prefetch never ran for short TTLs.** The threshold truncated to zero below
100 seconds. Refresh failures now back off rather than retrying once a second,
which is how a brief upstream rate limit became a permanent one.

**IPv6 regressions**, including a configured-but-broken IPv6 path being
detected at startup and turned off for the run rather than silently costing
every lookup a timeout.

**`make static OPT=…` silently discarded the flags**, so a tuned static build
was not tuned.

### Changed

- Builds land in `bin/`, which is gitignored, and `make` seeds `bin/elpis.conf`
  from the shipped defaults once and never touches it again. `make install`
  goes to `/opt/elpis-resolver`.
- CPU percentage on the status page is averaged across cores rather than summed.
- The README is now an overview; the detail moved to [docs/](docs/).

## 1.0.0 — 2026-09-21

First release. Recursive resolver in portable C99 with no external
dependencies: DNSSEC validation (RSA, ECDSA, Ed25519, ML-DSA), NSEC and NSEC3
denial, qname minimisation, DNS cookies, 0x20 encoding, DNS64, RFC 8767
serve-stale, prefetch, message/RRset/delegation/infrastructure caches, root
priming and TLD warming, AXFR of the root zone, local zones and response rate
limiting.
