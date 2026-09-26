# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org):
the major number changes when a config file that worked stops working.

Every binary also carries the exact commit it was built from. The About window
on the status page shows it, and so does the identity probe:

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
```

## Unreleased

### Added

**Instances can warm each other, with nothing on disk.** With `mesh: yes`,
instances you run connect to the bridges in `mesh-peer:` and to the instances
those know. One that starts asks the others for the questions their clients ask
most, merges them with its checkpoint if there is one, and warms the lot.
Measured with three instances: the only one with clients, restarted with no
checkpoint, was warm four and a half seconds later, its slowest answer 158 ms
against 1,065 ms cold. Names only, never answers, and only names asked
`mesh-share-min-hits` times. Connections are Noise_NNpsk0 over TCP, keyed by
one PSK from `elpis --gen-psk`: X25519 for forward secrecy, ChaCha20-Poly1305,
and the PSK mixed into every key, so recorded traffic stays safe from a future
quantum computer while the key does. See [Mesh](docs/mesh.md).

**Instances on one network segment find each other.** With the mesh on,
`mesh-lsd: yes` (the default) has each instance announce itself by multicast,
to `239.255.78.78` and `ff12::7878` on UDP 7878 with a hop limit of 1, and the
others dial it, so a segment needs no `mesh-peer:` at all. Announcements carry
an HMAC tag under a key derived from the PSK: another mesh on the same network
is ignored without a word. Measured on one host, an instance with no bridge was
found and warm 4.5 seconds after starting.

**A miss can be answered by a nearby instance.** With `mesh-lookup: yes`, a
client question that misses the cache is also sent to the nearest peer within
`mesh-lookup-rtt` whose cache digest (a Bloom filter each instance sends every
half minute) says it has the answer, while resolution goes on as usual;
whichever answers first goes to the client. A, AAAA and HTTPS only, NOERROR
only (records or NODATA), never CD. The peer's answer carries no AD and is
resolved again here straight away: our own answer replaces it, and one we
cannot confirm is dropped and not asked of peers again for ten minutes.
Lookups are UDP sealed with ChaCha20-Poly1305 under per-instance keys handed
out inside the Noise sessions and replaced hourly, and a peer answers only the
addresses of its mesh connections. Measured with warm-up off: a second
instance answered 60 sites with a median of 0 ms against 214 ms cold.

**A mesh can require licensed instances.** With `mesh-require-licence: yes`,
each instance holds its own key (`elpis --mesh-keygen`) and a certificate for
it from the licence issuer (`elpis-licence issue --mesh-key …`). The handshake
becomes Noise_XXpsk0, in which each side proves it holds the key its certificate
names, and a peer is let in only with a certificate from this build's issuer,
unexpired, for our own organisation. A leaked PSK is no longer enough to join;
a certificate copied from someone's config is refused, even from a build
patched to present it; another customer of the same issuer stays out. The
certificate is a separate token from the deployment licence, signed under its
own context, and the resolver still contains no signing code. See
[Mesh](docs/mesh.md#requiring-licensed-instances).

**A restart can come back warm.** With `checkpoint:` set to a path, Elpis
writes down the questions clients ask most, every `checkpoint-interval` and
never at shutdown, and after a restart resolves them all again, most valuable
first, before clients ask. Names are ranked by how often they are asked times
how long they took cold, so the far-away ones come first. Measured on 60 sites
after a restart, the slowest went from 1,580 ms cold to 13 ms warmed; the
warm-up took 1.3 seconds. The file holds names, never answers, so everything
it brings back is resolved and validated as usual. It is still a list of what
clients looked up, so it is off by default and written `0600`. See
[Caching](docs/caching.md#surviving-a-restart).

## 2.0.2 — 2026-09-25

### Fixed

**A glueless-name flood could grow a worker to gigabytes.** `max-pending`
capped the client queries admitted, but a resolution is more than one task: it
spawns children for a glueless zone's nameserver addresses and for the DNSSEC
chain walk, and background refreshes make tasks of their own. None of those
were counted, so a flood of uncacheable names on glueless, signed zones — a
livestream app cycling through thousands of unique CDN hostnames — fanned the
child trees out to hundreds of thousands of tasks at once, roughly 100× the
limit, and grew the process to several gigabytes. Task creation now stops at a
ceiling of four times `max-pending`, counting children and refreshes, so the
table can never grow past the memory the config budgets for; past it a task is
refused, which every caller already answers with SERVFAIL or a degraded
lookup.

**Memory a spike used was never handed back.** glibc keeps freed allocations on
its arenas' free lists rather than returning them to the OS, so once a burst
drained, the resident size stayed at the peak — 3.9 GiB seen holding 200 MiB of
live caches — indefinitely. A worker now trims the heap back once a minute when
the load has passed, so the resident size follows the working set down again.

## 2.0.1 — 2026-09-24

### Changed

**The build string names the release.** A build from a release tag reports
just the tag, `v2.0.1`. Any other build reports its branch and commit,
`main@bcc97d252fac`. It appears in the About window, the status JSON and the
identity TXT record. The `-dirty` suffix is gone. It marked every build made
with an uncommitted change, and a release showing it looked broken.

### Added

**`dns64-strip-a`: an IPv6-only network without turning IPv4 off.** With
`dns64: yes`, A questions are answered with no A records (NOERROR: the name
still exists), so a client sees only AAAA. That is the real AAAA where a name
has one and a synthesised address in the DNS64 prefix where it does not, so
everything it looks up is reached over IPv6 or through NAT64. `ipv4only.arpa`
keeps working, so CLAT still finds the prefix. A client that sets DO and CD is
validating for itself and gets the real data, as with DNS64. Every client of
the resolver loses IPv4 in DNS, so it is meant for an instance or listener of
its own:

```
dns64: yes
dns64-prefix: 2402:4e20:b00b:7fff:64:ff9b::/96
dns64-strip-a: yes
```

### Fixed

**DNS64 listed a CNAME chain twice.** Synthesising for a name reached through
CNAMEs copied the chain from its A lookup into an answer that already held it,
so `www.baidu.com` AAAA listed every CNAME twice.

## 2.0.0 — 2026-09-24

The first release meant to be left running. After the review that made 1.1.15,
this one went looking for what the review had not reached: forwarding set-ups,
the shutdown path, and a benchmark across the services people actually use.

It is 2.0 for one reason. Behind `forward-zone: .`, a private zone that the
upstream serves now has to be routed here as well (see **Changed**), so a
config that resolved it before will not until that line is added. Apart from
that, no config that worked stops working.

The benchmark covered 28 groups of popular services, 1,221 lookups: Epic,
Ubisoft Connect, EA, Steam, Google, YouTube, Telegram Web, WhatsApp, Pixiv,
Apple, Microsoft and Windows Update, Discord, Lowyat.net, GitHub, ASUS, MSI,
Acer, Gigabyte and other PC vendors, Taobao, Shopee, Malaysian banks and
government sites, and more. Every host of a site was asked A, AAAA and HTTPS
at once, as a browser asks, and each answer was checked against 1.1.1.1:

```
                         p50       p90       p99
Elpis, warm cache        0.6 ms    1.1 ms    1.5 ms
Elpis, cold cache        82 ms     269 ms    709 ms   (real recursion from empty)
1.1.1.1 from here        4.2 ms    15.5 ms   170 ms
```

Elpis agreed with 1.1.1.1 on 1,218 of 1,221 answers. In two of the three, a
CDN answered differently for a different location. In the third,
`www.pbebank.com` AAAA, Elpis answered and 1.1.1.1 returned SERVFAIL. The
lookups that failed are the ones the zone itself breaks: `www.cimb.com.my`'s
nameservers drop HTTPS-type queries unanswered, so 1.1.1.1 cannot answer them
either.

### Added

**Resolution failures are remembered (RFC 9520).** A question whose resolution
ends in SERVFAIL is answered SERVFAIL straight away for a while, with EDE 13
"Cached Error". The first hold is 5 seconds; it doubles while the same
question keeps failing, up to a minute, and any answer clears it. Before
this, every retry repeated the whole failed resolution. For `www.cimb.com.my`
HTTPS that took 5.3 seconds the first time and 9.5 the second, and browsers
ask that type for every site and retry failures. Every worker thread shares
the one record, so a retry arriving on a different worker is answered at
once too. Refusals under `max-pending` are not recorded.

### Fixed

**Behind `forward-zone: .`, an answer stripped of its signatures was
served.** Every record is stamped with the zone that served it, and the
validator declines to judge an unsigned record with no stamp. The stamp was
the zone's label count, which made the root 0, the same as no stamp. Under
`forward-zone: .` the root is the zone every question is asked under, so
nothing forwarded was ever judged. A forwarder, or anything on the path to it,
could remove the signatures from a signed answer and have it served as an
ordinary unsigned one, without AD, instead of refused. `harden-dnssec-stripped`
did nothing in that mode. Answers that arrived signed were validated as usual.

Through a forwarder that removes the signatures from A and AAAA answers:

```
                                      before           now
www.isc.org A                         NOERROR, no AD   SERVFAIL, EDE 10
dnssec-failed.org A                   NOERROR, no AD   SERVFAIL, EDE 9
github.com A                          NOERROR, no AD   NOERROR, no AD
```

And through one that does not validate, a name whose signatures are missing at
the source:

```
<id>-nosig.test-alg13.dnscheck.tools  NOERROR, no AD   SERVFAIL, EDE 10
```

An unsigned answer is now followed down the signed tree, through the same
forwarder, until its zone is proven unsigned. The proof is kept, so the next
name under the same unsigned zone costs no further signature checks: 20 new
names under github.com took 5 verifications, where without it they took 41.
When resolving directly, the root zone's own data is now judged the same way;
nothing that validated before changes.

**DNS64 skipped DNSSEC-aware clients and synthesised for the one it must
not.** RFC 6147 has a client that sets both DO and CD validate for itself and
do its own synthesis, so it must be given the data untouched. DO alone is
what any DNSSEC-aware forwarder sends, AdGuard Home with DNSSEC enabled among
them, and it should be synthesised for like anyone else. Elpis had the two
the other way round. Behind such a forwarder an IPv6-only client got no
address at all for an IPv4-only name, and CLAT on Android, Windows and
Apple devices could not find the NAT64 prefix from `ipv4only.arpa`:

```
github.com AAAA, DO set       before: NOERROR, no answer   now: 64:ff9b::14cd:f3a6
ipv4only.arpa AAAA, DO set    before: NOERROR, no answer   now: 64:ff9b::c000:aa ...
github.com AAAA, DO and CD    before: synthesised          now: left as it is
```

Names with real AAAA records, NXDOMAIN answers and answers that fail
validation are treated as before: kept, not synthesised over, and SERVFAIL.

**AD was set on NXDOMAIN answers that NSEC3 opt-out cannot prove.** Some
signed zones prove that a name does not exist with an NSEC3 "opt-out" span.
That shows the name is not among the records the zone signed, but an unsigned
delegation the zone chose not to sign could still be there. RFC 5155 section
9.2 forbids AD on such an answer, and Unbound and 1.1.1.1 leave it off. Elpis
set it, for every nonexistent name under `.com` and `gov.my`, among others. It
no longer does. Denials from zones that do not use opt-out, such as `isc.org`
and `nic.cz`, keep AD.

**`www.hasil.gov.my` failed with SERVFAIL.** The site of LHDN, Malaysia's tax
authority, is a CNAME to a name in an unsigned zone delegated below
`eservices.hasil.gov.my`, and that name is itself a CNAME, to Microsoft's
application proxy. Checking the chain of trust down to the answer, Elpis asked
for `eservices.hasil.gov.my`'s DS and got the CNAME back. It never found a DS
answer, and gave up with `no DS for eservices.hasil.gov.my after 2 attempts`.
A name that owns a CNAME cannot be the start of a delegated zone, so the check
now carries on past it. `www.hasil.gov.my` and `mytax.hasil.gov.my` resolve,
insecure as they should be, and `hasil.gov.my` itself keeps AD.

**Zones on a DNS provider's nameservers were always asked through the same
one.** Whether that nameserver was near or far made no difference. When a
zone's nameservers live in another domain, as on Google Cloud DNS, Route 53
or Azure DNS, Elpis looked up the address of one of them, used it, and cached
the zone that way. The others were never looked up while that one answered.
`telegram.org` was always asked through `ns-cloud-b1`, 80 ms away, never
through `b2` or `b4`, which are 7 ms away. Each new Telegram name also cost
a second round trip, a query-minimisation probe for `web.telegram.org` that
the cache could already answer. The other nameservers are now looked up in
the background and measured like any other server, and the probe is skipped
when the cache already has the answer. New Telegram names went from 164 ms to
7–9 ms. Telegram Web opens a dozen of them (`kws1`–`kws5`, `zws1`–`zws5`,
`venus`, `pluto` and more) as it loads.

**The private-zone rule from 1.1.15 now applies only to the zone configured.**
1.1.15 answered a stub-zone or forward-zone as insecure when the signed tree
proved it did not exist, and it applied that to any name under any configured
route. A route high in the tree, such as `stub-zone: .` for a local copy of the
root or a route for a whole TLD, covers every name below it. Under such a
route, a proof that `nosuchname.com.` does not exist made forged data for
`x.nosuchname.com.` insecure instead of bogus. The rule now needs the
configured zone to be at or below the name proven not to exist: `corp.` routed
and `corp.` denied. The exception for RFC 8020 (nothing below a nonexistent
name) is bounded the same way. Stub and forward zones for private names
resolve as in 1.1.15.

**Lookups still running at shutdown are freed.** Stopping the process freed
the queries it had outstanding but not the lookups waiting on them. Each of
those was left behind, and so were client TCP connections still waiting for an
answer. 1.1.15 reported nothing only because its test workload had finished
everything before it stopped. Stopped mid-flight, after 350 queries and 50 TCP
clients of which 40 were still waiting, it left 1.6 MB in 249 allocations. Now
every lookup still running is freed without answering anyone, then every
client connection is closed. Stopped the same way, valgrind reports 0 bytes in
use at exit: 5,447 allocations, 5,447 frees.

### Changed

**A private zone behind `forward-zone: .` has to be routed here too.** This
follows from the fix above. If the upstream serves `corp.` from a stub-zone of
its own, this instance no longer takes its word for it. The signed tree says
`corp.` does not exist, so the zone is refused (SERVFAIL, or NXDOMAIN once that
denial is cached) until it is routed here as well. It is then answered as
insecure, as in 1.1.15:

```
forward-zone: . 10.0.0.53
forward-zone: corp 10.0.0.53
```

## 1.1.15 — 2026-09-24

A release review: the faults a resolver meets after weeks of running that a
benchmark never shows. TCP, which answered only from the cache, and stub zones
under DNSSEC work again. Memory has a ceiling, the status page no longer waits
on a slow client, and valgrind reports nothing at exit. No config that worked
stops working. `tld-refresh` and `root-refresh`, always in the shipped config,
now take effect, and `tcp-idle-timeout` means what it says.

### Added

**The CPU a binary was built for, beside the compiler.** The startup line, the
About window and the CPU pane of the Task Manager now say what the build was
aimed at as well as what built it:

```
elpis 1.1.14 starting: ..., epoll, gcc 13.3.0, x86_64 znver3 (native), ...
```

The instruction set — `x86_64`, `arm64`, `riscv64` and so on — comes from the
compiler's own predefined macros, so it is what the binary is. The CPU is
`-march` and `-mtune` as the compiler resolved them, which is how
`-march=native` becomes `znver3 (native)`. A build that set neither says
`generic`; one that tunes for something else says `haswell tuned for znver3`.

**`max-pending`, a ceiling on the resolutions a worker has open.** Nothing
limited them before. Each takes about 11 KB, 26 KB more while it is being
validated, and lives as long as `query-total-timeout`: 30,000 queries to a zone
whose servers answered slowly took the process from 5 MB to 326 MB, and a flood
of names that miss the cache carried on until the kernel stepped in. Past the
ceiling, a query that misses the cache is answered SERVFAIL at once, which a
forwarder in front takes as its cue to try another upstream. It is counted as
`overload=` in the statistics and logged with a rate-limited warning. Cache hits
and local answers are never refused. The same flood now peaks at 50 MB.

```
max-pending: auto        # one per MiB this process may use, 512 to 4096
```

Background refreshes, which had a fixed limit of 4096, now stop at half of it.

**`make fuzz`.** A libFuzzer harness for everything a DNS message passes
through before it is trusted: the parser, every record type's rdata, and the
NSEC and NSEC3 denial proofs. It needs clang and builds with ASan and UBSan
into `bin/`, apart from the normal build. The first run went through 13.4
million inputs without a finding.

### Fixed

**TCP answered only what was already cached.** `tcp-idle-timeout` is written
in seconds and was used as milliseconds, so the shipped `10s` closed every
client TCP connection ten milliseconds after its query arrived. Anything
answered from the cache took microseconds and got through; anything that had
to be resolved lost its connection first, and the client waited out its own
timeout. 1.1.14 answered none of 12 fresh names over TCP, and all of them now.
Everything that falls back to TCP was affected: a forwarder retrying a
truncated reply, clients set to use TCP, large answers.

**Stub zones and forward zones for private names failed with DNSSEC on**, which
is the default. The first query for a name under a stub-zone or forward-zone
for, say, `corp.` or `home.arpa.` was SERVFAIL, logged as
`dnssec: no DS for corp. after 2 attempts`. From the second query on it was
NXDOMAIN.

The validator's lookup of the DS for `corp.` came back NXDOMAIN, which is cached
under a different key from a DS answer, so the validator never found it and
kept asking. A configured zone that the signed tree proves does not exist is
now answered as insecure, without AD. The proof must verify against the
parent's keys. Anywhere else, data for a name the signed tree says does not
exist is still refused. The NXDOMAIN from the second query on came from the
RFC 8020 rule that nothing exists below a nonexistent name. The rule is sound
for the public tree, but inside a zone the operator routed elsewhere it
answered for names that zone actually serves. It no longer applies there.

**`trust-anchor-file` loaded nothing from an ordinary anchor file.** The parser
read `NAME [CLASS] TYPE`, and every usual source of an anchor file puts a TTL
in that line: root.key as unbound-anchor writes it, a saved dig, a zone file.
The TTL was read as the type, every line was skipped, and the startup line said
`0 loaded` without a warning. The built-in root keys hid this. Past eight
fields a line was also cut short, and dig splits a key into chunks, so a root
KSK in dig's format would have loaded truncated, as an anchor that matches
nothing.

The TTL and class are now accepted in either order, and up to 32 fields are
read. A line with more is refused rather than cut. An anchor line that cannot
be read is reported with its line number, and a key with the REVOKE bit set is
refused (RFC 5011).

```
WARN  trust-anchor-file '/etc/elpis/root.key' line 7: unreadable DS record, skipped
```

**The root and TLD delegations were never refreshed.** A TLD's delegation is
pinned the first time the root refers to it, and pinned entries do not expire.
Every lookup under the TLD starts from that entry, so nothing asked the root
about it again: a TLD's nameservers and their addresses stayed as first learned
for as long as the process ran. A TLD that renumbered would be followed to its
old addresses until a restart. `tld-refresh` and `root-refresh` were meant to
prevent this but were read and never used. When a pinned delegation is older
than its interval, or its TTL if that is shorter, the next query under it now
sends one refresh in the background and carries on with what is pinned.

**A TCP client that hung up mid-query made its worker spin.** The closed socket
stayed registered until the answer was ready, and a closed socket is always
readable. Four such clients held 2.8 cores; the same four now cost nothing. The
idle timer also no longer closes a connection that is waiting on an answer.
A client that pipelines queries and never reads the answers is no longer read
from once 64 KB of answers are waiting. Before, its buffer grew to 4 MB, or
2 GB for a worker with 512 such connections. Its queries are served again once
it catches up.

**The status page could be held by one slow client.** It serves one
connection at a time with a five-second timeout on each read, so a client
sending a byte every few seconds held it indefinitely. That locked everyone
else out and stopped the traffic history, which is sampled on the same thread.
A whole request now has three seconds. A login whose body arrived in a TCP
segment of its own, as a browser may send it, failed with the right password;
the body is now read to its `Content-Length`.

**Failed logins on the status page are logged safely.** The warning was
unthrottled and printed the user name as sent, URL-decoded, so `%0A` started a
new line of its own in the log. It is rate limited now, and every log line has
its control characters replaced. A POST with no `user` field logged whatever
the stack held, since that buffer was only filled when the field was present.
It is logged as `(none)` now.

**Nothing left behind at exit.** The validator's per-thread memory, a 512 KiB
signing buffer and a pool of validation states, was never freed, so every
shutdown reported about 2 MB as leaked and buried anything really lost. Under
ASan and valgrind across the full workload, the leak report is empty.


**A stripped answer asked for twice could be served the second time.** An
answer whose signatures had been removed was refused when first asked for — and
served, as an ordinary unsigned answer, to a second question arriving while the
first was still being validated:

```
<id>-nosig.test-alg13.dnscheck.tools A, twice, 200 ms apart
  first:  SERVFAIL  323 ms
  second: NOERROR   166 ms   the unsigned address
```

Records are cached as they arrive, before the chain of trust is walked. The
copy off the wire knows which zone served it, which is how an unsigned record
in a signed zone is recognised as forged; the cached copy did not, and a record
the validator cannot place counts as insecure. Bad and expired signatures were
not affected — those are checked whatever the zone. The cache now keeps the
zone with the record.

It surfaced as dnscheck.tools failing "Missing" behind a MikroTik forwarding to
AdGuard Home over plain DNS: the MikroTik asks again after a failure or a
dropped reply, AdGuard sends every question to every Elpis upstream, and the
repeat lands inside the window. Any two clients asking for the same name within
a quarter of a second would have done the same.

**No OPT record in replies to queries that had none.** RFC 6891 says a client
that sends no OPT record does not speak EDNS and must not be sent one. Answers
from the cache already obeyed; every answer that had to be resolved carried
one anyway.

**Changing `OPT` over an existing build now rebuilds it.** make watched files,
not flags, so a build switched to `-march=znver3` without `make clean` kept
every object compiled the old way, and the 1.1.14 version bump produced a
binary that still called itself 1.1.13. The flags are kept in a stamp that
everything compiled with them depends on: changing them recompiles all 51
objects, and repeating a build with the same flags compiles none.

## 1.1.14 — 2026-09-24

Mostly speed: new names under unsigned zones, and cold lookups anywhere. Along
the way, a handful of lookups that failed, and two DNSSEC answers that claimed
more than they had proven.

### Fixed

**AD was set on answers that passed through an unsigned CNAME.** A CNAME chain
answered from cache took the security status of its last link, so an unsigned
zone's CNAME into a signed name came out authenticated:

```
distro-gateway-prod.ol.epicgames.com.         CNAME  ...cdn.cloudflare.net.  unsigned
distro-gateway-prod.ol.epicgames.com.cdn.cloudflare.net.  A  104.18.12.27     secure
```

That is every Epic Games Launcher name behind Cloudflare, and anything shaped
like it. It also happened when the CNAME had just come off the wire and had not
been validated at all: a secure record cached at its target vouched for it, and
validation was skipped because that record needed none.

An answer is now as secure as its weakest link. One with a link nobody has
checked is validated whole before it is sent. Chains signed end to end —
`www.icann.org`, `www.apnic.net`, `www.sidn.nl` — keep AD, and chains from a
signed zone into an unsigned one still get none.

**Records fetched after a cached secure CNAME were cached as validated.** They
were stamped with the task's status as they arrived, and following a cached
CNAME had set that to the CNAME's. A later hit served them with AD, and the
chain walk takes a DS or DNSKEY marked secure without checking it again.
Everything off the wire is cached unchecked now; only the validator records
verdicts.

**`www.gov.uk` failed now and then with SERVFAIL, `EDE 20`.** A QNAME
minimisation probe drew BADCOOKIE, and the retry asked the full question
instead of the probe. nic.uk answers `www.gov.uk` with a CNAME into
`service.gov.uk` and that zone's NS set alongside. Read as the answer to the
probe, that looked like a referral, and `www.gov.uk` was sent to
`service.gov.uk`'s servers, which refused it one after another. Retries now
resend the question actually in flight, and a referral is only taken for a
zone that contains the name being resolved.

**A zone was given up on after one pass through its servers.** Once each
address had been asked, the lookup failed: about a second in, with most of
`query-total-timeout` unspent. `max-retries` was read from the config and never
used. It is now the number of further rounds through the zone's servers, and
each attempt after the first round is held to `query-timeout`, so a zone whose
servers are all down still fails in seconds.

A reply slower than its timer is no longer thrown away, either. The query keeps
listening for one more timeout, so the server is measured and the next lookup
waits for it properly. Against a test server answering 500 ms late, the first
lookup takes 876 ms and the next 500, where it used to fail.

**Servers that drop case-randomised names are asked in lowercase.** For a while
on release day `intel.com`'s four servers answered `www.intel.com` and ignored
`wWw.InTeL.cOm` completely, and with 0x20 on — the default — every cold lookup
of the name failed. A server that has timed out without ever answering a
randomised name is now asked once as-is. If that is answered, it is remembered,
and the log says so:

```
INFO  192.0.2.53:53 answers only names sent in lowercase; case randomisation is off for it
```

Any later answer to a randomised name clears it again, so a server that is only
slow keeps its 0x20. Nothing is randomised over TCP any more, where the
handshake already keeps an off-path attacker out.

**BADCOOKIE was only ever retried on a task's first query.** Anywhere after a
minimisation probe or a referral, it was taken as the server failing and the
next one was tried. Each query now gets its own single retry.

Once a server rejects a cookie it issued itself, it is sent the client half
only. g-root and the `.uk` servers do this often — one address, many machines,
each with its own secret — and the retry could land on a third. Over the DNSSEC
test set, 7 to 20 BADCOOKIEs a run became 2 to 4, one per such server.

### Changed

**An unsigned zone is proven unsigned once, not once per name under it.** A new
name in an unsigned zone was validated by walking from the root, down to the
parent's signed proof that the zone has no DS. The verdict was recorded, but
only looked up for the zone apex, so the next name walked again. `com` and
`net` sign with P-256, at 2.6 ms a signature here, and the proof is two of
them. Every new name under an unsigned `.com` domain held its worker for five
milliseconds, with the other queries on that worker queued behind it.

dnscheck.tools times exactly this, with random names under `null-addr.com`,
`.net` and `.org` (A and AAAA together, warm):

| | 1.1.13 | 1.1.14 |
|---|---|---|
| `null-addr.com`, `.net` | 12.4 ms | 1.8 ms |
| `null-addr.org` | 2.3 ms | 1.7 ms |

1.1.1.1 measures 3.3–4.0 ms from the same host. The reply now leaves 37 µs after
the answer arrives, down from 5.7 ms. The root key set's check against the
trust anchor is recorded the same way, once per copy rather than once per
validation.

**A slow server no longer hides a fast one.** A server never used was ranked on
a 376 ms guess, so once one server of a zone had been measured, however slow,
the rest were never tried. From the test host every `com` and `net` referral
went to a gtld server 160–200 ms away, while `b.gtld-servers.net` answers over
IPv6 in 11.

When the best known server is slower than 10 ms, the same question now also
goes to one never-measured address in the delegation, and the first usable
answer wins; the other is measured anyway. While nothing under 40 ms is known,
up to eight more addresses are asked as well, purely to be measured, so a
delegation the size of `com`'s is mapped within a few queries. Exploring stops
once every address has been measured, until its infra entry expires an hour
after last use. Forwarders, stub zones and TLD warming never explore. The
statistics line counts the extra queries as `raced=`.

**The DS a signed referral carries is kept.** It is what a DS query returns,
and the validator asked for it anyway, one zone at a time, after the answer
was in hand. `www.baidu.com` crosses three unsigned `com` zones and waited on
three sequential DS round trips for proofs it had been given on the way down.
The data is cached unchecked and verified on the walk like anything fetched. A
kept denial that proves nothing is dropped and the parent asked directly, as
before.

Together, from a fresh start, 157 sites resolved the way a browser does —
`www.` names, A + AAAA + HTTPS, six at a time — three runs each:

| | median | p90 | mean |
|---|---|---|---|
| 1.1.13 | 502–527 ms | 1220–1385 ms | 655–676 ms |
| 1.1.14 | 80–96 ms | 350–370 ms | 156–164 ms |

No SERVFAILs in either. And every host the sites reported as not opening load,
all at once, from a fresh start — the time until the last one answers:

| | 1.1.13 | 1.1.14 |
|---|---|---|
| forums.linuxmint.com | 1.2 s | 0.6–0.7 s |
| Epic Games Launcher, 37 hosts | 2.5–2.6 s | 0.6–0.8 s |
| Taobao, 30 hosts | 2.6–2.9 s | 0.9–1.0 s |
| Shopee MY, SG, ID | 0.8–1.7 s | 0.2–0.5 s |

All 285 of those answers match 1.1.1.1's, on both versions.

**Failing takes longer.** With `max-retries` in effect, a zone whose servers are
all unreachable answers SERVFAIL after a few seconds rather than about one. The
shipped `elpis.conf` has always said `max-retries: 3`, so existing configs get
this too; set it to `0` for a single pass, as before.

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
