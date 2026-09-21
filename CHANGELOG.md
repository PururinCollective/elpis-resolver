# Changelog

Notable changes, newest first. Versions follow [semantic versioning](https://semver.org):
the major number changes when a config file that worked stops working.

Every binary also carries the exact commit it was built from. The About window
on the status page shows it, and so does the identity probe:

```bash
nslookup -q=txt elpis.sakurako.oomuro 127.0.0.1
```

## 1.1.4 — 2026-09-22

### Fixed

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
