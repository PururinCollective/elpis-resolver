# 🧠 Recall

What earlier sessions learned, so the next one doesn't relearn it. Add to it
when you learn something that isn't obvious from the code or `CHANGELOG.md`.

## 📅 Timeline

| release | date | in one line |
|---|---|---|
| 1.0.0 | 2026-09-21 | first release |
| 1.1.x | 2026-09-22 → 24 | fast fixes from real use: unsigned children of signed parents (`forums.linuxmint.com`), TCP replies never read, OPT on the wrong owner, 376 ms for unmeasured servers, serve-stale vs validation |
| 2.0.0 | 2026-09-24 | first release meant to be left running; major because `forward-zone: .` needs private zones routed too |
| 2.0.1 | 2026-09-24 | build string names the release (`v2.0.1` / `main@<hash>`); `-dirty` is gone |
| 2.0.2 | 2026-09-25 | a glueless-name flood could grow a worker to gigabytes: task ceiling |
| 2.1.0 | 2026-09-28 | stress test: KeyTrap exposure, a way to deny names in signed zones, stored XSS on the status page, the first quirks |
| 2.2.0 | 2026-09-30 | EDNS Client Subnet, server hold-down, shipped-config merge, `bogus answer` reasons |
| 2.2.1 | 2026-10-02 | DNSKEY/DS with TTL 0 validate; a proof too big for UDP is truncated |
| 2.3.0 | 2026-10-03 | post-quantum downgrade protection, RFC 8509 root key sentinels |
| 2.4.0 "Intrinsic Future" | 2026-10-05 | opportunistic DoT to authoritative servers (RFC 9539) with an in-tree TLS 1.3 client; `caps-exempt:`; release names begin |
| 2.4.1 "Lettersong" | 2026-10-05 | starting at boot (LXC, VM) before the addresses are up: listeners bind anyway, `outgoing-interface` sockets wait and retry |
| 2.4.2 "Lettersong" | 2026-10-05 | the shipped unit drops `Conflicts=systemd-resolved`, which silently cancelled Elpis at boot; Elpis names resolved's stub when it holds the port |
| 2.4.3 "Resilient Journey" | 2026-10-06 | `contrib/elpis-install.sh`: account, unit, enable, and `RESOLVED=replace` to take systemd-resolved's place on 127.0.0.53; scripts run in place from the clone (`/opt` recommended); 127.0.0.53 messages fixed |
| 2.4.4 "Celestial Equations" | 2026-10-07 | A FORMERR with no question, to an EDNS query, is read as an EDNS refusal and the same server asked again plain: every Exchange Online mail host (`*.mail.protection.outlook.com`) had been a SERVFAIL |
| 2.4.5 "Celestial Cascade" | 2026-10-08 | A cached record past its TTL and past every signature on it is a cache miss, for answers and for the validator's DNSKEY/DS/denials: `accounts.pandasecurity.com` (Route 53, signed on the fly for ~65 min, TTL 300) had been a SERVFAIL once stale |

## 🧭 Decisions, and why

### DoT to authoritative servers (2.4.0)

| decision | why |
|---|---|
| Opportunistic only, no certificate check | An NS record names no identity to check a certificate against (RFC 9539). The server's Finished is verified. |
| `authoritative-dot: yes` refused | Kept for a possible strict mode that would rather fail than send in the clear. |
| Untested server: plain **plus** a DoT copy | The first query is never slower; the copy is the test. |
| Available for `ttl` (24 h) **after the last DoT answer** | A server in use stays on DoT; renewed at most once a minute. |
| Failed → plain, retried every `retry` (1 h); given up after `max-try` (24) failed retries | Maintainer's choice. Never-worked servers get the same treatment. `0` = never give up. |
| DoT-capable servers chosen first, **whatever their RTT** | Maintainer's call: about 81% of answers come from cache at ~0.5 ms, so a slower server costs little. Guards: not if failing (`ELPIS_RTT_BAN`) or held. |
| No race, probe or plain copy beside a DoT query | The name must not leak in the clear to anyone else. |
| A cold connection waits for its handshake | Every query to a DoT server stays encrypted. |
| Safety net: no DoT reply in the usual time → same question plain; plain answers → DoT failed | Never lose an answer to DoT; DoT trouble never counts against the server's hold-down. |
| DoT state lives in the infra entry, kept past the usual hour (`dot_keep`); everything else in the entry resets after an hour (`freshen()`) | Failed retries must be counted across hours; RTTs must not go stale. |
| TLS 1.3 only, X25519 only, no SNI, ALPN `dot`, padding to 128 | What DoT servers actually run; SNI would send the name in the clear. A server without X25519 alerts 40 ("no X25519"), not HRR. |
| Suite order by hardware: AES-GCM first with AES-NI, ChaCha20 first otherwise | Fastest on each CPU. |
| No DoQ | A QUIC stack is several times the rest of the crypto, and few servers offer it. |

### Starting at boot (2.4.1, 2.4.2)

| decision | why |
|---|---|
| The shipped unit has no `Conflicts=systemd-resolved` (2.4.2) | Found while chasing a VM where Elpis never started at boot, nothing logged; that VM's unit had never been enabled (see the gotcha below), so the race was not what it hit. The race is real all the same, modelled with user units on systemd 255: if resolved's start matters (a `Requires=` chain), or anything starts resolved while Elpis's start job waits for `network-online.target`, systemd drops or cancels Elpis's job silently, so `Restart=` never applies. Now Elpis always starts and fails loudly, and the operator masks resolved or sets `DNSStubListener=no`. The `ExecStopPost=` hand-back went with it. |
| Port 53 on 127.0.0.53 / 127.0.0.54 named as resolved's stub without proof | Not root, Elpis can't read resolved's `/proc/<pid>/fd`, and "something is already listening" helped no one. Only the message uses this guess; nothing is stopped on it. |
| `IP_FREEBIND` on listeners, **not** on outbound sockets | Tested: on Linux an IPv6 socket with it, bound to an address the host doesn't have, sends from it (IPv4 gets `ENETUNREACH`). A listener only replies to queries that reached its address. |
| Outbound slots kept and retried (1, 2, 4, 8 s, then every 10 s); an absent IPv4 source no longer exits | The same "start, warn, catch up" as listeners. Before, IPv6 slots vanished silently until a restart. |
| "Not here yet" is a throwaway `bind()` to port 0, not `getifaddrs()` | The shipped unit's `RestrictAddressFamilies=AF_INET AF_INET6` refuses the netlink socket `getifaddrs()` needs, so it always fails under systemd. |

### Servers that refuse EDNS (2.4.4)

| decision | why |
|---|---|
| A FORMERR or NOTIMP with **no question section**, no OPT, to a query that carried one, is matched on ID, port and address alone | The servers for `mail.protection.outlook.com` (`ns1`/`ns2-proddns.glbdns.o365filtering.com`) send exactly that to any EDNS query. Matched on the question, it was dropped as a spoof, and every Exchange Online mail host timed out into a SERVFAIL. |
| Not believed from a server whose infra entry already says `ELPIS_EDNS_YES` | With no question there is no 0x20 to check, so a spoofer who guessed the ID and port could switch EDNS, and DNSSEC with it, off for a server that speaks both. What is left is the window before a server's first EDNS answer, or after an hour unused, when `freshen()` starts its entry over. |
| The same server is asked again, plain; not the next one | RFC 6891 section 7. A zone's servers usually run the same software, so the next one only returned the same FORMERR. |
| A reply with no question teaches nothing about 0x20 | It says nothing about how the name was sent. |
| DoT unchanged | No DoT server without EDNS has been seen. |

### Stale records past their signatures (2.4.5)

| decision | why |
|---|---|
| Stale **and** every signature outside its window → a miss, asked again | It can never validate. Built into an answer it was refused as bogus; read as DNSKEY or DS it failed every validation under the zone, with nothing to replace it for the whole serve-stale day. |
| Only stale records; a fresh one with an expired signature is still used | That is a zone that really is broken: it must stay bogus (EDE 7), not turn into a fetch loop and "no DNSKEY after 2 attempts". |
| Stale records inside their signatures still served | RFC 8767 is the point of serve-stale; those still validate. |
| Denials checked through the signatures kept with their proof | A NODATA/NXDOMAIN marker keeps its NSEC/NSEC3 and RRSIGs as items after the SOA, not in `sigcount`. A stale proof that lapsed can't show an unsigned cut. |
| The message cache left alone | Its stale replies go out with EDE 3 and a short TTL while a refresh runs, which already worked. |

### The built-in blocklist (unreleased)

| decision | why |
|---|---|
| Compiled in from `bogus.txt` in the ElpisDNS repo, never fetched | Maintainer's call ("an array source file"); the list is gathered from their honeypot. Nothing at runtime depends on GitHub being reachable. The refresh `sed` one-liner is in the file's header comment. |
| REFUSED + EDE 15 (Blocked), not NXDOMAIN or a silent drop | REFUSED doesn't lie about the namespace; a drop makes stubs retry, which is more packets, not fewer. RFC 8914's 15 is "blocked by the resolver operator's policy". |
| Checked right after the RD/snoop check, before `localzone` | A listed name is refused whatever the type: ANY would otherwise get the RFC 8482 HINFO. Queries for a listed name aren't printed by `log-queries`, which comes later. |
| A hash table looked up once per label suffix, skipping suffixes with more or fewer labels than any entry | A linear walk would make every query pay for the length of a list that's meant to grow. About 16-22 ns per query on the maintainer's box, hit or miss (2026-10-09). |
| Only the client's question, not CNAME targets or NS names | The point is cheap refusal of floods; following chains would mean a task. |
| `blocklist: no` switches it off; no per-name unblock yet | An escape hatch for a false positive without a rebuild. `vtb.com` is VTB Bank's (NS `ns1-3.vtb.ru`), with a 3,367-byte signed DNSKEY answer (via 1.1.1.1, 2026-10-09), so likely there as an amplification name; its real users get REFUSED too. |

### Older ones

| decision | why |
|---|---|
| CLOCK, not LRU, in the caches | A hit is a relaxed byte store under a shared lock; LRU would put a writer on the hottest path. |
| No RFC 5011 | A writable anchor state file is a path for walking the resolver onto an attacker's key. |
| No RFC 8198 aggressive NSEC | The hash tables can't give the ordered index it needs; half an implementation is worse. |
| No `getaddrinfo()` / NSS | Static glibc builds stay safe; privilege drop can't silently fail. |
| Default port 5335 | 5353 is mDNS, and avahi holds it; the clash would be silent. |
| `edition:` self-declared; signed licences for real claims | See `docs/licensing.md`; licences never change resolution. |
| Identity probe never carries an IP | An unauthenticated UDP probe must not map anyone's network. |
| Releases are named | Maintainer's wish, from 2.4.0. Ask for each name. |

## 🚧 Gotchas

- **`pkill -f <pattern>` kills your own shell** when the pattern appears in the
  command line. Stop processes by PID.
- **The user may run real Elpis instances.** Check `ps` before stopping
  anything; test on high ports with a scratch config.
- **Check vectors with Python's `cryptography` before freezing them.** RFC
  7748's second vector was once misremembered.
- **Most authoritative servers drop SYNs to port 853.** About 90% of DoT tests
  end in the 3 s timeout. Known to speak DoT (October 2026): `b.root-servers.net`
  (170.247.170.2), Facebook's authoritative servers, Wikimedia's (198.35.27.27),
  and some `.gr` servers.
- **TLD warming at startup** triggers DoT tests against many TLD servers in the
  first seconds (about 100). Normal.
- **Loopback `connect()` refuses synchronously**; remote refusals arrive later
  as an event. `dot.c` handles both.
- **A Python TLS test server adds 40 ms per query** (Nagle) unless it sets
  `TCP_NODELAY`. That's the test server, not Elpis.
- **Infra entries expire after an hour of disuse**, except while their DoT
  state needs keeping.
- **The status API wants a session**: `POST /api/login` then `GET /api/status`.
- **`webui_assets.h` is generated.** Edit `web/index.html` and run `make`.
- **A disabled unit looks exactly like a cancelled one**: inactive,
  `Result=success`, `NRestarts=0`, not a line in the journal. Ask for
  `systemctl is-enabled` before theorising about transactions. 2.4.2 was
  first written up as fixing a race on the maintainer's VM; the unit there
  had simply never been enabled.
- **`Conflicts=` can cancel a unit with no trace.** A queued start job is
  replaced by the stop that a conflicting unit's start brings: the unit is
  inactive, not failed, and nothing is logged. Test transactions like this
  with throwaway user units in `$XDG_RUNTIME_DIR/systemd/user`
  (`systemctl --user`), no root needed.
- **No sudo, but `unshare -rn sh script.sh` works**: root inside a private
  network namespace, so `ip addr add`, veth pairs and port 53 all work. That
  is how the boot race was reproduced: start Elpis, then add the address. Use
  a **veth pair** for IPv6: a dummy link is NOARP and skips duplicate address
  detection, so its addresses are never `tentative`.
- **Ageing the cache needs a clock shift.** Stale-data bugs only show once a
  record is past its TTL *and* its signature, and the test binary can't move
  the cache clock. A scratch `LD_PRELOAD` that adds a file's seconds to
  `CLOCK_REALTIME` and `CLOCK_MONOTONIC` works (`clock_gettime` and `time`;
  re-read the file every 200 ms). Real upstreams sign live: pick the shift so
  the cached signature has expired but a fresh one has not (Route 53: cache,
  wait 3 min, shift +63 min).

## 📌 Open items

| item | note |
|---|---|
| ARMv8 AES/PMULL path | not written: no aarch64 toolchain or qemu to test it. ARM uses the portable AES (ChaCha20 is offered first there anyway). |
| X25519 speed | 154 µs/op with 10×25.5-bit limbs; 51-bit limbs with a 128-bit type could be ~4× faster. Only matters if handshakes get frequent. |
| DoT session resumption | not done; each handshake is full. |
| P-256 key share | only if the "no X25519" counter shows real servers need it. |
| README contact for commercial support | a TODO comment, waiting on the maintainer. |
| `accounts.pandasecurity.com` on the maintainer's box | 2026-10-08: SERVFAIL EDE 6 on every query for minutes, healed after a fresh DNSKEY/CNAME fetch. Reproduced locally only as EDE 7 (stale CNAME past its signature), which heals after one failure; the fix covers stale answers and stale DNSKEY/DS/denials past their signatures. The box's own log line was not seen, so its exact EDE 6 path is unconfirmed. |
