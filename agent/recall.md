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

## 📌 Open items

| item | note |
|---|---|
| ARMv8 AES/PMULL path | not written: no aarch64 toolchain or qemu to test it. ARM uses the portable AES (ChaCha20 is offered first there anyway). |
| X25519 speed | 154 µs/op with 10×25.5-bit limbs; 51-bit limbs with a 128-bit type could be ~4× faster. Only matters if handshakes get frequent. |
| DoT session resumption | not done; each handshake is full. |
| P-256 key share | only if the "no X25519" counter shows real servers need it. |
| README contact for commercial support | a TODO comment, waiting on the maintainer. |
