# 🧭 Architecture

Where things live and how one query moves through them.

## 🧵 Process shape

```
 main.c: config, caches, workers, signals, status page thread
   │
   ├── worker 0 ─┐   one thread each; owns its event loop (src/net/loop.c),
   ├── worker 1  │   listening sockets (SO_REUSEPORT), outbound UDP socket pool,
   ├── ...       │   DoT connections, and every task it started.
   └── worker N ─┘   Per-thread state uses ELPIS_TLS (__thread).
          │
          ▼
   shared, sharded caches (src/cache/): message · RRset · delegation · infra
   CLOCK eviction, shared read locks, no refcounts: copy out before unlock.

   status page (src/webui/): its own thread, one connection at a time.
```

- **The only lock on the hot path is a cache shard lock.** Anything else
  shared (telemetry rows, stats folding) is off the per-query path or batched.
- **Worker stats** (`elpis_stats_t` in `include/elpis/ctx.h`) are plain
  `uint64_t` counters, folded into the global copy by delta every tick
  (`publish_stats()` in `main.c`). Add a field and it's summed automatically.

## 🔎 One query

```
 UDP/TCP packet
   │  src/server/server.c  handle_query()
   ▼
 local names?  src/server/localzone.c   localhost, private reverse, identity probe
   │ no
   ▼
 message cache  src/cache/mcache.c  elpis_mcache_serve() ── hit ──► reply (memcpy + TTL patch)
   │ miss
   ▼
 task  src/resolver/resolver.c   elpis_task_start() → elpis_task_step()
   │   states: INIT → LOOKUP → DELEG → SEND → WAIT → (NSADDR) → VALIDATE → FINISH
   │
   │   choose_server()   cheapest untried address; DoT-capable first when
   │                     authoritative-dot is on; held servers skipped
   │   send_query()      elpis_out_send(), plus races/probes to unmeasured servers
   ▼
 outbound  src/resolver/outbound.c   out_start()
   │   picks the transport from the server's infra entry:
   │     UDP (default) · TCP (after TC, or TCP-only servers) · DoT (src/resolver/dot.c)
   │   0x20 case, random ID/port, cookies, ECS, EDNS padding over DoT
   ▼
 reply  handle_message() → elpis_resolver_on_response()
   │   referral → next zone; CNAME/DNAME → follow; answer → validate
   ▼
 DNSSEC  src/dnssec/dnssec.c   elpis_val_start()   (may spawn child tasks: DNSKEY, DS)
   ▼
 cache store + elpis_task_respond()  (src/server/server.c)
```

## 📁 Code map

| path | holds |
|---|---|
| `src/main.c` | startup, workers, signals, tick (stats, expiry), licence gate on `identity-name:` |
| `src/conf.c`, `include/elpis/conf.h` | settings: defaults, parsing, `elpis_conf_dump()` |
| `src/util.c`, `src/log.c`, `src/stats.c` | helpers, logging, SIGUSR1 statistics |
| `src/licence.c` | licence token decode and Ed25519 check (**protected, see AGENTS.md**) |
| `src/quirks.c` | built-in zone quirk list |
| `src/conflict.c` | who holds the port, systemd-resolved handling |
| `src/dns/` | names, messages, rdata, EDNS, cookies, ECS |
| `src/cache/` | sharded hash table (`cache.c`), message/RRset caches, `infra.c` (per-server RTT, EDNS, cookies, hold-down, DoT state), `delegation.c` |
| `src/net/loop.c`, `sock.c` | epoll/kqueue event loop and timers; socket helpers |
| `src/net/tls.c` | TLS 1.3 client engine: bytes in/out, no sockets (`include/elpis/tls.h`) |
| `src/server/` | client side: `server.c`, rate limits, RRL, `localzone.c` (**identity probe: protected**), DNS64 |
| `src/resolver/resolver.c` | the task state machine, server choice, referrals, CNAME/DNAME, QNAME minimisation |
| `src/resolver/outbound.c` | queries out, response matching, timeouts, TCP fallback, DoT transport choice, safety net |
| `src/resolver/dot.c` | DoT connection pool per worker: open, pipeline, idle close, failure hand-back |
| `src/resolver/roots.c`, `tld.c`, `axfr.c`, `probe.c` | priming, TLD warming, root zone AXFR, root RTT probe |
| `src/dnssec/` | validator, NSEC, NSEC3, trust anchors |
| `src/crypto/` | SHA-1/2/3, RSA, ECDSA, Ed25519, ML-DSA (verify; public data) and the TLS primitives: X25519, HKDF, ChaCha20-Poly1305, AES-128-GCM (+ `aes_ni.c`), constant time, in `include/elpis/tlscrypto.h` |
| `src/simd/` | SSE2/AVX2/NEON kernels, CPUID dispatch (`elpis_cpu()`) |
| `src/webui/` | status page server (`webui.c`), telemetry tables (`telemetry.c`), self-info (public IP, AS) |
| `web/index.html` | the status page source → `src/webui/webui_assets.h` (generated) |
| `tests/test_main.c` | every self-test; `vectors.h` (frozen crypto vectors), `rfc8448.h` (TLS trace) |
| `tests/fuzz_*.c` | libFuzzer: DNS messages, TLS client |
| `tools/` | `conf-merge.sh` (3-way config merge), `mkassets.py`, `licence.c` (licence tool), `tls-probe.c`, `cputarget.sh` |
| `contrib/` | systemd unit, `elpis-update.sh` (pull, build, restart), `elpis-reinstall.sh` (account, unit, commands, systemd-resolved, resolv.conf) |

## 🧱 Key types

| type | header | what |
|---|---|---|
| `elpis_conf_t` | `conf.h` | all settings |
| `elpis_ctx_t` | `ctx.h` | process-wide: config, caches, stats, licence, self-info |
| `elpis_worker_t` | `resolver.h` | one thread's loop, sockets, tasks, DoT pool, stats |
| `elpis_task_t` | `resolver.h` | one resolution (client query or child lookup) |
| `elpis_outq_t` | `resolver.h` | one query in flight to one server (UDP, TCP or DoT) |
| `elpis_dotconn_t` | `resolver.h` | one DoT connection |
| `elpis_infra_info_t` | `infra.h` | per-server state: RTT, EDNS, cookie, 0x20, hold-down, ECS, DoT |
| `elpis_tls_t` | `tls.h` | one TLS 1.3 client session |

## ➕ Adding things

| to add | touch |
|---|---|
| a setting | `conf.h` field + comment → `conf.c` default, `KEY(...)` parse, `elpis_conf_dump()` if useful → `elpis.conf` (commented, at its default) → `docs/configuration.md` → a test in `tests/test_main.c` |
| a counter | `elpis_stats_t` in `ctx.h` (`uint64_t`, folded automatically) → `/api/status` in `webui.c` → `web/index.html` |
| a status page window | `web/index.html` `VIEWS` entry; `make` regenerates `webui_assets.h`. Keep the About credit lines (AGENTS.md) |
| a per-server fact | `elpis_infra_info_t` + an `infra_update()` callback in `infra.c`; entries expire after an hour of disuse unless `dot_keep` says otherwise |
| a test | a `static void test_x(void)` with `section("...")` and `CHECK(cond, "message")`, called from `main()` |
