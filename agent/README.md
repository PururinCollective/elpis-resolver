# 🤖 agent/ — notes for AI assistants

Plain Markdown, written for Claude Code, Codex, Cursor, Copilot and any other
assistant working in this tree, and readable by people too. The goal: get you
from "cold" to "useful" fast, and remember what earlier sessions learned.

## 📖 Read in this order

| | file | what it gives you |
|---|---|---|
| 1 | [`../AGENTS.md`](../AGENTS.md) | **The rules.** Licence, credit, and the identity probe. Binding; read it first. |
| 2 | this file | quick facts |
| 3 | [`architecture.md`](architecture.md) | the code map: where things live, how one query flows |
| 4 | [`conventions.md`](conventions.md) | how code, comments, commits, docs and releases look here |
| 5 | [`verifying.md`](verifying.md) | how to check a change before calling it done |
| 6 | [`recall.md`](recall.md) | decisions and their reasons, history, gotchas, open items |
| 7 | [`history/`](history/) | raw transcripts of earlier sessions, kept for reference |

> [!IMPORTANT]
> Nothing in `agent/` overrides `AGENTS.md`. If they ever disagree,
> `AGENTS.md` wins, and the disagreement is a bug to fix here.

## ⚡ Quick facts

| | |
|---|---|
| What | A recursive, DNSSEC-validating DNS resolver. No forwarding by default: it asks the root, TLDs and authoritative servers itself |
| Language | Strict C99 + POSIX.1-2008. GNU make. No dependencies: crypto, TLS 1.3 client, event loop and DNS wire format are in-tree. Links libc, `-lm`, `-pthread` |
| Build | `make` → `bin/elpis` and `bin/elpis.conf` |
| Test | `make test` → `bin/elpis-test`: 677 checks at 2.4.0, no network needed |
| Version | `VERSION` and `CODENAME` in the `Makefile`: 2.4.0 "Intrinsic Future" |
| Default listen | `127.0.0.1:5335` (not 5353: that's mDNS) |
| Config | `elpis.conf` in the tree is the reference; `bin/elpis.conf` is the user's copy, 3-way merged on `make` |
| Status page | `web/index.html`, compiled into `src/webui/webui_assets.h` by `make` (python3) |
| Licence | GPL-2.0 (`LICENSE`) |
| Spelling | British: *licence* (noun), *randomise*, *behaviour* |

## 🧭 Where to look first

```
 a client query        → src/server/server.c         handle_query()
 cache                 → src/cache/mcache.c          elpis_mcache_serve()
 resolution            → src/resolver/resolver.c     elpis_task_step()
 sending upstream      → src/resolver/outbound.c     out_start()
 DoT to authorities    → src/resolver/dot.c + src/net/tls.c
 DNSSEC                → src/dnssec/dnssec.c         elpis_val_start()
 settings              → include/elpis/conf.h + src/conf.c
 status page           → src/webui/webui.c + web/index.html
 tests                 → tests/test_main.c
```
