# 📝 Conventions

How things look in this tree. Match what's around you.

## 💻 Code

- **Strict C99, POSIX.1-2008.** No GNU extensions required; compiler features
  sit behind `ELPIS_*` macros in `include/elpis/common.h`. No VLAs (`-Wvla`).
- **Builds warning-free** under gcc and clang at the Makefile's level
  (`-Wall -Wextra -Wshadow -Wstrict-prototypes ...`). Keep it that way.
- **Names:** `elpis_` prefix for anything external, `ELPIS_` for macros; file
  `static` for the rest. Headers live in `include/elpis/`, private ones beside
  their `.c` (e.g. `src/crypto/aes.h`).
- **No dependencies.** Don't add a library. Crypto, TLS, the event loop and
  the wire format are in-tree on purpose: one static binary is a headline
  promise.
- **Secrets** (TLS keys, X25519 scalars) are handled in constant time and wiped
  with `elpis_wipe()`. The DNSSEC verifiers work on public data and needn't be.
- **Never in `bin/elpis`:** signing code (`ELPIS_ED25519_SIGN`) and the TLS
  test entry points (`ELPIS_TLS_TESTING`). Test-only builds get them via
  special objects in the Makefile.

## 💬 Comments

Every file opens with what it is:

```c
/*
 * conflict.c -- identify (and, for systemd-resolved, clear) a port conflict.
 */
```

Comments explain **why**, in full sentences, often with the incident that
caused the code: a zone, a measurement, what went wrong before. Not *what* the
next line does. When you fix a bug, the comment says what used to happen.

## 🧪 Tests

- All in `tests/test_main.c`: `static void test_x(void)` with
  `section("x")`, `CHECK(cond, "fmt", ...)`, called from `main()`.
- Crypto and TLS vectors are frozen: from the RFCs, or generated once with an
  independent implementation (Python `cryptography` / OpenSSL) and checked
  before freezing. Never generate expected values with Elpis itself.
- Integration tests drive a real worker against loopback sockets
  (`test_caps_exempt`, `test_dot`); a task set to `ELPIS_TS_DEAD` lets answers
  arrive without the resolver acting on them.
- Expected stderr noise: a few `ERROR ... bad value` lines from tests that
  feed bad settings on purpose.

## 🧾 Commits

```
area: what changed, in plain words

Why: the problem, with the evidence (a zone, a number, a log line).
What: the change, and anything a reviewer would ask about.
Tested: make test count, compilers, ASan/UBSan, and any live check.

Co-Authored-By: <assistant trailer, when an assistant wrote it>
```

- **Areas** seen in history: `resolver`, `dnssec`, `server`, `ecs`, `webui`,
  `crypto`, `tls`, `docs`, `release`.
- Prose, not bullet soup. Real numbers. Say what was *not* done.
- **One concern per commit.** Each commit builds and passes on its own.
- Branches: `feat/...`, `fix/...`, `docs/...`. PRs to `main`, merged by the
  maintainer.

## 🔀 Pull requests

`## Problem` → `## Changes` (one numbered item per commit, with its hash) →
`## Testing` (counts, compilers, sanitizers, live and regression checks), and a
closing line on what is *not* done ("No tag has been made.").

## 📚 Docs

The docs are written to be read fast:

- Start each page with what it's for, in one line, then the facts.
- Tables for facts, ASCII diagrams for flows, real log lines in code blocks.
- The main point goes in plain text. The **why**, the history and the edge
  cases go in `> [!NOTE]` blocks or `<sub>small text</sub>`.
- GitHub alerts: `[!NOTE]`, `[!TIP]`, `[!IMPORTANT]`, `[!WARNING]`, `[!CAUTION]`.
- Emoji on headings. Anchors then start with `-`: `#-the-config-file`.
- Every page ends with the `<sub>` nav row.
- Settings are also documented where they live: `elpis.conf`, commented, at
  their defaults. `make` merges shipped-config changes into users' copies, so
  a new setting arrives there by itself.

## 🔖 Versions and releases

- **Semver, with one rule:** the major number changes only when a config that
  worked stops working. New features are minor, fixes are patch.
- **Releases have names** from 2.4.0 on (`CODENAME` in the `Makefile`). Ask
  the maintainer for the next one; don't invent it.
- **A release is its own commit**, `release: X.Y.Z "Name"`, touching:
  - `Makefile`: `VERSION` and `CODENAME`
  - `CHANGELOG.md`: `## Unreleased` → `## X.Y.Z "Name" — YYYY-MM-DD`, with a
    summary paragraph and "No config that worked stops working." (or what does)
  - `docs/COMPILING.md`: the tested-compilers line
- Tags and GitHub releases are made by the maintainer.
