<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/logo-dark.svg">
    <img alt="ΕΛΠΙΣ Resolver" src="docs/images/logo-light.svg" width="420">
  </picture>
</p>

<p align="center">
  <b>A private, validating, recursive DNS resolver, in portable C99.</b><br>
  It asks the root, the TLDs and the authoritative servers itself,<br>
  so your lookups stay between you and the servers that hold the answers.
</p>

<p align="center">
  <a href="../../releases"><img alt="Release" src="https://img.shields.io/github/v/release/PururinCollective/elpis-resolver?color=2f9ee0&label=release"></a>
  <img alt="C99" src="https://img.shields.io/badge/C-C99-2f9ee0">
  <img alt="DNSSEC" src="https://img.shields.io/badge/DNSSEC-validating-2ea44f">
  <img alt="ADoT" src="https://img.shields.io/badge/ADoT-opportunistic-2ea44f">
  <img alt="Platforms" src="https://img.shields.io/badge/runs%20on-Linux%20%7C%20BSD%20%7C%20macOS-555">
  <a href="LICENSE"><img alt="Licence" src="https://img.shields.io/badge/licence-GPL--2.0-555"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick start</a> ·
  <a href="docs/COMPILING.md">Compiling</a> ·
  <a href="docs/configuration.md">Configuration</a> ·
  <a href="#-documentation">Documentation</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

> *Elpis* (Ελπίς) is the Greek word for **hope**.

## 🧭 Where it sits

Elpis is the back half of a private DNS setup. Something friendly sits in
front for your devices; Elpis does the real work behind it.

```
          📱 💻 📺   your devices
              │
              │   DoH · DoT · DoQ · plain DNS
              ▼
 ┌──────────────────────────┐
 │  AdGuard Home / Pi-hole  │   blocklists · per-client rules
 └────────────┬─────────────┘
              │   plain DNS, over your LAN or VPN
              ▼
 ┌──────────────────────────┐
 │      ΕΛΠΙΣ  ·  Elpis     │   recursion · DNSSEC · cache
 └────────────┬─────────────┘
              │   DoT where the server offers it, plain DNS where not
              ▼
       .   ──►   com.   ──►   example.com.
     root        TLD          authoritative
```

There is no upstream resolver in this picture. Nobody but the servers that
hold the answers ever sees what you look up.

## ✨ What you get

| | |
|---|---|
| 🌳 **Real recursion** | Resolves from the root servers down. No upstream to trust, nothing to forward to. |
| 🔐 **DNSSEC validation** | RSA, ECDSA, Ed25519 and post-quantum ML-DSA. Forged and stripped answers are refused, even behind a forwarder. |
| 🔒 **DoT to authoritative servers** | What it asks the root, the TLDs and the authorities goes encrypted wherever they offer DNS over TLS ([RFC 9539](docs/configuration.md#-dns-over-tls-to-authoritative-servers)). |
| ⚡ **Fast** | 0.6 ms median from cache. Hand-written AVX2, SSE2 and NEON code, picked at runtime for the CPU it runs on. |
| 📦 **One static binary** | No dependencies. The crypto, the TLS client, the event loop and the DNS wire format are all in this tree. Copy the binary and its config, and it runs. |
| 🧠 **A cache that looks after itself** | Sizes itself to your RAM or container, refreshes popular names before they expire, serves stale data through outages, remembers failures. |
| 🌐 **DNS64** | With an IPv6-only answer mode, for trying an IPv6-only network without turning IPv4 off. |
| 📊 **Status page** | Optional and read-only: live charts, the busiest names and clients, DoT servers, the recent log. |

## 🔎 One query, start to finish

```
 client asks  www.example.com  A
       │
       ▼
 ┌────────────┐   hit    ┌─────────────────────────────────┐
 │   cache    │────────► │  answered in about 0.6 ms       │
 └─────┬──────┘          └─────────────────────────────────┘
       │ miss
       ▼
 ┌─────────────────────────────────────────────────────────┐
 │  start as deep as the cache already knows (. com. ...)  │
 │  ask the best server of that zone:                      │
 │    · over DoT if it speaks DoT, plain DNS if not        │
 │    · random ID and port, 0x20 case, DNS cookies         │
 │  follow referrals and CNAMEs down to the answer         │
 └────────────────────────────┬────────────────────────────┘
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │  DNSSEC: every signature checked back to the root key   │
 │  bogus → SERVFAIL with the reason, never the bad data   │
 └────────────────────────────┬────────────────────────────┘
                              ▼
               cached, and sent to the client
```

## 🚀 Quick start

### From source

A C compiler and make are all it needs.

```bash
sudo apt install build-essential git
git clone https://github.com/PururinCollective/elpis-resolver.git
cd elpis-resolver && make
./bin/elpis                               # listens on 127.0.0.1:5335
dig @127.0.0.1 -p 5335 example.com        # in another terminal
```

<sub>Every platform, CPU tuning and static builds: [docs/COMPILING.md](docs/COMPILING.md)</sub>

### Pre-built

Grab the static binary from [Releases](../../releases). It runs on any recent
Linux with nothing to install.

```bash
sudo mkdir -p /opt/elpis-resolver/bin
sudo cp elpis elpis.conf /opt/elpis-resolver/bin/
/opt/elpis-resolver/bin/elpis -t          # check the config and exit
```

> [!TIP]
> `sudo make install` puts a source build in the same place. The systemd unit
> in [contrib/elpis.service](contrib/elpis.service) binds port 53 without
> running as root. For a git clone (in `/opt/elpis-resolver`, recommended),
> [contrib/elpis-install.sh](contrib/elpis-install.sh) installs it with the
> `elpis` account, and with `RESOLVED=replace` puts Elpis on `127.0.0.53` in
> systemd-resolved's place:
> [details](docs/configuration.md#taking-systemd-resolveds-place-on-127053).

## 🔧 Configure

The config sits beside the binary: `bin/elpis.conf`, or
`/opt/elpis-resolver/bin/elpis.conf` once installed. Every setting is in there
at its default, with a comment saying what it does.

A minimal setup behind AdGuard Home:

```
listen: [2402:4e20::1111]@53
access-control: 2402:4e20::/48 allow
dnssec: yes
authoritative-dot: opportunistic       # optional: encrypt to servers that allow it
```

Then set AdGuard Home's upstream to `[2402:4e20::1111]:53`.

> [!TIP]
> - List **two or more Elpis instances** as upstreams, and AdGuard spreads the
>   load and fails over between them.
> - Instances in different places? Turn on
>   [EDNS Client Subnet](docs/configuration.md#-edns-client-subnet) (`ecs: yes`),
>   so a content network answers for where your clients are, not for whichever
>   Elpis they happened to ask.
> - Each Elpis is happiest in its own LXC container or VM with its own IPv6
>   address: easy to firewall, easy to move, easy to spot in a packet capture.

## ⚡ Performance

Measured for 2.0 across 28 groups of popular services (Google, YouTube, Steam,
Epic, Telegram, Microsoft and Windows Update, Apple, Discord, GitHub, Shopee,
Taobao, Malaysian banks and more): 1,221 lookups, every host asked A, AAAA and
HTTPS at once, the way a browser asks.

| | median | 90th percentile | 99th percentile |
|---|---|---|---|
| **Elpis, answered from cache** | **0.6 ms** | **1.1 ms** | **1.5 ms** |
| Elpis, cold cache (full recursion) | 82 ms | 269 ms | 709 ms |
| 1.1.1.1, from the same machine | 4.2 ms | 15.5 ms | 170 ms |

<sub>Elpis matched 1.1.1.1 on 1,218 of the 1,221 lookups. Of the other three,
two were CDNs answering differently for a different location, and one was a
name 1.1.1.1 failed to resolve.</sub>

## 💻 Hardware

- **CPU:** any 64-bit x86 or ARM, or anything else with a C99 compiler. AVX2
  is used when the CPU has it, AES-NI for DoT where there is one.
- **Memory:** the cache takes about a fifth of what the machine or container
  may use.

| RAM | cache | names held |
|---|---|---|
| 1 GB | 171 MiB | ~340,000 |
| 2 GB | 410 MiB | ~830,000 |
| **4 GB** | **819 MiB** | **~1,600,000** |
| 8 GB | 2 GiB | ~4,100,000 |

<sub>A home or office network fits in a 4 GB container many times over.</sub>

## 📊 Status page

Optional and read-only. Two lines switch it on:

```
webgui: yes
webgui-password: choose-something
```

Cache hit rate, response times, CPU and memory, the busiest names and clients,
servers that went quiet, DoT servers and the recent log, in draggable windows
with light and dark themes.

> [!NOTE]
> It binds to loopback. Reach it over an SSH tunnel, a VPN, or your own TLS
> reverse proxy. See [docs/status-page.md](docs/status-page.md).

## 📚 Documentation

| | |
|---|---|
| 🔨 [Compiling](docs/COMPILING.md) | building on every platform, CPU tuning, static and cross builds |
| 🔧 [Configuration](docs/configuration.md) | settings, privileged ports, ECS, DoT, the identity probe, signals |
| 🧠 [Caching](docs/caching.md) | the caches, background refresh, what happens when a refresh fails |
| 🔐 [DNSSEC](docs/dnssec.md) | validation, the algorithms, post-quantum, cookies, standards |
| 📊 [Status page](docs/status-page.md) | the web interface and how to reach it safely |
| 🩺 [Troubleshooting](docs/troubleshooting.md) | answers not coming back, dead servers, bogus answers, port conflicts |
| 🧩 [Quirks](docs/quirks.md) | zones whose servers drop or dodge some query types |
| 🔩 [Internals](docs/internals.md) | why the hot paths look the way they do |
| 🔏 [Licensing](docs/licensing.md) | signed deployment licences |
| 📝 [Changelog](CHANGELOG.md) | what changed in each release |

## 🚫 Not here

- **DoH, DoT and DoQ for your clients.** Elpis answers over UDP and TCP.
  AdGuard Home or Pi-hole in front handles the encrypted transports.
  <br><sub>Elpis does speak DoT itself, outbound, to authoritative servers.</sub>
- **Authoritative service.** No zone files, dynamic updates or TSIG. Elpis
  resolves; it does not serve zones.

## 🤖 For AI assistants

Start with [AGENTS.md](AGENTS.md): the licence, the credit and the identity
probe come with rules. Then [agent/](agent/README.md) has a map of the code,
the conventions, how to check a change, and what was decided and why.

## 💼 Commercial support

Commercial support is available: deployment, tuning for your traffic mix,
integration work, and prioritised fixes.

<!-- TODO: add the contact address you want people to use. -->

## Licence

GPL-2.0. See [LICENSE](LICENSE).
