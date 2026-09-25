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
  <img alt="Platforms" src="https://img.shields.io/badge/runs%20on-Linux%20%7C%20BSD%20%7C%20macOS-555">
  <a href="LICENSE"><img alt="Licence" src="https://img.shields.io/badge/licence-GPL--2.0-555"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="docs/COMPILING.md">Compiling</a> ·
  <a href="docs/configuration.md">Configuration</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

*Elpis* (Ελπίς) is the Greek word for hope.

## Highlights

- 🌳 **Real recursion.** It resolves from the root servers down. There is no
  upstream to trust and nothing to forward to.
- 🔐 **DNSSEC validation.** RSA, ECDSA, Ed25519, and post-quantum ML-DSA. It
  catches forged and stripped answers, even behind a forwarder.
- ⚡ **Fast.** 0.6 ms median from cache, and hand-written AVX2, SSE2 and NEON
  code chosen at runtime for the CPU it runs on.
- 📦 **One static binary with no dependencies.** The crypto, the event loop and
  the DNS wire format are all in this tree. Copy the binary and its config to
  a machine, and it runs.
- 🧠 **A cache that takes care of itself.** It sizes itself to your RAM or
  container, refreshes popular names before they expire, serves stale data
  through outages, and remembers failures.
- 🌐 **DNS64**, with an option to answer IPv6 only, for trying an IPv6-only
  network without turning IPv4 off.
- 📊 **An optional status page** with live charts, the busiest names and
  clients, and the recent log.

## How it fits

Elpis is the back half of a private DNS setup. Put **AdGuard Home** or
**Pi-hole** in front for blocklists, per-client rules and DoH, DoT and DoQ,
and point their upstream at Elpis:

```
  clients ──► AdGuard Home / Pi-hole ──► ΕΛΠΙΣ ──► root, TLD and authoritative servers
              filtering, DoH / DoT        recursion, cache, DNSSEC
```

List two or more Elpis instances as upstreams, and AdGuard spreads the load
and fails over between them. Each Elpis is happiest in its own LXC container
or VM, with its own IPv6 address: easy to firewall, easy to move, and easy to
spot in a packet capture.

## Quick start

**From source.** A C compiler and make are all it needs. See
[docs/COMPILING.md](docs/COMPILING.md) for every platform, CPU tuning and
static builds.

```bash
sudo apt install build-essential git
git clone https://github.com/PururinCollective/elpis-resolver.git
cd elpis-resolver && make
./bin/elpis                               # listens on 127.0.0.1:5335
dig @127.0.0.1 -p 5335 example.com        # in another terminal
```

**Pre-built.** Grab the static binary from [Releases](../../releases). It runs
on any recent Linux with nothing to install:

```bash
sudo mkdir -p /opt/elpis-resolver/bin
sudo cp elpis elpis.conf /opt/elpis-resolver/bin/
/opt/elpis-resolver/bin/elpis -t          # check the config and exit
```

`sudo make install` puts a source build in the same place. A systemd unit is
in [contrib/elpis.service](contrib/elpis.service); it binds port 53 without
running as root.

## Configure

The config lives beside the binary (`bin/elpis.conf`, or
`/opt/elpis-resolver/bin/elpis.conf` once installed). Every setting is
documented there at its default. A minimal setup behind AdGuard:

```
listen: [2402:4e20::1111]@53
access-control: 2402:4e20::/48 allow
dnssec: yes
```

Then set AdGuard Home's upstream to `[2402:4e20::1111]:53`.

## Performance

Measured for 2.0 across 28 groups of popular services (Google, YouTube,
Steam, Epic, Telegram, Microsoft and Windows Update, Apple, Discord, GitHub,
Shopee, Taobao, Malaysian banks and more): 1,221 lookups, with every host
asked A, AAAA and HTTPS at once, as a browser asks.

| | median | 90th percentile | 99th percentile |
|---|---|---|---|
| **Elpis, answered from cache** | **0.6 ms** | **1.1 ms** | **1.5 ms** |
| Elpis, cold cache (full recursion) | 82 ms | 269 ms | 709 ms |
| 1.1.1.1, from the same machine | 4.2 ms | 15.5 ms | 170 ms |

Elpis's answers matched 1.1.1.1's on 1,218 of the 1,221 lookups. Of the other
three, two were CDNs answering differently for a different location, and one
was a name that 1.1.1.1 failed to resolve.

## Hardware

- **CPU:** any 64-bit x86 or ARM, or anything else with a C99 compiler. AVX2
  is used when the CPU has it.
- **Memory:** the cache takes about a fifth of what the machine or container
  may use:

  | RAM | cache | names held |
  |---|---|---|
  | 1 GB | 171 MiB | ~340,000 |
  | 2 GB | 410 MiB | ~830,000 |
  | **4 GB** | **819 MiB** | **~1,600,000** |
  | 8 GB | 2 GiB | ~4,100,000 |

  A home or office network fits in a 4 GB container many times over.

## Status page

Optional and read-only. Two lines switch it on:

```
webgui: yes
webgui-password: choose-something
```

It shows the cache hit rate, response times, CPU and memory, the busiest names
and clients, upstream servers that have gone quiet, and the recent log, in
draggable windows with light and dark themes. It binds to loopback; reach it
over an SSH tunnel, a VPN, or your own TLS reverse proxy. See
[docs/status-page.md](docs/status-page.md).

## Documentation

| | |
|---|---|
| [Compiling](docs/COMPILING.md) | building on every platform, CPU tuning, static and cross builds |
| [Configuration](docs/configuration.md) | every setting, privileged ports, signals, the identity probe |
| [Caching](docs/caching.md) | the caches, background refresh, what happens when a refresh fails, warming after a restart |
| [Mesh](docs/mesh.md) | instances you run warming each other after a restart, without a disk |
| [DNSSEC](docs/dnssec.md) | validation, the algorithms, cookies, the standards followed |
| [Status page](docs/status-page.md) | the web interface and how to reach it safely |
| [Troubleshooting](docs/troubleshooting.md) | answers not coming back, port conflicts, malformed input |
| [Internals](docs/internals.md) | why the hot paths look the way they do |
| [Licensing](docs/licensing.md) | signed deployment licences |
| [Changelog](CHANGELOG.md) | what changed in each release |

## Not here

- **DoH, DoT and DoQ.** Elpis speaks UDP and TCP. AdGuard or Pi-hole in front
  handles the encrypted transports.
- **Authoritative service.** No zone files, dynamic updates or TSIG. Elpis
  resolves; it does not serve zones.

## Commercial support

Commercial support is available: deployment, tuning for your traffic mix,
integration work, and prioritised fixes.

<!-- TODO: add the contact address you want people to use. -->

## Licence

GPL-2.0. See [LICENSE](LICENSE).
