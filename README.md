# ΕΛΠΙΣ Resolver

A recursive DNS resolver in portable C99, for people who would rather not send
every lookup to Google or Cloudflare.

It does the recursion itself — root servers, TLDs, authoritative servers — so
your queries stay between you and the servers that actually hold the answers.
No external dependencies: the crypto, the event loop and the wire format are
all in this tree, so it builds into one static binary you copy to a machine
and run.

```
$ make && ./bin/elpis -d
elpis 1.0.0 starting: avx2 kernels (cpu: sse2 ssse3 sse4.1 avx2 bmi2), epoll,
              4096 MiB RAM detected, cache budget 819 MiB
msg-cache: 32 shards, budget 409 MiB
rrset-cache: 32 shards, budget 262 MiB
listening with 4 workers
```

## What it is for

Elpis is the back half of a private DNS setup. It is **not** a public-facing
server and it does not speak DoH, DoT or DoQ — AdGuard Home and Pi-hole
already do that well, so put one of them in front and let Elpis do what it is
good at.

```
                     ┌────────────────┐
                 ┌───┤ ΕΛΠΙΣ Resolver │  2402:4e20::1001
                 │   └────────────────┘
   ┌─────────┐   │   ┌────────────────┐
   │ AdGuard ├───┼───┤ ΕΛΠΙΣ Resolver │  2402:4e20::1111
   └─────────┘   │   └────────────────┘
                 │   ┌────────────────┐
                 └───┤ ΕΛΠΙΣ Resolver │  2402:4e20:b00b::1234
                     └────────────────┘

   public face,            recursion, caching, DNSSEC,
   DoH / DoT / DoQ,        straight to the root and TLD servers
   filtering, logging
```

AdGuard faces the network and handles the encrypted transports, the blocklists
and the per-client rules. Elpis sits behind it, resolves from the root, and
answers from cache. Point AdGuard's upstream at the Elpis addresses; list
several and it will spread load and fail over between them.

**Run each Elpis in its own LXC container or VM**, isolated from whatever else
the host does, and give it **its own IPv6 address**. A resolver with an address
of its own is easy to firewall, easy to move, and easy to pick out of a packet
capture when something is wrong. Nothing stops you running it on loopback next
to AdGuard — it just gives up the isolation.

## Install

### Pre-built binary

Grab the latest static binary from [Releases](../../releases). It has no
shared-library dependencies, so it runs on any reasonably recent Linux without
installing anything:

```bash
sudo mkdir -p /opt/elpis-resolver/bin
sudo cp elpis elpis.conf /opt/elpis-resolver/bin/
sudo chmod +x /opt/elpis-resolver/bin/elpis
/opt/elpis-resolver/bin/elpis -t        # check the config and exit
```

The binary reads the `elpis.conf` sitting beside it, so those two files are the
whole installation. Without a config it still runs, on `127.0.0.1:5335` with
built-in defaults.

### Building it yourself

The release binary is built for portability — a generic `x86-64` baseline that
runs anywhere. If you want the last few percent, compile for your own CPU:

```bash
make static OPT="-O3 -fno-strict-aliasing -march=znver3 -mtune=znver3"
```

`OPT` replaces the optimisation flags for the whole build, static included.
Pick the one that matches your processor:

| CPU | flags |
|---|---|
| AMD Zen 3 (Ryzen 5000, EPYC Milan) | `-march=znver3 -mtune=znver3` |
| AMD Zen 4 (Ryzen 7000, EPYC Genoa) | `-march=znver4 -mtune=znver4` |
| Intel Alder Lake and later | `-march=alderlake -mtune=alderlake` |
| Intel Skylake / Cascade Lake | `-march=skylake-avx512` |
| whatever this machine is | `-march=native -mtune=native` |

Use `-march=native` only when you build on the same machine you run on — the
binary will not start on an older CPU.

```bash
make            # ordinary build      -> bin/elpis + bin/elpis.conf
make static     # one relocatable binary, no shared libraries
make test       # 242 self tests, no network needed
make debug      # -O0 -g3
make asan       # address and UB sanitizers
make clean      # objects and binaries; keeps your bin/elpis.conf
make distclean  # bin/ and everything in it
```

Everything the build produces goes in `bin/`, which is in `.gitignore`, so
`git pull && make clean && make` never leaves anything behind for git to
notice.

`bin/` is a complete bundle — the binary plus a config seeded from the shipped
defaults — so you can copy the directory to another machine and run it. The
seeding happens once: your edits to `bin/elpis.conf` survive every rebuild and
`make clean`, and the copy in the source tree stays the untouched reference.

### Installing it

```bash
sudo make install          # -> /opt/elpis-resolver/bin/{elpis,elpis.conf}
```

`/opt` keeps it clear of anything the distribution manages, which is what you
want for a program that ships as one binary and one file beside it. The
installed layout is the same shape as `bin/`, so the config is found the same
way in both. An existing config is never overwritten, and `make uninstall`
leaves it alone. `PREFIX=/usr/local make install` if you would rather.

A systemd unit is in [contrib/elpis.service](contrib/elpis.service); it expects
exactly this path and binds port 53 with `CAP_NET_BIND_SERVICE` instead of
running as root.

Strict C99 plus POSIX.1-2008. epoll on Linux, kqueue on the BSDs and macOS,
poll everywhere else.

## Hardware

**CPU.** The hot paths — cache lookup, name comparison, case folding — have
hand-written SIMD kernels chosen at runtime from CPUID. **x86-64 with AVX2 is
recommended**; SSE2 and ARM NEON kernels are there too, and a scalar fallback
covers everything else. The test suite checks that every vector path agrees
with the scalar one byte for byte, so the only difference is speed.

Startup says which it picked, and what the CPU offered:

```
elpis 1.0.0 starting: avx2 kernels (cpu: sse2 ssse3 sse4.1 avx2 bmi2), epoll, ...
```

**Memory.** The cache sizes itself from host RAM — a fifth of it on a typical
box, read from the cgroup limit when containerised. On **4 GB**, with a stock
Ubuntu Server using about 800 MB, Elpis takes roughly **820 MB of cache and
holds about 1.6 million names**, leaving well over 2 GB free.

| RAM | cache budget | names held |
|---|---|---|
| 1 GB | 171 MiB | ~340,000 |
| 2 GB | 410 MiB | ~830,000 |
| **4 GB** | **819 MiB** | **~1,600,000** |
| 8 GB | 2 GiB | ~4,100,000 |
| 16 GB | 4 GiB | ~8,300,000 |

Measured rather than estimated: a 64 MiB message cache held 258,047 entries
before it began evicting, with four A records per name. Names carrying more —
IPv6 plus HTTPS records plus DNSSEC signatures — cost more, so treat these as
an upper bound for a typical browsing mix. `cache-size: 2G` overrides the lot
if you would rather say it yourself.

At 1.6 million names, a home or small-office name set fits many times over, so
a 4 GB container spends its time answering from cache rather than evicting.

## Configure

`make` puts a config beside the binary at `bin/elpis.conf`, seeded from the
shipped defaults, and that is the one it reads. (Failing that it looks one
directory up, then in `/etc/elpis/`, then `/etc/`.) A minimal config for the
setup above:

```
listen: [2402:4e20::1111]@53
access-control: 2402:4e20::/48 allow

cache-size: auto
dnssec: yes
prefetch: yes
```

Then point AdGuard Home's upstream at `[2402:4e20::1111]:53`. The shipped
[elpis.conf](elpis.conf) documents every setting at its default value.

## Documentation

| | |
|---|---|
| [Caching](docs/caching.md) | the three caches, background refresh, what happens when a refresh fails, delegation reuse |
| [DNSSEC](docs/dnssec.md) | validation, RSA / ECDSA / Ed25519 / ML-DSA-44, cookies, standards |
| [Configuration](docs/configuration.md) | every setting, privileged ports, binding, signals |
| [Troubleshooting](docs/troubleshooting.md) | queries arriving but answers not coming back, port conflicts, malformed input |
| [Internals](docs/internals.md) | why the hot paths look the way they do, and what is deliberately missing |

## Not here

DoH, DoT and DoQ — Elpis speaks UDP and TCP, and the thing in front of it
terminates the encrypted transports.

Authoritative service, zone files, dynamic update, TSIG signing. This
resolves; it does not serve.

## Commercial support

Commercial support is available: deployment, tuning for your traffic mix,
integration work, and prioritised fixes.

<!-- TODO: add the contact address you want people to use. -->

## Licence

See [LICENSE](LICENSE).
