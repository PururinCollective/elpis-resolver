# Compiling Elpis

Everything about building Elpis from source: what you need, the make targets
and variables, tuning for your CPU, static and cross builds, and the tools for
working on the code.

- [What you need](#what-you-need)
- [Building](#building)
- [Make targets](#make-targets)
- [Build variables](#build-variables)
- [Tuning for your CPU](#tuning-for-your-cpu)
- [SIMD kernels](#simd-kernels)
- [Static builds](#static-builds)
- [Cross-compiling](#cross-compiling)
- [What a binary says about itself](#what-a-binary-says-about-itself)
- [Installing](#installing)
- [Working on Elpis](#working-on-elpis)
- [When the build goes wrong](#when-the-build-goes-wrong)

## What you need

A C99 compiler, **GNU make** and the C library headers. That is all. The
cryptography, the event loop and the DNS wire format are in this tree, and the
binary links nothing but libc.

| System | Command |
|---|---|
| Debian, Ubuntu | `sudo apt install build-essential git` |
| Fedora, RHEL, Rocky, Alma | `sudo dnf install gcc make git` |
| Arch, Manjaro | `sudo pacman -S base-devel git` |
| Alpine | `apk add build-base git` |
| openSUSE | `sudo zypper install gcc make git` |
| FreeBSD | `pkg install gmake git`, then build with `gmake` |
| macOS | `xcode-select --install` |

Two tools are optional:

- **git** is only needed to clone the tree and to stamp the release or commit
  into the binary. A tarball builds without it, and the binary then reports
  `no git checkout`.
- **python3** regenerates the status page from `web/index.html` when you edit
  it. Without python3 the committed copy in `src/webui_assets.h` is used, and
  the build says so.

Linux builds with gcc and clang are tested for each release: gcc 13.3 and
clang 18.1 for 2.0.1. The BSDs (kqueue) and macOS (kqueue) are supported by
the code, but no build on them was tested for this release.

## Building

```bash
git clone https://github.com/PururinCollective/elpis-resolver.git
cd elpis-resolver
make
./bin/elpis            # 127.0.0.1:5335, with the config beside it
```

Everything the build produces goes in `bin/`, which git ignores, so
`git pull && make` never leaves anything behind for git to notice.

`bin/` is a complete bundle: the binary, plus `bin/elpis.conf` seeded from the
shipped defaults the first time you build. Copy the directory to another
machine and it runs. The config is seeded once and never touched again, so
your edits survive every rebuild and `make clean`. `elpis.conf` in the source
tree stays the untouched reference.

Changing compiler flags needs no `make clean`. The flags are kept in a stamp
file that every object depends on, so a changed `OPT` or `CFLAGS` recompiles
everything, and repeating a build with the same flags compiles nothing.

## Make targets

| Target | What it does |
|---|---|
| `make` | Ordinary build: `bin/elpis` and `bin/elpis.conf` |
| `make static` | One statically linked binary with no shared libraries (runs `make clean` first) |
| `make test` | The self-tests: 376 of them, no network needed |
| `make debug` | `-O0 -g3` with debug assertions |
| `make asan` | AddressSanitizer and UndefinedBehaviorSanitizer build |
| `make fuzz` | libFuzzer harness for the message parser, `bin/fuzz-msg` (needs clang) |
| `make licence-tool` | `bin/elpis-licence`, which signs deployment licences (see [licensing](licensing.md)) |
| `make install` | Install to `/opt/elpis-resolver/bin` (see [Installing](#installing)) |
| `make uninstall` | Remove the binary and leave your config alone |
| `make clean` | Objects and binaries. Keeps `bin/elpis.conf` |
| `make distclean` | `bin/` and everything in it |

`debug`, `asan` and `static` run `make clean` first, because they change what
every object is compiled with.

## Build variables

Pass these on the make command line, for example `make OPT="-O2"`.

| Variable | Default | Meaning |
|---|---|---|
| `CC` | `cc` | The compiler: `gcc`, `clang`, or a cross compiler |
| `OPT` | `-O3 -fno-strict-aliasing -fomit-frame-pointer` | Optimisation and target flags for the whole build |
| `CFLAGS` | `$(OPT)` | Replaces `OPT` entirely if you set it |
| `LDFLAGS` | empty | Extra linker flags |
| `STATIC_OPT` | `$(OPT)` | `OPT` for `make static`, if it should differ |
| `PREFIX` | `/opt/elpis-resolver` | Install location |
| `DESTDIR` | empty | Staging root for packaging |
| `SYSCONFDIR` | `/etc` | Where the binary looks for a config after its own directory |
| `UNAME_M` | `uname -m` | The target architecture; set it when cross-compiling |
| `FUZZ_CC` | `clang` | The compiler for `make fuzz` |
| `LICENCE_ISSUER` | built in | Ed25519 public key that licences are checked against |

Keep `-fno-strict-aliasing` when you replace `OPT`. It is in the default,
and it is what the code is built and tested with.

## Tuning for your CPU

The default build targets the generic baseline of its architecture, so the
binary runs on any CPU of that kind. To get the last few percent, compile for
the CPU the resolver runs on:

```bash
make OPT="-O3 -fno-strict-aliasing -march=znver3 -mtune=znver3"
```

### x86-64

The simplest choice is a microarchitecture level, which covers a whole
generation of CPUs from both vendors:

| Level | Adds | Runs on |
|---|---|---|
| `x86-64` (default) | SSE2 | every 64-bit x86 CPU |
| `-march=x86-64-v2` | SSE4.2, POPCNT | Intel Nehalem (2008) and later, AMD Bulldozer and later |
| `-march=x86-64-v3` | AVX2, BMI2, FMA | Intel Haswell (2013) and later, AMD Zen and later |
| `-march=x86-64-v4` | AVX-512 | Intel Skylake-SP and later server CPUs, AMD Zen 4 and later |

Or name the CPU exactly:

| CPU | Flags |
|---|---|
| AMD Zen 2 (Ryzen 3000, EPYC Rome) | `-march=znver2 -mtune=znver2` |
| AMD Zen 3 (Ryzen 5000, EPYC Milan) | `-march=znver3 -mtune=znver3` |
| AMD Zen 4 (Ryzen 7000, EPYC Genoa) | `-march=znver4 -mtune=znver4` |
| Intel Skylake / Cascade Lake servers | `-march=skylake-avx512` |
| Intel Ice Lake servers | `-march=icelake-server` |
| Intel Alder Lake and Raptor Lake | `-march=alderlake -mtune=alderlake` |
| Intel Sapphire Rapids | `-march=sapphirerapids` |
| The machine you are building on | `-march=native -mtune=native` |

A binary built with `-march` needs that CPU or a newer one: on an older CPU it
dies with "Illegal instruction", usually before it prints anything. Use
`-march=native` only when you build on the machine that will run it. For a
fleet of mixed hardware, the lowest `x86-64-vN` they all support is the safe
choice.

### ARM64

On ARM, `-mcpu` sets the architecture and the tuning together:

| CPU | Flags |
|---|---|
| Raspberry Pi 4 (Cortex-A72) | `-mcpu=cortex-a72` |
| Raspberry Pi 5 (Cortex-A76) | `-mcpu=cortex-a76` |
| AWS Graviton2, Ampere Altra (Neoverse N1) | `-mcpu=neoverse-n1` |
| AWS Graviton3 (Neoverse V1) | `-mcpu=neoverse-v1` |
| The machine you are building on | `-mcpu=native` |

### Other architectures

Anything with a C99 compiler and POSIX builds: RISC-V, POWER, and others use
the scalar code paths, and 32-bit ARM uses NEON (see below). RISC-V boards
typically want `-march=rv64gc`.

## SIMD kernels

The hot paths (cache lookups, name comparison, case folding) have hand-written
vector kernels:

| Architecture | Kernels |
|---|---|
| x86-64 | SSE2 and AVX2 |
| ARM64 | NEON |
| 32-bit ARM | NEON, where the compiler targets an FPU that has it |
| everything else | scalar |

**On x86-64 the kernel is chosen at runtime.** Each kernel file is compiled
with its own instruction-set flags (the AVX2 file with `-mavx2 -mbmi
-mbmi2`), and the CPU is asked at startup what it supports. So a generic
build still uses AVX2 on a CPU that has it, and still runs on one that does
not. `-march` does not change which kernel runs; it changes how the compiler
builds everything else.

The self-tests check that every vector path agrees with the scalar one, byte
for byte. The kernels differ only in speed.

## Static builds

```bash
make static
make static OPT="-O3 -fno-strict-aliasing -march=x86-64-v3"
```

This gives one self-contained binary with no shared libraries, about 1.4 MB
with glibc on x86-64. Copy it to any Linux of the same architecture and run
it. Elpis never uses the system's name lookup (`getaddrinfo`, NSS), so the
usual glibc warnings about static linking do not apply. `make static` strips
the binary afterwards.

On Alpine, the same command builds against musl, which usually gives a
smaller static binary.

## Cross-compiling

The Makefile picks the SIMD kernels from `UNAME_M`, which defaults to the
architecture of the machine you build on. When cross-compiling, set it to the
target, along with the cross compiler:

```bash
# Debian/Ubuntu: sudo apt install gcc-aarch64-linux-gnu
make CC=aarch64-linux-gnu-gcc UNAME_M=aarch64
make static CC=aarch64-linux-gnu-gcc UNAME_M=aarch64 \
     OPT="-O3 -fno-strict-aliasing -mcpu=cortex-a76"
```

| Target | `CC` | `UNAME_M` |
|---|---|---|
| ARM64 | `aarch64-linux-gnu-gcc` | `aarch64` |
| 32-bit ARM | `arm-linux-gnueabihf-gcc` | `armv7l` |
| RISC-V 64 | `riscv64-linux-gnu-gcc` | `riscv64` |

`make test` builds a binary for the target, so it cannot run on the build
machine. Run `bin/elpis-test` on the target, or under `qemu-user`.

A dry run confirms that the Makefile switches to the NEON kernels for
`UNAME_M=aarch64`. No cross build was run for this release.

## What a binary says about itself

The startup line names the compiler, the architecture, the CPU the build was
tuned for, and the SIMD kernel in use:

```
elpis 2.0.1 starting: avx2 kernels (cpu: sse2 ssse3 sse4.1 avx2 bmi2), epoll,
              gcc 13.3.0, x86_64 znver3 (native), ...
```

The tuning shows as `generic` when no `-march` was given, as `x86-64-v3` or
`znver3` when one was, and as `znver3 (native)` for `-march=native`. The
About window and the CPU pane of the status page show the same.

The **build** string shows where the binary came from:

| Built from | Build string |
|---|---|
| a release tag | `v2.0.1` |
| any other commit | `main@bcc97d252fac` (branch and commit) |
| a tarball, no git | empty, and the status page says `no git checkout` |

It appears in the About window, the status JSON, and the identity TXT record:

```bash
dig @127.0.0.1 -p 5335 elpis.sakurako.oomuro TXT
```

## Installing

```bash
sudo make install            # -> /opt/elpis-resolver/bin/{elpis,elpis.conf}
sudo make uninstall          # removes the binary, keeps your config
```

`/opt` keeps Elpis clear of anything the distribution manages, and the
installed layout has the same shape as `bin/`, so the config is found the same
way in both. An existing config is never overwritten. Use
`make install PREFIX=/usr/local` for a different location, and `DESTDIR=` for
a packaging staging root.

A systemd unit is in [contrib/elpis.service](../contrib/elpis.service). It
expects the `/opt` path and binds port 53 with `CAP_NET_BIND_SERVICE` rather
than running as root.

## Working on Elpis

Four more tools come in when you work on the code rather than run it. None of
them is needed to build or run Elpis:

```bash
sudo apt install valgrind cppcheck clang
```

| Tool | Used for |
|---|---|
| `clang` | `make fuzz`, and a second compiler's warnings (`make CC=clang`) |
| `valgrind` | memory errors and leaks in a running resolver |
| `cppcheck` | static analysis |
| `make asan` | memory errors and leaks, faster than valgrind |

```bash
make test                                             # always, before a commit
make asan && bin/elpis -c bin/elpis.conf              # Ctrl-C for the leak report
valgrind --leak-check=full bin/elpis -c bin/elpis.conf
cppcheck --enable=warning,portability -q -Iinclude -Isrc src src/crypto
make fuzz && mkdir -p bin/corpus && cd bin && ./fuzz-msg -max_total_time=300 corpus/
```

For readable valgrind stacks, build with `make OPT="-O1 -g -fno-strict-aliasing
-fno-omit-frame-pointer"`. The code builds without warnings under gcc and
clang at the warning level the Makefile sets, and should stay that way.

## When the build goes wrong

| Symptom | Cause |
|---|---|
| Errors about `ifneq`, or `missing separator` | Not GNU make, as on the BSDs. Use `gmake`. |
| `python3 not found: keeping the committed src/webui_assets.h` | Not an error. Install python3 only if you edit `web/index.html`. |
| The binary stops with "Illegal instruction" | Built with `-march` for a newer CPU than this one. Rebuild with a lower level or no `-march`. |
| The startup line says `generic` after you changed `OPT` | `CFLAGS` was also set, and it overrides `OPT`. Unset it. |
| `make fuzz` fails | Needs clang with libFuzzer (`sudo apt install clang`). |
