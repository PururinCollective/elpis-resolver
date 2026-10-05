# 🔨 Compiling Elpis

Build it, tune it for your CPU, make one static binary, or cross-compile it.

**On this page:**
[What you need](#-what-you-need) ·
[Building](#-building) ·
[Make targets](#-make-targets) ·
[Build variables](#-build-variables) ·
[Tuning for your CPU](#-tuning-for-your-cpu) ·
[SIMD kernels](#-simd-kernels) ·
[Static builds](#-static-builds) ·
[Cross-compiling](#-cross-compiling) ·
[What a binary says](#-what-a-binary-says-about-itself) ·
[Installing](#-installing) ·
[Working on Elpis](#-working-on-elpis) ·
[When the build goes wrong](#-when-the-build-goes-wrong)

## 📦 What you need

A C99 compiler, **GNU make** and the C library headers. That's all.

| System | Command |
|---|---|
| Debian, Ubuntu | `sudo apt install build-essential git` |
| Fedora, RHEL, Rocky, Alma | `sudo dnf install gcc make git` |
| Arch, Manjaro | `sudo pacman -S base-devel git` |
| Alpine | `apk add build-base git` |
| openSUSE | `sudo zypper install gcc make git` |
| FreeBSD | `pkg install gmake git`, then build with `gmake` |
| macOS | `xcode-select --install` |

<sub>The cryptography, the TLS client, the event loop and the DNS wire format
are all in this tree. The binary links nothing but libc.</sub>

**Optional:**
- **git** — to clone, and to stamp the release or commit into the binary.
  <br><sub>A tarball builds without it; the binary then reports `no git checkout`.</sub>
- **python3** — regenerates the status page from `web/index.html` when you
  edit it.
  <br><sub>Without it the committed `src/webui/webui_assets.h` is used, and the build says so.</sub>

> [!NOTE]
> Tested for each release on Linux with gcc and clang: gcc 13.3 and clang 18.1
> for 2.4.2. The BSDs and macOS (kqueue) are supported by the code, but no
> build on them was tested for this release.

## 🧱 Building

```bash
git clone https://github.com/PururinCollective/elpis-resolver.git
cd elpis-resolver
make
./bin/elpis            # 127.0.0.1:5335, with the config beside it
```

Everything lands in `bin/`, which git ignores:

```
bin/
├── elpis                  the resolver
├── elpis.conf             your config, seeded from the shipped one on the first build
└── elpis.conf.shipped     the defaults your config was last merged with
```

- **`bin/` is a complete bundle.** Copy the directory to another machine and it runs.
- **Your config is yours.** Edits survive every rebuild and `make clean`.
- **New shipped defaults are merged in.** When a pull changes `elpis.conf`,
  `make` merges the change into `bin/elpis.conf` and keeps your edits.
  <br><sub>Where the two clash it changes nothing and warns you — see
  [when the shipped defaults change](configuration.md#when-the-shipped-defaults-change).
  `elpis.conf` in the source tree stays the reference.</sub>
- **No `make clean` after changing flags.** A stamp file every object depends
  on holds the flags, so a changed `OPT` or `CFLAGS` recompiles everything, and
  the same flags again compile nothing.

## 🎯 Make targets

| Target | What it does |
|---|---|
| `make` | Ordinary build: `bin/elpis`, and `bin/elpis.conf` seeded or brought up to date |
| `make static` | One statically linked binary, no shared libraries (runs `make clean` first) |
| `make test` | The self-tests: 693 at 2.4.2, no network needed |
| `make debug` | `-O0 -g3` with debug assertions |
| `make asan` | AddressSanitizer and UndefinedBehaviorSanitizer build |
| `make fuzz` | libFuzzer harnesses `bin/fuzz-msg` (DNS messages) and `bin/fuzz-tls` (the TLS client). Needs clang |
| `make tls-probe` | `bin/elpis-tls-probe`: the TLS client against one DoT server, with a query over it |
| `make licence-tool` | `bin/elpis-licence`, which signs deployment licences (see [licensing](licensing.md)) |
| `make install` | Install to `/opt/elpis-resolver/bin` (see [Installing](#-installing)) |
| `make uninstall` | Remove the binary, leave your config alone |
| `make clean` | Objects and binaries. Keeps `bin/elpis.conf` and `bin/elpis.conf.shipped` |
| `make distclean` | `bin/` and everything in it |

<sub>`debug`, `asan` and `static` run `make clean` first, because they change
what every object is compiled with. `tls-probe` and `licence-tool` are never
built by `all` and never installed.</sub>

## 🧰 Build variables

On the command line (`make OPT="-O2"`), or kept in `local.mk` (below).

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

> [!IMPORTANT]
> Keep `-fno-strict-aliasing` when you replace `OPT`. It is in the default, and
> it is what the code is built and tested with.

### Keeping them in `local.mk`

Settings you want on every build go in `local.mk` at the top of the tree, one
`NAME = value` per line:

```bash
cp local.mk.example local.mk
```

```make
OPT = -O3 -fno-strict-aliasing -march=znver3 -mtune=znver3
LICENCE_ISSUER = 6cd740f1...dd6315
```

`make` says what it took from it:

```
  local.mk sets: OPT LICENCE_ISSUER
```

- Git ignores the file, so a pull never touches it.
- It reaches builds that don't get your shell's environment: `sudo make install`,
  and `contrib/elpis-update.sh`, which runs as root.
  <br><sub>A variable set in `.bashrc` is lost in both. That matters most for
  `LICENCE_ISSUER`: a binary built without the key rejects every licence.</sub>
- Command line beats `local.mk`, and `local.mk` beats the environment.
- No `make clean` needed: the flags and the issuer key are watched, and
  whatever they affect is rebuilt.

## 💨 Tuning for your CPU

The default build targets the generic baseline of its architecture, so it runs
on any CPU of that kind. For the last few percent, compile for the CPU it will
run on:

```bash
make OPT="-O3 -fno-strict-aliasing -march=znver3 -mtune=znver3"
```

### x86-64

A microarchitecture level covers a whole generation from both vendors:

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

> [!WARNING]
> A binary built with `-march` needs that CPU or a newer one. On an older CPU it
> dies with "Illegal instruction", usually before it prints anything. Use
> `-march=native` only when you build on the machine that will run it. For a
> fleet of mixed hardware, pick the lowest `x86-64-vN` they all support.

### ARM64

`-mcpu` sets the architecture and the tuning together:

| CPU | Flags |
|---|---|
| Raspberry Pi 4 (Cortex-A72) | `-mcpu=cortex-a72` |
| Raspberry Pi 5 (Cortex-A76) | `-mcpu=cortex-a76` |
| AWS Graviton2, Ampere Altra (Neoverse N1) | `-mcpu=neoverse-n1` |
| AWS Graviton3 (Neoverse V1) | `-mcpu=neoverse-v1` |
| The machine you are building on | `-mcpu=native` |

### Other architectures

Anything with a C99 compiler and POSIX builds. RISC-V, POWER and others use the
scalar code paths, and 32-bit ARM uses NEON (below).

<sub>RISC-V boards typically want `-march=rv64gc`.</sub>

## 🧮 SIMD kernels

The hot paths — cache lookups, name comparison, case folding — have hand-written
vector kernels:

| Architecture | Kernels |
|---|---|
| x86-64 | SSE2 and AVX2, plus AES-NI and PCLMULQDQ for DoT's AES-128-GCM |
| ARM64 | NEON |
| 32-bit ARM | NEON, where the compiler targets an FPU that has it |
| everything else | scalar |

**On x86-64 the kernel is chosen at runtime.** Each kernel file is compiled with
its own instruction-set flags (the AVX2 file with `-mavx2 -mbmi -mbmi2`, the
AES file with `-maes -mpclmul -mssse3`), and the CPU is asked at startup what
it supports. A generic build still uses AVX2 and AES-NI on a CPU that has them,
and still runs on one that doesn't.

<sub>`-march` does not change which kernel runs; it changes how the compiler
builds everything else. The self-tests check every vector path against the
scalar one, byte for byte, so kernels differ only in speed. Without AES-NI,
AES-128-GCM uses a portable constant-time version, and ChaCha20-Poly1305 is the
suite offered first.</sub>

## 📦 Static builds

```bash
make static
make static OPT="-O3 -fno-strict-aliasing -march=x86-64-v3"
```

One self-contained binary, no shared libraries: about 1.5 MB with glibc on
x86-64, stripped. Copy it to any Linux of the same architecture and run it.

<sub>Elpis never uses the system's name lookup (`getaddrinfo`, NSS), so the
usual glibc warnings about static linking don't apply. On Alpine the same
command builds against musl, which usually gives a smaller binary.</sub>

## 🌍 Cross-compiling

The Makefile picks the SIMD kernels from `UNAME_M`, which defaults to the
machine you build on. Set it to the target, with the cross compiler:

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

> [!NOTE]
> `make test` then builds a binary for the target, which can't run on the
> build machine. Run `bin/elpis-test` on the target, or under `qemu-user`.
> <br><sub>A dry run confirms the Makefile switches to the NEON kernels for
> `UNAME_M=aarch64`. No cross build was run for this release.</sub>

## 🔖 What a binary says about itself

The startup line names the release, the compiler, the architecture, the CPU the
build was tuned for, and the kernels in use:

```
elpis 2.4.2 "Lettersong" starting: avx2 kernels (cpu: sse2 ssse3 sse4.1
      avx2 bmi2 aes pclmul), epoll, gcc 13.3.0, x86_64 znver3 (native), ...
```

The tuning reads `generic` with no `-march`, `x86-64-v3` or `znver3` with one,
and `znver3 (native)` for `-march=native`.

The **build** string says where the binary came from:

| Built from | Build string |
|---|---|
| a release tag | `v2.4.2` |
| any other commit | `main@bcc97d252fac` (branch and commit) |
| a tarball, no git | empty, and the status page says `no git checkout` |

It shows in the About window, the status JSON, and the identity TXT record:

```bash
dig @127.0.0.1 -p 5335 elpis.sakurako.oomuro TXT
```

## 📥 Installing

```bash
sudo make install            # -> /opt/elpis-resolver/bin/{elpis,elpis.conf}
sudo make uninstall          # removes the binary, keeps your config
```

- `/opt` keeps Elpis clear of anything the distribution manages.
- The installed layout has the same shape as `bin/`, so the config is found the
  same way in both.
- An existing config is never overwritten.
- `make install PREFIX=/usr/local` for another place, `DESTDIR=` for a
  packaging root.

For a checkout at `/opt/elpis-resolver` that runs as a service:

| script | does |
|---|---|
| [`contrib/elpis-update.sh`](../contrib/elpis-update.sh) | pull, build, check the config, restart. Says when `contrib/` has changed since it was installed |
| [`contrib/elpis-reinstall.sh`](../contrib/elpis-reinstall.sh) | everything around the binary: the `elpis` account, the systemd unit, both commands in `/usr/local/sbin`, enabling the service. `RESOLVED=replace` also takes systemd-resolved's place on `127.0.0.53` |

```bash
sudo bash /opt/elpis-resolver/contrib/elpis-reinstall.sh    # the first time
sudo elpis-update                                           # from then on
sudo elpis-reinstall                                        # when it says so
```

<sub>The unit, [contrib/elpis.service](../contrib/elpis.service), expects the
`/opt` path and binds port 53 with `CAP_NET_BIND_SERVICE` rather than running as
root. Both scripts look before they change anything; `DRY_RUN=1 elpis-reinstall`
shows what it would do.</sub>

## 🔬 Working on Elpis

None of these is needed to build or run Elpis:

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
make fuzz && mkdir -p bin/corpus-tls && cd bin && ./fuzz-tls -max_total_time=300 corpus-tls/
make tls-probe && bin/elpis-tls-probe 1.1.1.1 example.com A
```

<sub>For readable valgrind stacks, build with
`make OPT="-O1 -g -fno-strict-aliasing -fno-omit-frame-pointer"`. The code
builds without warnings under gcc and clang at the Makefile's warning level,
and should stay that way.</sub>

## 🩹 When the build goes wrong

| Symptom | Cause |
|---|---|
| Errors about `ifneq`, or `missing separator` | Not GNU make, as on the BSDs. Use `gmake`. |
| `python3 not found: keeping the committed src/webui/webui_assets.h` | Not an error. Install python3 only if you edit `web/index.html`. |
| The binary stops with "Illegal instruction" | Built with `-march` for a newer CPU than this one. Rebuild with a lower level or no `-march`. |
| The startup line says `generic` after you changed `OPT` | `CFLAGS` was also set, and it overrides `OPT`. Unset it. |
| `make fuzz` fails | Needs clang with libFuzzer (`sudo apt install clang`). |

---

<sub>[README](../README.md) · [Configuration](configuration.md) · [Caching](caching.md) · [DNSSEC](dnssec.md) · [Status page](status-page.md) · [Troubleshooting](troubleshooting.md) · [Quirks](quirks.md) · [Internals](internals.md) · [Licensing](licensing.md)</sub>
