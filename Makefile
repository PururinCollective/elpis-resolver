# Elpis Resolver -- portable C99 recursive DNS resolver
# SPDX-License-Identifier: see LICENSE

# Your own settings for every build, one `NAME = value` per line: OPT for a
# tuned build, CC, PREFIX, LICENCE_ISSUER -- anything in the table in
# docs/COMPILING.md.  See local.mk.example.  Git ignores the file, so a pull
# leaves it alone, and it reaches builds that do not get your shell's
# environment: `sudo make install`, and contrib/elpis-update.sh running as
# root.  A value on the make command line still wins over it, and it wins
# over the environment.
-include local.mk
ifeq ($(MAKELEVEL),0)
ifneq ($(wildcard local.mk),)
LOCAL_MK_VARS := $(strip $(shell sed -n -e 's/^[[:space:]]*override[[:space:]]*//' \
    -e 's/^[[:space:]]*export[[:space:]]*//' \
    -e 's/^\([A-Za-z_][A-Za-z0-9_]*\)[[:space:]]*[:?+!]*=.*/\1/p' local.mk))
LOCAL_MK_SP :=
$(info $(LOCAL_MK_SP)  local.mk sets: $(or $(LOCAL_MK_VARS),nothing))
endif
endif

PROG      := elpis
# Build outputs land in bin/, which is ignored by git, so a working tree stays
# clean across `git pull` and the usual `make clean && make`.
BINDIR    := bin
BIN       := $(BINDIR)/$(PROG)
TESTBIN   := $(BINDIR)/$(PROG)-test
BINCONF   := $(BINDIR)/$(PROG).conf
BINCONF_BASE := $(BINDIR)/$(PROG).conf.shipped
VERSION   := 2.3.0
# This is a self-contained program: one binary and one config file beside it.
# /opt keeps it out of the way of anything the distribution manages, and the
# shipped systemd unit expects it here.
PREFIX    ?= /opt/elpis-resolver
SYSCONFDIR?= /etc

CC        ?= cc
AR        ?= ar

# ---- portability -----------------------------------------------------------
# Strict C99 + POSIX.1-2008.  No GNU extensions are required; where a compiler
# supports them (e.g. __builtin_expect) they are used behind feature tests.
STD       := -std=c99
POSIX     := -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700

WARN      := -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
             -Wstrict-prototypes -Wmissing-prototypes -Wwrite-strings \
             -Wno-unused-parameter -Wvla

OPT       ?= -O3 -fno-strict-aliasing -fomit-frame-pointer
DEFS      := -DELPIS_VERSION=\"$(VERSION)\" -DELPIS_SYSCONFDIR=\"$(SYSCONFDIR)\"
# The Ed25519 public key deployment licences are signed with.  Normally set
# once in include/elpis/licence.h; this is here so a one-off build can carry a
# different issuer without editing the tree.
ifneq ($(LICENCE_ISSUER),)
DEFS      += -DELPIS_LICENCE_ISSUER=\"$(LICENCE_ISSUER)\"
endif

CFLAGS    ?= $(OPT)
# -MMD -MP emits a .d file per object listing the headers it used, so a header
# change rebuilds every translation unit that included it.  Without this a
# struct layout change leaves stale objects behind and the link succeeds.
DEPFLAGS  := -MMD -MP

ALL_CFLAGS = $(STD) $(POSIX) $(WARN) $(DEFS) $(DEPFLAGS) $(CFLAGS) -Iinclude -Isrc -pthread
LDFLAGS   ?=
ALL_LDFLAGS = $(LDFLAGS) -pthread
LIBS      := -lm

# ---- sources ---------------------------------------------------------------
# One directory per part of the resolver; the program itself (startup, config,
# logging, counters, licence) stays at the top of src/.  Headers are all in
# include/elpis/ whichever directory their code lives in.

# DNS wire format: names, messages, record data, EDNS and cookies.
DNS_SRC := \
  src/dns/name.c src/dns/msg.c src/dns/rdata.c src/dns/edns.c \
  src/dns/rrlist.c src/dns/cookie.c src/dns/ecs.c

# The shared hash table and the caches built on it.
CACHE_SRC := \
  src/cache/cache.c src/cache/mcache.c src/cache/rcache.c src/cache/infra.c \
  src/cache/delegation.c

# Event loop and sockets, used by both the server and the resolver side.
NET_SRC := \
  src/net/loop.c src/net/sock.c

# The client side: listeners, the answer path, rate limits, local names, DNS64.
SERVER_SRC := \
  src/server/server.c src/server/ratelimit.c src/server/rrl.c \
  src/server/localzone.c src/server/dns64.c

# The upstream side: recursion, queries out, and warming at startup.
RESOLVER_SRC := \
  src/resolver/resolver.c src/resolver/outbound.c src/resolver/roots.c \
  src/resolver/tld.c src/resolver/axfr.c src/resolver/probe.c

DNSSEC_SRC := \
  src/dnssec/dnssec.c src/dnssec/nsec.c src/dnssec/nsec3.c \
  src/dnssec/trustanchor.c

# The status page and what it shows.
WEBUI_SRC := \
  src/webui/webui.c src/webui/telemetry.c src/webui/selfinfo.c

CORE_SRC := \
  src/util.c src/log.c src/conf.c src/stats.c src/licence.c src/conflict.c \
  src/quirks.c \
  src/simd/simd.c $(DNS_SRC) $(CACHE_SRC) $(NET_SRC) $(SERVER_SRC) \
  $(RESOLVER_SRC) $(DNSSEC_SRC) $(WEBUI_SRC) src/main.c

CRYPTO_SRC := \
  src/crypto/sha1.c src/crypto/sha2.c src/crypto/keccak.c src/crypto/bn.c \
  src/crypto/rsa.c src/crypto/ec.c src/crypto/ecdsa.c src/crypto/ed25519.c \
  src/crypto/mldsa.c src/crypto/chacha20.c src/crypto/rand.c

# What a TLS 1.3 client needs on top: HKDF, X25519 and the two record
# ciphers (include/elpis/tlscrypto.h).  Kept apart from CRYPTO_SRC, which the
# licence tool compiles as well and has no use for these.  The AES-NI half of
# AES-128-GCM is in the x86 list below, built with the flags it needs.
TLSCRYPTO_SRC := \
  src/crypto/hkdf.c src/crypto/poly1305.c src/crypto/x25519.c \
  src/crypto/aes.c src/crypto/aead.c

SRC      := $(CORE_SRC) $(CRYPTO_SRC) $(TLSCRYPTO_SRC)
OBJ      := $(SRC:.c=.o)

# ---- build provenance ------------------------------------------------------
# The commit a binary was built from, so "which build are you running?" has an
# exact answer.  It goes into a generated header rather than onto the command
# line because a command-line -D would change ALL_CFLAGS on every commit and
# rebuild every object; the header is rewritten only when the revision really
# changes, and then only the one file that includes it recompiles.  Outside a
# git checkout (a release tarball) it comes out empty and the page says so.
#
# A build from a release tag says so and nothing else -- "v2.0.1".  Any other
# build is its branch and commit, "main@bcc97d252fac", or the commit alone on
# a detached HEAD.  There is no "-dirty": it was on every build made with a
# change not yet committed, which is most of them while working, and a
# release carrying it read as a broken one.
GITREV   := $(shell git describe --tags --exact-match HEAD 2>/dev/null)
ifeq ($(GITREV),)
GITHASH  := $(shell git rev-parse --short=12 HEAD 2>/dev/null)
GITBR    := $(shell git symbolic-ref --short -q HEAD 2>/dev/null)
GITREV   := $(if $(GITBR),$(if $(GITHASH),$(GITBR)@$(GITHASH)),$(GITHASH))
endif

# SIMD kernels compiled with elevated ISA + selected at runtime via CPUID.
SIMD_X86_SRC := src/simd/simd_sse2.c src/simd/simd_avx2.c src/crypto/aes_ni.c
SIMD_ARM_SRC := src/simd/simd_neon.c

# Only when not given, so a cross build can set it in local.mk as well as on
# the command line.
ifndef UNAME_M
UNAME_M := $(shell uname -m 2>/dev/null || echo unknown)
endif

ifneq (,$(filter x86_64 amd64 i386 i686,$(UNAME_M)))
  SIMD_SRC  := $(SIMD_X86_SRC)
  SIMD_OBJ  := $(SIMD_SRC:.c=.o)
  DEFS      += -DELPIS_ARCH_X86=1
else ifneq (,$(filter aarch64 arm64 armv7l,$(UNAME_M)))
  SIMD_SRC  := $(SIMD_ARM_SRC)
  SIMD_OBJ  := $(SIMD_SRC:.c=.o)
  DEFS      += -DELPIS_ARCH_ARM=1
else
  SIMD_SRC  :=
  SIMD_OBJ  :=
endif

OBJ += $(SIMD_OBJ)

# ---- targets ---------------------------------------------------------------
.PHONY: all static debug asan clean distclean install uninstall test check fmt \
        licence-tool fuzz FORCE


all: $(BIN) $(BINCONF) $(BINCONF_BASE)

FORCE:

src/gitrev.h: FORCE
	@printf '/* generated by make; not tracked */\n#define ELPIS_GITREV "%s"\n' \
	    '$(GITREV)' > $@.tmp
	@cmp -s $@.tmp $@ || { mv -f $@.tmp $@; \
	    echo "  build provenance: $(if $(GITREV),$(GITREV),no git checkout)"; }
	@rm -f $@.tmp

# The CPU the build is compiled for, as the compiler resolves -march, -mtune
# and -mcpu: "znver3", "znver3 (native)", or "generic" when none is given.  It
# goes beside the compiler on the startup line and the status page, in a
# header rewritten only when it changes, as the revision is.
TARGET_FLAGS := $(filter -march=% -mtune=% -mcpu=%,$(CFLAGS))

src/buildtarget.h: FORCE
	@printf '/* generated by make; not tracked */\n#define ELPIS_BUILD_TARGET "%s"\n' \
	    "$$(CC='$(CC)' sh tools/cputarget.sh $(TARGET_FLAGS))" > $@.tmp
	@cmp -s $@.tmp $@ || { mv -f $@.tmp $@; \
	    echo "  built for: $$(sed -n 's/.*TARGET "\(.*\)"/\1/p' $@)"; }
	@rm -f $@.tmp

src/util.o: src/gitrev.h src/buildtarget.h

# make watches files, not flags.  Change OPT, CFLAGS or VERSION over an
# existing build and every object stays as it was compiled: a binary built
# with -march=znver3 that is mostly generic, or a 1.1.14 that still calls
# itself 1.1.13 until someone thinks to run make clean.  The stamp holds the
# flags, is rewritten only when they change, and everything compiled with them
# depends on it.
src/cflags.stamp: FORCE
	@printf '%s\n' '$(CC) $(ALL_CFLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ || mv -f $@.tmp $@
	@rm -f $@.tmp

$(OBJ) tests/test_main.o tests/ed25519_sign.o tests/licence_test.o: src/cflags.stamp

# The status page is compiled in, so the generated header has to be rebuilt
# whenever the page changes.  Doing that by hand is a trap: regenerate it
# within the same second as the last build and make's mtime comparison says
# the object is current, so the old page stays in the binary and every test
# of the new one silently measures the old one.
src/webui/webui_assets.h: web/index.html tools/mkassets.py
	@if command -v python3 >/dev/null 2>&1; then \
	    python3 tools/mkassets.py; \
	else \
	    echo "  python3 not found: keeping the committed $@"; \
	    touch $@; \
	fi

src/webui/webui.o: src/webui/webui_assets.h

# Changing LICENCE_ISSUER changes a -D, and make does not watch flags: without
# this, `make LICENCE_ISSUER=...` over an existing build leaves the old key
# compiled in and silently rejects every licence.  The stamp holds the value,
# so it is rewritten exactly when the value changes, and licence.o rebuilds.
src/licence_issuer.stamp: FORCE
	@printf '%s\n' '$(LICENCE_ISSUER)' > $@.tmp
	@cmp -s $@.tmp $@ || mv -f $@.tmp $@
	@rm -f $@.tmp

src/licence.o: src/licence_issuer.stamp

# ---- licence tool ----------------------------------------------------------
# Not built by `all` and not installed: it is the only thing here that signs,
# and it is for whoever issues licences, not for whoever runs a resolver.  It
# compiles its own copy of the crypto with ELPIS_ED25519_SIGN defined, so the
# signing code never reaches bin/elpis.
LICENCE_BIN  := $(BINDIR)/$(PROG)-licence
LICENCE_SRC  := tools/licence.c src/licence.c src/util.c src/log.c $(CRYPTO_SRC)

licence-tool: $(LICENCE_BIN)

$(LICENCE_BIN): $(LICENCE_SRC) src/gitrev.h src/buildtarget.h src/licence_issuer.stamp | $(BINDIR)
	$(CC) $(STD) $(POSIX) $(WARN) $(DEFS) -DELPIS_ED25519_SIGN=1 \
	    $(CFLAGS) -Iinclude -Isrc -pthread -o $@ $(LICENCE_SRC) \
	    $(ALL_LDFLAGS) $(LIBS)

$(BINDIR):
	@mkdir -p $(BINDIR)

# bin/ is meant to be a complete, portable bundle: copy the directory to a
# machine and it runs.  The config is seeded from the shipped defaults, and
# after that it is yours: `make clean` leaves it alone, and so does every
# rebuild -- except that when elpis.conf itself changes, the change is merged
# in, three-way, against the defaults your copy was last merged with
# (bin/elpis.conf.shipped).  New settings and comments arrive and your edits
# stay.  Where both changed the same lines nothing is touched: the merge with
# the conflicts marked goes to bin/elpis.conf.new and make says so, every
# time, until you have dealt with it.  See tools/conf-merge.sh.  Use
# `make distclean` to start over.
$(BINCONF): | $(BINDIR)
	@sh tools/conf-merge.sh elpis.conf $(BINCONF) $(BINCONF_BASE)

$(BINCONF_BASE): elpis.conf | $(BINCONF)
	@sh tools/conf-merge.sh elpis.conf $(BINCONF) $(BINCONF_BASE)

$(BIN): $(OBJ) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) -o $@ $(OBJ) $(ALL_LDFLAGS) $(LIBS)

# Fully static, relocatable binary.  Note: we never call getaddrinfo()/NSS, so
# a static glibc link carries no dlopen() surprises.
# OPT is passed through rather than hardcoded, so a tuned static build works:
#   make static OPT="-O3 -fno-strict-aliasing -march=znver3 -mtune=znver3"
STATIC_OPT ?= $(OPT)
static:
	$(MAKE) clean
	$(MAKE) LDFLAGS="-static" OPT="$(STATIC_OPT)" $(BIN) $(BINCONF) $(BINCONF_BASE)
	-strip $(BIN)

debug:
	$(MAKE) clean
	$(MAKE) OPT="-O0 -g3 -DELPIS_DEBUG=1 -fno-omit-frame-pointer" $(BIN)

asan:
	$(MAKE) clean
	$(MAKE) OPT="-O1 -g3 -DELPIS_DEBUG=1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined" $(BIN)

src/simd/simd_avx2.o: src/simd/simd_avx2.c
	$(CC) $(ALL_CFLAGS) -mavx2 -mbmi -mbmi2 -c -o $@ $<

src/simd/simd_sse2.o: src/simd/simd_sse2.c
	$(CC) $(ALL_CFLAGS) -msse2 -c -o $@ $<

src/crypto/aes_ni.o: src/crypto/aes_ni.c
	$(CC) $(ALL_CFLAGS) -maes -mpclmul -mssse3 -c -o $@ $<

src/simd/simd_neon.o: src/simd/simd_neon.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# ---- tests -----------------------------------------------------------------
# Two objects are rebuilt differently for the test binary: ed25519 with signing
# compiled in, so the RFC 8032 vectors can be checked in both directions, and
# licence with a known issuer key, so a licence can be signed and verified
# without a real one.  The key is RFC 8032's own test vector 1 -- published,
# therefore obviously not a secret, which is exactly what a test key should be.
TEST_SRC    := tests/test_main.c
TEST_ISSUER := d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
TEST_OBJ    := $(filter-out src/main.o src/crypto/ed25519.o src/licence.o,$(OBJ)) \
               tests/ed25519_sign.o tests/licence_test.o

tests/ed25519_sign.o: src/crypto/ed25519.c
	$(CC) $(ALL_CFLAGS) -DELPIS_ED25519_SIGN=1 -c -o $@ $<

tests/licence_test.o: src/licence.c
	$(CC) $(ALL_CFLAGS) -UELPIS_LICENCE_ISSUER \
	    -DELPIS_LICENCE_ISSUER=\"$(TEST_ISSUER)\" -c -o $@ $<

tests/test_main.o: tests/test_main.c
	$(CC) $(ALL_CFLAGS) -DELPIS_ED25519_SIGN=1 -c -o $@ $<

$(TESTBIN): $(TEST_OBJ) tests/test_main.o | $(BINDIR)
	$(CC) $(ALL_CFLAGS) -o $@ $^ $(ALL_LDFLAGS) $(LIBS)

test check: $(TESTBIN)
	./$(TESTBIN)

# ---- fuzzing ---------------------------------------------------------------
# libFuzzer over everything a DNS message passes through before it is trusted:
# the parser, every record type's rdata, and the NSEC and NSEC3 proofs
# (tests/fuzz_msg.c).  Needs clang.  Its objects are compiled apart from the
# normal ones, under bin/fuzz/, with the fuzzer's coverage and ASan/UBSan.
#
#   make fuzz
#   mkdir -p bin/corpus && cd bin && ./fuzz-msg -max_total_time=300 corpus/
#
# From bin/, because with -jobs libFuzzer writes a fuzz-N.log wherever it runs.
FUZZ_CC     ?= clang
FUZZ_BIN    := $(BINDIR)/fuzz-msg
FUZZ_DIR    := $(BINDIR)/fuzz
FUZZ_CFLAGS  = $(STD) $(POSIX) $(WARN) $(DEFS) $(DEPFLAGS) -O1 -g \
               -fno-omit-frame-pointer -fsanitize=address,undefined \
               -Iinclude -Isrc -pthread
FUZZ_OBJ    := $(patsubst %.c,$(FUZZ_DIR)/%.o,$(filter-out src/main.c,$(SRC) $(SIMD_SRC)))

fuzz: $(FUZZ_BIN)

$(FUZZ_DIR)/src/simd/simd_avx2.o: FUZZ_ISA := -mavx2 -mbmi -mbmi2
$(FUZZ_DIR)/src/simd/simd_sse2.o: FUZZ_ISA := -msse2
$(FUZZ_DIR)/src/crypto/aes_ni.o: FUZZ_ISA := -maes -mpclmul -mssse3
$(FUZZ_DIR)/src/util.o: src/gitrev.h src/buildtarget.h
$(FUZZ_DIR)/src/webui/webui.o: src/webui/webui_assets.h
$(FUZZ_DIR)/src/licence.o: src/licence_issuer.stamp

$(FUZZ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer-no-link $(FUZZ_ISA) -c -o $@ $<

$(FUZZ_BIN): tests/fuzz_msg.c $(FUZZ_OBJ) | $(BINDIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer -o $@ $^ $(LIBS)

# Installs the same shape as the build tree, so the config lookup behaves
# identically whether you run it from bin/ or from /opt.  An existing config is
# never overwritten.
install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(PROG)
	test -f $(DESTDIR)$(PREFIX)/bin/$(PROG).conf || \
	  install -m 0644 elpis.conf $(DESTDIR)$(PREFIX)/bin/$(PROG).conf
	@echo "installed $(PREFIX)/bin/$(PROG) and its config"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(PROG)
	@echo "left $(PREFIX)/bin/$(PROG).conf in place; remove it yourself if you meant to"
	-rmdir $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX) 2>/dev/null || true

# Every object and .d file under src/ and tests/, not only the ones in $(OBJ):
# a build on another branch leaves objects for files this branch does not
# have, or has somewhere else, and $(OBJ) would never name them.
clean:
	rm -f $(BIN) $(TESTBIN) $(BINDIR)/$(PROG)-licence $(FUZZ_BIN) $(FUZZ_BIN).d
	rm -rf $(FUZZ_DIR)
	find src tests \( -name '*.o' -o -name '*.d' \) -exec rm -f {} +
	rm -f src/gitrev.h src/licence_issuer.stamp src/buildtarget.h src/cflags.stamp
	@rmdir $(BINDIR) 2>/dev/null || true

# clean keeps bin/elpis.conf because it is yours by then, and the record of
# the defaults it was merged with; this drops them too.
distclean: clean
	rm -rf $(BINDIR)

# The test objects are built outside $(OBJ), so their own .d files have to be
# named here as well -- otherwise a change to a header leaves them stale and
# they are linked against a struct layout they were not compiled for.  That
# includes the signing ed25519 and the test-issuer licence objects: a change to
# the bignum header once left both behind, and every Ed25519 test failed.
-include $(OBJ:.o=.d) tests/test_main.d tests/ed25519_sign.d \
         tests/licence_test.d $(FUZZ_OBJ:.o=.d)
