# Elpis Resolver -- portable C99 recursive DNS resolver
# SPDX-License-Identifier: see LICENSE

PROG      := elpis
# Build outputs land in bin/, which is ignored by git, so a working tree stays
# clean across `git pull` and the usual `make clean && make`.
BINDIR    := bin
BIN       := $(BINDIR)/$(PROG)
TESTBIN   := $(BINDIR)/$(PROG)-test
VERSION   := 1.0.0
PREFIX    ?= /usr/local
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
CORE_SRC := \
  src/util.c src/log.c src/conf.c src/simd.c src/name.c src/msg.c src/rdata.c \
  src/edns.c src/rrlist.c src/cache.c src/mcache.c src/rcache.c src/infra.c src/loop.c \
  src/sock.c src/server.c src/outbound.c src/resolver.c src/delegation.c \
  src/roots.c src/tld.c src/axfr.c src/probe.c src/dns64.c src/localzone.c src/ratelimit.c \
  src/stats.c src/dnssec.c src/nsec.c src/nsec3.c src/trustanchor.c \
  src/cookie.c src/rrl.c src/conflict.c src/main.c

CRYPTO_SRC := \
  src/crypto/sha1.c src/crypto/sha2.c src/crypto/keccak.c src/crypto/bn.c \
  src/crypto/rsa.c src/crypto/ec.c src/crypto/ecdsa.c src/crypto/ed25519.c \
  src/crypto/mldsa.c src/crypto/rand.c

SRC      := $(CORE_SRC) $(CRYPTO_SRC)
OBJ      := $(SRC:.c=.o)

# SIMD kernels compiled with elevated ISA + selected at runtime via CPUID.
SIMD_X86_SRC := src/simd_sse2.c src/simd_avx2.c
SIMD_ARM_SRC := src/simd_neon.c

UNAME_M := $(shell uname -m 2>/dev/null || echo unknown)

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
.PHONY: all static debug asan clean install uninstall test check fmt

all: $(BIN)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(BIN): $(OBJ) | $(BINDIR)
	$(CC) $(ALL_CFLAGS) -o $@ $(OBJ) $(ALL_LDFLAGS) $(LIBS)

# Fully static, relocatable binary.  Note: we never call getaddrinfo()/NSS, so
# a static glibc link carries no dlopen() surprises.
# OPT is passed through rather than hardcoded, so a tuned static build works:
#   make static OPT="-O3 -fno-strict-aliasing -march=znver3 -mtune=znver3"
STATIC_OPT ?= $(OPT)
static:
	$(MAKE) clean
	$(MAKE) LDFLAGS="-static" OPT="$(STATIC_OPT)" $(BIN)
	-strip $(BIN)

debug:
	$(MAKE) clean
	$(MAKE) OPT="-O0 -g3 -DELPIS_DEBUG=1 -fno-omit-frame-pointer" $(BIN)

asan:
	$(MAKE) clean
	$(MAKE) OPT="-O1 -g3 -DELPIS_DEBUG=1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined" $(BIN)

src/simd_avx2.o: src/simd_avx2.c
	$(CC) $(ALL_CFLAGS) -mavx2 -mbmi -mbmi2 -c -o $@ $<

src/simd_sse2.o: src/simd_sse2.c
	$(CC) $(ALL_CFLAGS) -msse2 -c -o $@ $<

src/simd_neon.o: src/simd_neon.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# ---- tests -----------------------------------------------------------------
TEST_SRC := tests/test_main.c
TEST_OBJ := $(filter-out src/main.o,$(OBJ))

$(TESTBIN): $(TEST_OBJ) tests/test_main.o | $(BINDIR)
	$(CC) $(ALL_CFLAGS) -o $@ $^ $(ALL_LDFLAGS) $(LIBS)

test check: $(TESTBIN)
	./$(TESTBIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/sbin/$(PROG)
	install -d $(DESTDIR)$(SYSCONFDIR)/elpis
	test -f $(DESTDIR)$(SYSCONFDIR)/elpis/elpis.conf || \
	  install -m 0644 elpis.conf $(DESTDIR)$(SYSCONFDIR)/elpis/elpis.conf

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(PROG)

clean:
	rm -f $(OBJ) tests/test_main.o $(BIN) $(TESTBIN)
	rm -f src/*.d src/crypto/*.d tests/*.d
	@rmdir $(BINDIR) 2>/dev/null || true

# The test object is built outside $(OBJ), so its own .d has to be named here
# as well -- otherwise a change to a header leaves tests/test_main.o stale and
# it is linked against a struct layout it was not compiled for.
-include $(OBJ:.o=.d) tests/test_main.d
