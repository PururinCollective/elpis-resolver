#!/bin/bash
#
# Pull, rebuild, restart -- and stop at the first thing that goes wrong.
#
#   install -m0755 contrib/elpis-update.sh /usr/local/sbin/elpis-update
#   elpis-update
#
# Set MARCH for a tuned build; leave it unset for a portable one:
#
#   MARCH=znver3 elpis-update
#
# A build that carries a licence issuer key gets it from LICENCE_ISSUER, and
# this runs as root, without your shell's environment.  Put it in local.mk at
# the top of the tree, which make reads and git leaves alone:
#
#   echo 'LICENCE_ISSUER = 6cd740f1...dd6315' > /opt/elpis-resolver/local.mk
#
# A new build that carries a different key from the one it replaces -- none,
# most likely -- is not installed: the old binary is put back and nothing is
# restarted.  ALLOW_ISSUER_CHANGE=yes installs it anyway, for a new key.
#
set -euo pipefail

# `service` and `systemctl` live in /usr/sbin, which is not on every
# non-login shell's PATH.  A script that works when pasted into a terminal
# and fails from cron is usually this.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SRC=${SRC:-/opt/elpis-resolver}
UNIT=${UNIT:-elpis}
MARCH=${MARCH:-}

die() { echo "[x] $*" >&2; exit 1; }
say() { echo "[*] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root: $SRC is root-owned and systemctl needs it"
cd "$SRC" || die "no $SRC"
command -v systemctl >/dev/null || die "no systemctl on PATH"

OPT="-O3 -fno-strict-aliasing"
[ -n "$MARCH" ] && OPT="$OPT -march=$MARCH -mtune=$MARCH"

was_running=0
systemctl is-active --quiet "$UNIT" && was_running=1

say "updating $SRC"
git pull --ff-only

# The licence issuer key the current build carries: see the top of this file.
# The binary is kept until the new one has shown it is fit to replace it.
issuer_of() { "$1" -V 2>/dev/null | sed -n 's/^licence issuer: //p'; }
old_issuer=""
if [ -x bin/elpis ]; then
    old_issuer=$(issuer_of ./bin/elpis) || old_issuer=""
    cp -p bin/elpis bin/elpis.prev
fi
put_back() { if [ -f bin/elpis.prev ]; then mv -f bin/elpis.prev bin/elpis; fi; }

# Build before stopping anything.  The old binary keeps serving while this
# runs, and a build that fails leaves it serving -- which is the whole point
# of not cleaning first.
say "building${MARCH:+ for $MARCH}"
make static OPT="$OPT" || { put_back; die "build failed; the old binary is back"; }

[ -x bin/elpis ] || { put_back; die "build produced no bin/elpis"; }
./bin/elpis -t >/dev/null 2>&1 ||
    { put_back; die "built binary rejects the config; the old binary is back, not restarting"; }

# A binary from before -V printed the key shows nothing here, and is not
# checked; "none" is a build that carries no key.
new_issuer=$(issuer_of ./bin/elpis) || new_issuer=
if [ -n "$old_issuer" ] && [ "$old_issuer" != none ] &&
   [ "$new_issuer" != "$old_issuer" ] && [ "${ALLOW_ISSUER_CHANGE:-}" != yes ]; then
    put_back
    if [ "$new_issuer" = none ]; then
        echo "[x] the new build carries no licence issuer key; the one it replaces has" >&2
        echo "    $old_issuer" >&2
        echo "    LICENCE_ISSUER did not reach the build.  Put it in $SRC/local.mk:" >&2
        echo "      LICENCE_ISSUER = $old_issuer" >&2
    else
        echo "[x] the new build carries licence issuer $new_issuer," >&2
        echo "    not $old_issuer as the one it replaces does." >&2
    fi
    die "the old binary is back and nothing was restarted (ALLOW_ISSUER_CHANGE=yes to install it anyway)"
fi
rm -f bin/elpis.prev
new=$(./bin/elpis -V | head -1)

say "restarting $UNIT"
systemctl restart "$UNIT"

# systemctl restart returns once systemd has forked it, not once it has
# survived.  A binary that dies on its config exits a moment later.
sleep 2
if ! systemctl is-active --quiet "$UNIT"; then
    echo "[x] $UNIT did not come up:" >&2
    systemctl --no-pager --lines=20 status "$UNIT" >&2 || true
    exit 1
fi

say "running $new"
say "licence issuer: ${new_issuer:-none}"
say "$(dig +short +tries=1 +timeout=3 TXT elpis.sakurako.oomuro @127.0.0.1 2>/dev/null | head -1 || echo '(probe did not answer)')"
[ "$was_running" -eq 1 ] || say "note: $UNIT was not running before this"
echo "[!] DONE"
