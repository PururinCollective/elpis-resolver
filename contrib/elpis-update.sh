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

# Build before stopping anything.  The old binary keeps serving while this
# runs, and a build that fails leaves it serving -- which is the whole point
# of not cleaning first.
say "building${MARCH:+ for $MARCH}"
make static OPT="$OPT"

[ -x bin/elpis ] || die "build produced no bin/elpis"
./bin/elpis -t >/dev/null 2>&1 || die "built binary rejects the config; not restarting"
new=$(./bin/elpis -V)

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
say "$(dig +short +tries=1 +timeout=3 TXT elpis.sakurako.oomuro @127.0.0.1 2>/dev/null | head -1 || echo '(probe did not answer)')"
[ "$was_running" -eq 1 ] || say "note: $UNIT was not running before this"
echo "[!] DONE"
