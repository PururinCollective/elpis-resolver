#!/bin/bash
#
# Pull, rebuild, restart -- and stop at the first thing that goes wrong.
# For a git clone of Elpis, built in place; run it from the clone, as root:
#
#   /opt/elpis-resolver/contrib/elpis-update.sh
#
# It updates the clone it sits in, wherever that is; /opt/elpis-resolver is
# the recommended place.  Nothing is copied out of the clone.  The systemd
# unit and the rest of the setup are contrib/elpis-install.sh's business;
# this says when the unit in contrib/ has changed and that needs running.
# With a precompiled binary there is nothing to pull: replace the binary.
#
# Set MARCH for a tuned build; leave it unset for a portable one:
#
#   MARCH=znver3 /opt/elpis-resolver/contrib/elpis-update.sh
#
# Or keep the build settings in local.mk at the top of the tree, which make
# reads and git leaves alone -- they then apply here, where this runs as root
# without your shell's environment, and to every other build too:
#
#   echo 'OPT = -O3 -fno-strict-aliasing -march=znver3 -mtune=znver3' \
#       >> /opt/elpis-resolver/local.mk
#
# MARCH, when given, replaces the OPT in local.mk for that run.
#
set -euo pipefail

# `service` and `systemctl` live in /usr/sbin, which is not on every
# non-login shell's PATH.  A script that works when pasted into a terminal
# and fails from cron is usually this.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The clone this script sits in: the directory above contrib/.
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
RECOMMENDED=/opt/elpis-resolver
UNIT=${UNIT:-elpis}
MARCH=${MARCH:-}

die() { echo "[x] $*" >&2; exit 1; }
say() { echo "[*] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root: $SRC is root-owned and systemctl needs it"
cd "$SRC" || die "no $SRC"
[ -e .git ] || die "$SRC is not a git clone, so there is nothing to pull; with a precompiled binary, replace the binary instead"
[ "$SRC" = "$RECOMMENDED" ] ||
    echo "[!] this clone is at $SRC; $RECOMMENDED is the recommended place -- apart from the system and easy to find"
command -v systemctl >/dev/null || die "no systemctl on PATH"

# OPT goes on the command line only for MARCH: otherwise it would override
# whatever local.mk says.
OPT_ARG=()
[ -n "$MARCH" ] &&
    OPT_ARG=(OPT="-O3 -fno-strict-aliasing -march=$MARCH -mtune=$MARCH")

was_running=0
systemctl is-active --quiet "$UNIT" && was_running=1

say "updating $SRC"
# This pull may replace this very script while it runs.  Git writes a new
# file rather than rewriting the old one in place, so bash goes on reading
# the old.
git pull --ff-only

# Build before stopping anything.  The old binary keeps serving while this
# runs, and a build that fails leaves it serving -- which is the whole point
# of not cleaning first.
say "building${MARCH:+ for $MARCH}"
make static ${OPT_ARG[@]+"${OPT_ARG[@]}"}

[ -x bin/elpis ] || die "build produced no bin/elpis"
# make merges new shipped defaults into bin/elpis.conf, and leaves it alone
# where they clash with your edits (tools/conf-merge.sh).  A config copied
# over from that merge with its markers still in would start -- the marker
# lines are skipped as unknown settings, which elpis -t only warns about --
# so refuse it here rather than run it.
if grep -q -e '^<<<<<<< ' -e '^>>>>>>> ' bin/elpis.conf; then
    die "bin/elpis.conf has merge conflict markers in it; not restarting"
fi
# elpis -t fails a config with a bad value in it, and names the line.  A
# start would only log that and run on the setting's default -- for a bad
# access-control line, refusing the clients it was meant to serve -- so show
# the line and leave the old binary serving.
if ! out=$(./bin/elpis -t 2>&1); then
    grep -E ' (ERROR|FATAL) ' <<<"$out" >&2 || tail -5 <<<"$out" >&2
    die "built binary rejects the config; not restarting"
fi
new=$(./bin/elpis -V)

# The unit is a copy in /etc/systemd/system, which a pull does not reach,
# written for this clone's path: compare it as elpis-install would write it.
unit_file=/etc/systemd/system/$UNIT.service
unit_stale=0
[ ! -f "$unit_file" ] ||
    sed "s|/opt/elpis-resolver|$SRC|g" contrib/elpis.service | cmp -s - "$unit_file" ||
    unit_stale=1

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
if [ "$unit_stale" -eq 1 ]; then
    echo "[!] $unit_file differs from contrib/elpis.service;"
    echo "[!] run $SRC/contrib/elpis-install.sh to bring it up to date"
fi
if [ -f bin/elpis.conf.shipped.pending ]; then
    echo "[!] new defaults in elpis.conf clash with your edits in bin/elpis.conf;"
    echo "[!] it is unchanged -- see bin/elpis.conf.new to merge them by hand"
fi
echo "[!] DONE"
