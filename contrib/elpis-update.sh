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

SRC=${SRC:-/opt/elpis-resolver}
UNIT=${UNIT:-elpis}
MARCH=${MARCH:-}

die() { echo "[x] $*" >&2; exit 1; }
say() { echo "[*] $*"; }

[ "$(id -u)" -eq 0 ] || die "run as root: $SRC is root-owned and systemctl needs it"
cd "$SRC" || die "no $SRC"
command -v systemctl >/dev/null || die "no systemctl on PATH"

# OPT goes on the command line only for MARCH: otherwise it would override
# whatever local.mk says.
OPT_ARG=()
[ -n "$MARCH" ] &&
    OPT_ARG=(OPT="-O3 -fno-strict-aliasing -march=$MARCH -mtune=$MARCH")

was_running=0
systemctl is-active --quiet "$UNIT" && was_running=1

say "updating $SRC"
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
# lines are skipped as bad settings -- so refuse it here rather than run it.
if grep -q -e '^<<<<<<< ' -e '^>>>>>>> ' bin/elpis.conf; then
    die "bin/elpis.conf has merge conflict markers in it; not restarting"
fi
./bin/elpis -t >/dev/null 2>&1 || die "built binary rejects the config; not restarting"
new=$(./bin/elpis -V)

# git pull updates contrib/, not the copies of it installed on this host.
stale=()
unit_file=/etc/systemd/system/$UNIT.service
[ ! -f "$unit_file" ] || cmp -s contrib/elpis.service "$unit_file" ||
    stale+=("$unit_file")
self=$(readlink -f "$0")
[ "$self" = "$(readlink -f contrib/elpis-update.sh)" ] ||
    cmp -s contrib/elpis-update.sh "$self" || stale+=("$self")

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
if [ "${#stale[@]}" -gt 0 ]; then
    echo "[!] contrib/ has changed since these were installed: ${stale[*]}"
    if command -v elpis-reinstall >/dev/null; then
        echo "[!] run elpis-reinstall to bring them up to date"
    else
        echo "[!] run 'bash $SRC/contrib/elpis-reinstall.sh' to bring them up to date"
    fi
fi
if [ -f bin/elpis.conf.shipped.pending ]; then
    echo "[!] new defaults in elpis.conf clash with your edits in bin/elpis.conf;"
    echo "[!] it is unchanged -- see bin/elpis.conf.new to merge them by hand"
fi
echo "[!] DONE"
