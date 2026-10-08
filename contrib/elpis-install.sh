#!/bin/bash
#
# Set up, or bring up to date, everything around a git clone of Elpis,
# built in place, that elpis-update does not touch: the account elpis runs
# as, the systemd unit, enabling it, and -- when asked -- taking
# systemd-resolved's place.  Run it in place, as root, once after the first
# build and again whenever elpis-update says the unit has changed:
#
#   /opt/elpis-resolver/contrib/elpis-install.sh
#
# It looks after the clone it sits in, wherever that is, and writes the unit
# for that path.  /opt/elpis-resolver is the recommended place: it keeps
# Elpis apart from the system and easy to find.  Nothing is copied out of
# the clone except what systemd has to have: the unit, in
# /etc/systemd/system.  With a precompiled binary, replace the binary and
# keep a unit of your own; contrib/elpis.service is a starting point.
#
# Every step looks before it acts, so running it again changes nothing that
# is already right.  DRY_RUN=1 shows what it would do, changes nothing, and
# needs no root.
#
# systemd-resolved is this host's resolver, so it is left alone unless you
# ask.  To have elpis answer in its place on 127.0.0.53 -- 'listen:
# 127.0.0.53@53', or 'listen: 0.0.0.0@53', in bin/elpis.conf:
#
#   RESOLVED=replace /opt/elpis-resolver/contrib/elpis-install.sh
#
# That disables and masks resolved, so nothing starts it again, and replaces
# /etc/resolv.conf -- a link into /run/systemd/resolve, which nothing writes
# once resolved is gone -- with a file naming elpis.  The file it replaces is
# kept as /etc/resolv.conf.elpis-bak.  To undo it:
#
#   systemctl unmask systemd-resolved && systemctl enable --now systemd-resolved
#   mv /etc/resolv.conf.elpis-bak /etc/resolv.conf
#
# The unit is replaced whole when contrib/ has a new one; the old one is kept
# as elpis.service.bak, which systemd ignores.  A change of your own belongs
# in a drop-in, which this never touches:
#
#   systemctl edit elpis
#
set -euo pipefail

# Same reason as elpis-update: systemctl and useradd live in sbin, which is
# not on every non-login shell's PATH.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The clone this script sits in: the directory above contrib/.
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
RECOMMENDED=/opt/elpis-resolver
unit_new=                       # the unit as written for this clone; a temp file
UNIT=${UNIT:-elpis}
RESOLVED=${RESOLVED:-keep}
DRY_RUN=${DRY_RUN:-}
RESOLV=${RESOLV:-/etc/resolv.conf}
UNIT_FILE=/etc/systemd/system/$UNIT.service
ACCOUNT=elpis                   # the unit's User=

die()  { echo "[x] $*" >&2; exit 1; }
say()  { echo "[*] $*"; }
note() { echo "[!] $*"; }

# Every change goes through here, so DRY_RUN can show it instead.
run() {
    if [ -n "$DRY_RUN" ]; then
        echo "    would run: $*"
    else
        "$@"
    fi
}

# The addresses elpis will listen on, "addr:port" one per line, as elpis
# itself reads them from the config the service uses: bin/elpis.conf.
listen_addresses() {
    local out
    # A bad value fails the check, and its line is logged near the top, above
    # the settings elpis prints: show the errors rather than the tail.
    out=$(./bin/elpis -t 2>&1) || {
        grep -E ' (ERROR|FATAL) ' <<<"$out" >&2 || echo "$out" | tail -5 >&2
        die "bin/elpis rejects its config; fix that first"
    }
    sed -n 's/.* listen \([^ ]*\)$/\1/p' <<<"$out"
}

# The loopback address resolv.conf should name for elpis on port 53, or
# nothing when elpis does not listen on port 53 on loopback.
loopback_ns() {
    local a
    for a in "$@"; do
        case "$a" in 0.0.0.0:53|127.0.0.53:53) echo 127.0.0.53; return ;; esac
    done
    for a in "$@"; do
        case "$a" in 127.*:53) echo "${a%:53}"; return ;; esac
    done
    for a in "$@"; do
        case "$a" in '[::]:53'|'[::1]:53') echo ::1; return ;; esac
    done
}

# Is a resolv.conf nameserver $1 answered by elpis, listening on "${@:2}"?
# The wildcard on port 53 answers this host's own addresses, so loopback --
# not 1.1.1.1 or anyone else's.
answers_ns() {
    local ns=$1 a
    shift
    for a in "$@"; do
        [ "$a" != "$ns:53" ] && [ "$a" != "[$ns]:53" ] || return 0
        case "$ns:$a" in
        127.*:0.0.0.0:53|::1:\[::\]:53) return 0 ;;
        esac
    done
    return 1
}

# contrib/elpis.service is written for /opt/elpis-resolver; the unit that is
# installed is the same with this clone's path in its place.
render_unit() {
    sed "s|/opt/elpis-resolver|$SRC|g" contrib/elpis.service
}

# Does resolved's stub hold an address elpis wants?  Its stub is 127.0.0.53
# and 127.0.0.54, port 53; the wildcard collides with both.
stub_in_the_way() {
    local a wants=0
    for a in "$@"; do
        case "$a" in 0.0.0.0:53|127.0.0.53:53|127.0.0.54:53) wants=1 ;; esac
    done
    [ "$wants" -eq 1 ] || return 1
    [ "$(systemctl is-active systemd-resolved 2>/dev/null || true)" = active ] || return 1
    ss -Hlnu 2>/dev/null | grep -qE '127\.0\.0\.5[34](%[a-z0-9]+)?:53[[:space:]]'
}

# Replace a resolv.conf that leans on systemd-resolved with one naming elpis
# on $1; the rest of the arguments are where elpis listens.
fix_resolv_conf() {
    local ns=$1 target search tmp line
    shift
    local where=("$@")
    target=$(readlink "$RESOLV" 2>/dev/null || true)
    case "$target" in
    *systemd/resolve/*)
        ;;                          # resolved's own file: it goes with resolved
    "")
        if [ -e "$RESOLV" ]; then
            # Any nameserver line elpis answers will do: 127.0.0.1 is elpis
            # too when it listens on the wildcard.
            while read -r line; do
                if answers_ns "$line" "${where[@]}"; then
                    say "$RESOLV: already names elpis ($line)"
                    return 0
                fi
            done < <(sed -n 's/^nameserver[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$RESOLV")
            if ! grep -qE '^nameserver[[:space:]]+127\.0\.0\.53([[:space:]]|$)' "$RESOLV"; then
                note "$RESOLV is a file of its own and does not name elpis; left as it is:"
                grep '^nameserver' "$RESOLV" | sed 's/^/    /' || true
                return 0
            fi
        fi
        ;;                          # names the stub elpis is not on, or is missing
    *)
        note "$RESOLV links to $target, which is not systemd-resolved's; left as it is"
        return 0
        ;;
    esac

    # Keep the search domains the old file had, if it can still be read.
    search=$(grep -E '^(search|domain)[[:space:]]' "$RESOLV" 2>/dev/null | tail -1 || true)
    if [ -e "$RESOLV" ] || [ -L "$RESOLV" ]; then
        say "$RESOLV: replacing it with a file naming elpis ($ns); the old one is kept as $RESOLV.elpis-bak"
    else
        say "$RESOLV: missing; writing one naming elpis ($ns)"
    fi
    if [ -n "$DRY_RUN" ]; then
        echo "    would write: nameserver $ns / options edns0 trust-ad${search:+ / $search}"
        return 0
    fi
    cp -P "$RESOLV" "$RESOLV.elpis-bak" 2>/dev/null || true
    # Written beside it and renamed over it: writing through the link would
    # write into resolved's file under /run instead of replacing the link.
    tmp=$RESOLV.elpis-new
    {
        echo "# Written by elpis-install on $(date +%F): elpis answers here, in"
        echo "# place of systemd-resolved.  The file this replaced is $RESOLV.elpis-bak."
        echo "nameserver $ns"
        # elpis validates DNSSEC and is on this host, so its AD bit can be
        # passed on to programs that ask -- as resolved's stub file does.
        echo "options edns0 trust-ad"
        [ -z "$search" ] || echo "$search"
    } >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$RESOLV"
}

main() {
    local listen listen_text ns unit_changed=0 resolved_changed=0 r_state
    local leftover f
    local first host port

    case "$RESOLVED" in
    keep|replace) ;;
    *) die "RESOLVED=$RESOLVED: use keep (the default) or replace" ;;
    esac
    [ -n "$DRY_RUN" ] || [ "$(id -u)" -eq 0 ] || die "run as root, or with DRY_RUN=1 to look"
    [ -z "$DRY_RUN" ] || say "dry run: nothing will be changed"
    cd "$SRC" || die "no $SRC"
    [ -e .git ] || die "$SRC is not a git clone; this looks after a clone built in place.  With a precompiled binary, replace the binary yourself and keep a unit of your own -- contrib/elpis.service is a starting point"
    # The unit names this path, so it has to be one a unit can name and the
    # service can reach.
    local bad='[[:space:]%"'\''\\|&]'
    [[ ! $SRC =~ $bad ]] || die "$SRC: a systemd unit cannot name a path with spaces or any of % \" ' \\ | &; clone it somewhere else, $RECOMMENDED for choice"
    case "$SRC/" in
    /home/*|/root/*|/run/user/*)
        die "$SRC: the unit's ProtectHome= hides home directories from the service, and the elpis account cannot reach into one anyway; clone it outside, $RECOMMENDED for choice" ;;
    esac
    [ "$SRC" = "$RECOMMENDED" ] ||
        note "this clone is at $SRC; $RECOMMENDED is the recommended place -- apart from the system and easy to find -- but the unit will be written for $SRC"
    command -v systemctl >/dev/null || die "no systemctl on PATH"
    [ -x bin/elpis ] || die "no $SRC/bin/elpis: build it first, with make static"
    [ -f contrib/elpis.service ] || die "no contrib/elpis.service in $SRC"

    listen_text=$(listen_addresses)
    [ -n "$listen_text" ] || die "could not read the listen addresses from bin/elpis -t"
    mapfile -t listen <<<"$listen_text"
    say "elpis will listen on: ${listen[*]}"

    # Refuse now, before anything is changed, rather than halfway through.
    ns=$(loopback_ns "${listen[@]}")
    case "$RESOLVED" in
    keep)
        if stub_in_the_way "${listen[@]}"; then
            die "systemd-resolved's stub holds 127.0.0.53/127.0.0.54 port 53, which elpis wants, so elpis would refuse to start; run this again with RESOLVED=replace to put elpis in its place, or set DNSStubListener=no for resolved yourself"
        fi
        ;;
    replace)
        [ -n "$ns" ] || die "RESOLVED=replace: elpis does not listen on port 53 on loopback, so nothing would answer in resolved's place; add 'listen: 127.0.0.53@53' (or 'listen: 0.0.0.0@53') to bin/elpis.conf"
        ;;
    esac

    # The account the unit runs elpis as.  systemd will not invent one.
    if getent passwd "$ACCOUNT" >/dev/null; then
        say "account $ACCOUNT: present"
    else
        say "account $ACCOUNT: creating it, with no home and no shell"
        run useradd --system --user-group --no-create-home \
            --shell "$(command -v nologin || echo /usr/sbin/nologin)" "$ACCOUNT"
    fi

    # Earlier instructions put copies of the scripts in /usr/local/sbin.
    # Everything runs from /opt now; point them out rather than delete
    # anything outside it.
    leftover=()
    for f in /usr/local/sbin/elpis-update /usr/local/sbin/elpis-reinstall; do
        [ ! -e "$f" ] || leftover+=("$f")
    done
    if [ "${#leftover[@]}" -gt 0 ]; then
        note "left in /usr/local/sbin by earlier instructions, and not needed now: ${leftover[*]}; the scripts run from $SRC/contrib.  Remove with: rm ${leftover[*]}"
    fi

    # The unit, written for this clone.
    unit_new=$(mktemp)
    trap 'rm -f "${unit_new:-}"' EXIT
    render_unit >"$unit_new"
    if [ -f "$UNIT_FILE" ] && cmp -s "$unit_new" "$UNIT_FILE"; then
        say "$UNIT_FILE: up to date"
    else
        if [ -f "$UNIT_FILE" ]; then
            note "$UNIT_FILE differs from contrib/elpis.service (for $SRC):"
            diff -u "$UNIT_FILE" "$unit_new" | sed -n '3,60p' | sed 's/^/    /' || true
            say "$UNIT_FILE: updating; the old one is kept as $UNIT_FILE.bak"
            run cp -p "$UNIT_FILE" "$UNIT_FILE.bak"
        else
            say "$UNIT_FILE: installing, for $SRC"
        fi
        run install -m 0644 "$unit_new" "$UNIT_FILE"
        run systemctl daemon-reload
        unit_changed=1
    fi

    # systemd-resolved.
    r_state=$(systemctl is-enabled systemd-resolved 2>/dev/null || true)
    case "$RESOLVED" in
    keep)
        say "systemd-resolved: left as it is (${r_state:-not installed})"
        ;;
    replace)
        case "$r_state" in
        masked)
            say "systemd-resolved: already masked" ;;
        ""|not-found)
            say "systemd-resolved: not installed" ;;
        *)
            say "systemd-resolved: stopping, disabling and masking it (it was $r_state)"
            run systemctl disable --now systemd-resolved
            run systemctl mask systemd-resolved
            resolved_changed=1
            ;;
        esac
        fix_resolv_conf "$ns" "${listen[@]}"
        ;;
    esac

    # Start at boot, and run the unit as it now is.
    if [ "$(systemctl is-enabled "$UNIT" 2>/dev/null || true)" = enabled ]; then
        say "$UNIT: enabled, so it starts at boot"
    else
        say "$UNIT: enabling it, so it starts at boot"
        run systemctl enable "$UNIT"
    fi
    if [ "$unit_changed" -eq 1 ] || [ "$resolved_changed" -eq 1 ] ||
       ! systemctl is-active --quiet "$UNIT"; then
        say "restarting $UNIT"
        run systemctl restart "$UNIT"
    else
        say "$UNIT: running, and nothing changed that needs a restart"
    fi
    if [ -n "$DRY_RUN" ]; then
        echo "[!] DRY RUN DONE: nothing was changed"
        return 0
    fi

    # systemctl restart returns once systemd has forked it, not once it has
    # survived.  A binary that dies on its config exits a moment later.
    sleep 2
    if ! systemctl is-active --quiet "$UNIT"; then
        echo "[x] $UNIT did not come up:" >&2
        systemctl --no-pager --lines=20 status "$UNIT" >&2 || true
        exit 1
    fi
    first=${listen[0]}
    port=${first##*:}
    host=${first%:*}
    host=${host#[}
    host=${host%]}
    case "$host" in 0.0.0.0) host=127.0.0.1 ;; ::) host=::1 ;; esac
    if command -v dig >/dev/null; then
        say "$(dig +short +tries=1 +timeout=3 -p "$port" TXT elpis.sakurako.oomuro @"$host" 2>/dev/null | head -1 || true)"
    fi
    echo "[!] DONE"
}

# Everything above is only definitions, so bash has read the whole file
# before any of it runs -- this script replaces its own installed copy.
main "$@"
