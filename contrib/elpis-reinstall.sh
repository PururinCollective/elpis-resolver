#!/bin/bash
#
# Put in place everything around the binary that elpis-update does not
# touch: the account elpis runs as, the systemd unit, the elpis-update and
# elpis-reinstall commands themselves, and -- when asked -- systemd-resolved
# and /etc/resolv.conf.  Run it once after the first build, and again when
# elpis-update says contrib/ has changed.
#
#   install -m0755 contrib/elpis-reinstall.sh /usr/local/sbin/elpis-reinstall
#   elpis-reinstall
#
# Every step looks before it acts, so running it again changes nothing that
# is already right.  DRY_RUN=1 shows what it would do, changes nothing, and
# needs no root.
#
# systemd-resolved is this host's resolver, so it is left alone unless you
# ask.  To have elpis answer in its place on 127.0.0.53 -- 'listen:
# 127.0.0.53@53', or 'listen: 0.0.0.0@53', in bin/elpis.conf:
#
#   RESOLVED=replace elpis-reinstall
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

SRC=${SRC:-/opt/elpis-resolver}
UNIT=${UNIT:-elpis}
RESOLVED=${RESOLVED:-keep}
DRY_RUN=${DRY_RUN:-}
SBIN=${SBIN:-/usr/local/sbin}
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

# Copy $1 to $2 with mode $3 when they differ.  Succeeds only when it copied.
install_if_changed() {
    if [ -f "$2" ] && cmp -s "$1" "$2"; then
        say "$2: up to date"
        return 1
    fi
    say "$2: $([ -f "$2" ] && echo updating || echo installing) from $1"
    run install -m "$3" "$1" "$2"
}

# The addresses elpis will listen on, "addr:port" one per line, as elpis
# itself reads them from the config the service uses: bin/elpis.conf.
listen_addresses() {
    local out
    out=$(./bin/elpis -t 2>&1) || {
        echo "$out" | tail -5 >&2
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

# Replace a resolv.conf that leans on systemd-resolved with one naming elpis.
fix_resolv_conf() {
    local ns=$1 target search tmp
    target=$(readlink "$RESOLV" 2>/dev/null || true)
    case "$target" in
    *systemd/resolve/*)
        ;;                          # resolved's own file: it goes with resolved
    "")
        if [ -e "$RESOLV" ]; then
            if grep -qE "^nameserver[[:space:]]+$ns([[:space:]]|\$)" "$RESOLV"; then
                say "$RESOLV: already names elpis ($ns)"
                return 0
            fi
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
        echo "# Written by elpis-reinstall on $(date +%F): elpis answers here, in"
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
    local first host port

    case "$RESOLVED" in
    keep|replace) ;;
    *) die "RESOLVED=$RESOLVED: use keep (the default) or replace" ;;
    esac
    [ -n "$DRY_RUN" ] || [ "$(id -u)" -eq 0 ] || die "run as root, or with DRY_RUN=1 to look"
    [ -z "$DRY_RUN" ] || say "dry run: nothing will be changed"
    cd "$SRC" || die "no $SRC"
    command -v systemctl >/dev/null || die "no systemctl on PATH"
    [ -x bin/elpis ] || die "no $SRC/bin/elpis: build it first, with make static or elpis-update"
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

    # These commands, so the next run is the new one.
    install_if_changed contrib/elpis-update.sh "$SBIN/elpis-update" 0755 || true
    install_if_changed contrib/elpis-reinstall.sh "$SBIN/elpis-reinstall" 0755 || true

    # The unit.
    if [ -f "$UNIT_FILE" ] && ! cmp -s contrib/elpis.service "$UNIT_FILE"; then
        note "$UNIT_FILE differs from contrib/elpis.service:"
        diff -u "$UNIT_FILE" contrib/elpis.service | sed -n '3,60p' | sed 's/^/    /' || true
        run cp -p "$UNIT_FILE" "$UNIT_FILE.bak"
    fi
    if install_if_changed contrib/elpis.service "$UNIT_FILE" 0644; then
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
        fix_resolv_conf "$ns"
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
