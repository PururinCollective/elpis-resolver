#!/bin/sh
#
# tools/conf-merge.sh -- bring a config up to date with the shipped defaults.
#
#   sh tools/conf-merge.sh SHIPPED MINE BASE
#
#   SHIPPED  elpis.conf as it is now, in the source tree
#   MINE     the config in use, edits and all: bin/elpis.conf
#   BASE     the shipped defaults MINE was last merged with:
#            bin/elpis.conf.shipped
#
# A three-way merge, the way git merges a branch: what changed in the shipped
# defaults since BASE is applied to MINE, and what you changed in MINE since
# BASE is kept.  New settings and new comments arrive; your edits stay.
#
# Where both sides changed the same lines, nothing is guessed.  MINE is left
# exactly as it was, the merge with the conflicts marked goes to MINE.new, and
# a warning says where -- again at every make, until MINE changes.  Copy
# MINE.new over it once the <<<<<<< blocks are sorted out, or edit MINE by
# hand; the next make takes it from there.
#
# A clean merge that changes anything keeps the previous copy as MINE.bak.
#
# The first run in a tree built before this existed has no BASE.  The one it
# started from is found in git history: the committed elpis.conf closest to
# MINE, which for a copy nobody edited is the exact one.  Outside a git
# checkout nothing can be found, so nothing is merged that time; BASE is
# recorded and from then on updates merge.
#
# Never fails the build: a config that could not be merged is still the one
# that was working.

SHIPPED=$1
MINE=$2
BASE=$3

[ -n "$SHIPPED" ] && [ -n "$MINE" ] && [ -n "$BASE" ] || {
    echo "usage: conf-merge.sh SHIPPED MINE BASE" >&2
    exit 2
}

TMP=$MINE.merge.$$
CAND=$MINE.cand.$$
trap 'rm -f "$TMP" "$CAND"' EXIT HUP INT TERM

say()  { echo "  $*"; }
warn() { echo "  WARNING: $*"; }

# ---- first build: seed --------------------------------------------------
if [ ! -f "$MINE" ]; then
    cp "$SHIPPED" "$MINE" && cp "$SHIPPED" "$BASE" || exit 1
    say "seeded $MINE from the shipped defaults"
    exit 0
fi

# ---- no record of the defaults MINE came from: look for them -------------
if [ ! -f "$BASE" ]; then
    bestn=
    history=0
    try() {
        n=$(diff "$1" "$MINE" | grep -c '^[<>]')
        if [ -z "$bestn" ] || [ "$n" -lt "$bestn" ]; then
            bestn=$n
            cp "$1" "$BASE"
        fi
    }
    try "$SHIPPED"
    if [ "$bestn" != 0 ] && git rev-parse --git-dir >/dev/null 2>&1; then
        for c in $(git rev-list HEAD -- "$SHIPPED" 2>/dev/null); do
            git show "$c:$SHIPPED" > "$CAND" 2>/dev/null || continue
            history=1
            try "$CAND"
            [ "$bestn" = 0 ] && break
        done
    fi
    if [ "$history" = 0 ] && [ "$bestn" != 0 ]; then
        say "$MINE: no git history to tell which shipped defaults it started"
        say "from, so nothing is merged this time; later changes to $SHIPPED"
        say "will be"
    elif ! cmp -s "$BASE" "$SHIPPED"; then
        if [ "$bestn" = 0 ]; then
            say "$MINE: started from an earlier $SHIPPED, found in git history"
        else
            say "$MINE: the closest earlier $SHIPPED in git history differs"
            say "from it by $bestn lines -- taking those as your edits"
        fi
    fi
fi

# ---- a conflict reported last time ----------------------------------------
# Resolved once MINE has been written since the warning and no marker is left
# in it.  Written, not changed: keeping your own side of every conflict leaves
# the content as it was.  Without this, keeping your side of a line would
# conflict again at every make, for ever.
if [ -f "$BASE.pending" ]; then
    if [ -n "$(find "$MINE" -newer "$BASE.pending" 2>/dev/null)" ]; then
        if grep -q -e '^<<<<<<< ' -e '^=======$' -e '^>>>>>>> ' "$MINE"; then
            echo
            warn "$MINE still has conflict markers in it.  Elpis reads those"
            warn "lines as bad settings and skips them.  Remove the markers."
            echo
            exit 0
        fi
        mv "$BASE.pending" "$BASE"
        rm -f "$MINE.new"
        say "$MINE was saved after the conflict was reported: taken as resolved"
        say "(where you kept your own lines, the new defaults were not applied)"
    else
        rm -f "$BASE.pending"
    fi
fi

# ---- nothing new shipped --------------------------------------------------
if cmp -s "$SHIPPED" "$BASE"; then
    touch "$BASE"
    exit 0
fi

# ---- merge ----------------------------------------------------------------
if command -v diff3 >/dev/null 2>&1; then
    diff3 -m -L "$MINE (yours)" -L "$BASE (defaults you started from)" \
          -L "$SHIPPED (new defaults)" "$MINE" "$BASE" "$SHIPPED" > "$TMP"
    rc=$?
elif command -v git >/dev/null 2>&1; then
    cp "$MINE" "$TMP"
    git merge-file --diff3 -L "$MINE (yours)" \
        -L "$BASE (defaults you started from)" -L "$SHIPPED (new defaults)" \
        "$TMP" "$BASE" "$SHIPPED"
    rc=$?
    [ "$rc" -gt 0 ] && [ "$rc" -lt 128 ] && rc=1
else
    warn "no diff3 and no git: $MINE was not merged with the new defaults"
    warn "compare it with $SHIPPED yourself"
    exit 0
fi

case $rc in
0)
    if cmp -s "$TMP" "$MINE"; then
        cp "$SHIPPED" "$BASE"
        exit 0
    fi
    added=$(diff "$MINE" "$TMP" | grep -c '^>')
    removed=$(diff "$MINE" "$TMP" | grep -c '^<')
    cp -p "$MINE" "$MINE.bak" || exit 0
    # Rewritten in place: the file keeps its owner and mode.
    cat "$TMP" > "$MINE" || { cp -p "$MINE.bak" "$MINE"; exit 0; }
    cp "$SHIPPED" "$BASE"
    rm -f "$MINE.new"
    say "merged the new shipped defaults into $MINE (+$added -$removed lines);"
    say "your edits are kept, and the previous copy is $MINE.bak"
    diff "$MINE.bak" "$MINE" | sed -n 's/^> \([a-z0-9-]*\):.*/\1/p' |
        sort -u | while read -r key; do
            say "  new setting: $key"
        done
    ;;
1)
    mv "$TMP" "$MINE.new"
    cp "$SHIPPED" "$BASE.pending"
    n=$(grep -c '^<<<<<<< ' "$MINE.new")
    echo
    warn "the new shipped defaults in $SHIPPED conflict with"
    warn "your edits in $MINE, in $n place(s)."
    warn "$MINE is unchanged and still in use."
    warn "The merge, with the conflicts marked, is $MINE.new"
    warn "-- see line(s) $(grep -n '^<<<<<<< ' "$MINE.new" | cut -d: -f1 | tr '\n' ' ')"
    warn "Keep what you want between <<<<<<< and >>>>>>>, remove the"
    warn "markers, and copy it over $MINE; or edit $MINE by"
    warn "hand.  Saving it tells the next make that this is dealt with."
    echo
    ;;
*)
    warn "could not merge $MINE with $SHIPPED (merge tool said $rc);"
    warn "it is unchanged -- compare the two yourself"
    ;;
esac
exit 0
