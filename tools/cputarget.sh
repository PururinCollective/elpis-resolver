#!/bin/sh
#
# cputarget.sh FLAGS... -- the CPU a build is compiled for, as the startup line
# and the status page show it.  $CC is the compiler; FLAGS are the build's
# -march, -mtune and -mcpu options, in order.
#
#   (none)                        generic
#   -march=znver3                 znver3
#   -march=x86-64-v3              x86-64-v3
#   -march=haswell -mtune=znver3  haswell tuned for znver3
#   -march=native                 znver3 (native)
#
# The compiler is asked what it makes of the flags rather than the flags being
# repeated back: that is how "native" becomes the CPU it stands for, and how
# -march=znver3 turns out to tune for znver3 too.  GCC says so outright with
# -Q --help=target; clang shows what it hands its own backend with -###.  If
# neither answers, the flags are reported as written.

march=
mtune=
for f in "$@"; do
    case $f in
    -march=*) march=${f#-march=} ;;
    -mtune=*) mtune=${f#-mtune=} ;;
    -mcpu=*)  march=${f#-mcpu=}; mtune=$march ;;      # Arm: both at once
    esac
done

if [ -z "$march$mtune" ]; then
    echo generic
    exit 0
fi

native=
case "$march $mtune" in
*native*) native=" (native)" ;;
esac

CC=${CC:-cc}
res=$($CC "$@" -Q --help=target 2>/dev/null | awk '
    $1 == "-march=" && NF > 1 { a = $2 }
    $1 == "-mcpu="  && NF > 1 { c = $2 }
    $1 == "-mtune=" && NF > 1 { t = $2 }
    END {
        if (c != "" && c != "generic") a = c
        if (a != "") print a, (t != "" ? t : a)
    }')
if [ -z "$res" ]; then
    res=$($CC "$@" -### -x c -c /dev/null -o /dev/null 2>&1 |
          tr ' ' '\n' | tr -d '"' | awk '
        p == "-target-cpu" { a = $0 }
        p == "-tune-cpu"   { t = $0 }
        { p = $0 }
        END { if (a != "") print a, (t != "" ? t : a) }')
fi

if [ -n "$res" ]; then
    set -- $res
    if [ -n "$march" ]; then
        march=$1
    fi
    mtune=$2
fi

: "${march:=generic}" "${mtune:=generic}"
# The compiler would not say what "native" is, so there is nothing to add.
if [ "$march" = native ] || [ "$mtune" = native ]; then
    native=
fi
if [ "$march" = "$mtune" ] || [ "$mtune" = generic ]; then
    echo "$march$native"
else
    echo "$march tuned for $mtune$native"
fi
