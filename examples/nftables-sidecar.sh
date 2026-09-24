#!/bin/sh
# Read the file surge writes at export_path and refresh an nftables set.
# Each line is: family bits address ttl incident
# Lua does not call nft.
#
#   nftables-sidecar.sh --watch [FILE]   check every second, apply on change
#   nftables-sidecar.sh [FILE]           apply once
#
# Run --watch under systemd, not cron: a minute of cron delay is a minute
# of blocked clients still costing a TLS handshake each. The file is
# applied when it changed, or when the table is gone (nft flush ruleset, a
# reload of nftables.conf). The ttl in each line was counted when the file
# was written, so each element gets ttl minus the file's age: re-applying an
# old file never extends a block.
#
# Sets use "flags interval, timeout" so /24 and /64 elements are legal.
# flush and add run as one nft -f transaction. A rejected element leaves
# the previous set in place instead of emptying it.
set -eu

WATCH=0
if [ "${1:-}" = "--watch" ]; then
    WATCH=1
    shift
fi
FILE=${1:-/var/run/surge/blocks.txt}
FAMILY=${FAMILY:-inet}
TABLE=${TABLE:-surge}
SET4=${SET4:-block4}
SET6=${SET6:-block6}
LAST=${LAST:-$FILE.applied}

snap=
batch=
trap 'rm -f "$snap" "$batch"' EXIT
trap 'exit 143' INT TERM

ensure_set() {
    name=$1
    typ=$2
    if nft list set "$FAMILY" "$TABLE" "$name" >/dev/null 2>&1; then
        if ! nft list set "$FAMILY" "$TABLE" "$name" | grep -q interval; then
            nft delete set "$FAMILY" "$TABLE" "$name"
        fi
    fi
    nft list set "$FAMILY" "$TABLE" "$name" >/dev/null 2>&1 \
        || nft add set "$FAMILY" "$TABLE" "$name" \
            "{ type $typ; flags interval, timeout; }"
}

apply_file() {
    [ -f "$FILE" ] || return 0
    # Copy first: surge may rename a new file in while this runs.
    snap=$(mktemp)
    cp -p "$FILE" "$snap"
    if [ -f "$LAST" ] && cmp -s "$snap" "$LAST" \
        && nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1; then
        rm -f "$snap"
        return 0
    fi
    age=$(( $(date +%s) - $(stat -c %Y "$snap") ))

    nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1 || nft add table "$FAMILY" "$TABLE"
    ensure_set "$SET4" ipv4_addr
    ensure_set "$SET6" ipv6_addr

    batch=$(mktemp)
    {
        echo "flush set $FAMILY $TABLE $SET4"
        echo "flush set $FAMILY $TABLE $SET6"
        while read -r family bits addr ttl incident; do
            [ -n "${family:-}" ] || continue
            case "$family" in
                v4) set=$SET4 ;;
                v6) set=$SET6 ;;
                *) continue ;;
            esac
            case "$ttl" in
                ''|*[!0-9]*) continue ;;
            esac
            ttl=$((ttl - age))
            if [ "$ttl" -le 0 ]; then
                continue
            fi
            elem=$addr
            if [ "$bits" != "32" ] && [ "$bits" != "128" ]; then
                elem="$addr/$bits"
            fi
            echo "add element $FAMILY $TABLE $set { $elem timeout ${ttl}s }"
        done < "$snap"
    } > "$batch"

    rc=0
    nft -f "$batch" || rc=$?
    rm -f "$batch"
    batch=
    if [ "$rc" -ne 0 ]; then
        rm -f "$snap"
        return "$rc"
    fi
    mv "$snap" "$LAST"
    snap=
}

if [ "$WATCH" = 1 ]; then
    while :; do
        apply_file || true
        sleep 1
    done
fi
apply_file
