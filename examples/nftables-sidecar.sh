#!/bin/sh
# Read the file surge writes at export_path and refresh an nftables set.
# Each line is: family bits address ttl incident
# Lua does not call nft. Run this from cron or a timer.
#
# Sets use "flags interval, timeout" so /24 and /64 elements are legal.
# flush and add run as one nft -f transaction. A rejected element leaves
# the previous set in place instead of emptying it.
set -eu

FILE=${1:-/var/run/surge/blocks.txt}
FAMILY=${FAMILY:-inet}
TABLE=${TABLE:-surge}
SET4=${SET4:-block4}
SET6=${SET6:-block6}

[ -f "$FILE" ] || exit 0

nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1 || nft add table "$FAMILY" "$TABLE"

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

ensure_set "$SET4" ipv4_addr
ensure_set "$SET6" ipv6_addr

batch=$(mktemp)
trap 'rm -f "$batch"' EXIT
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
        if [ "$ttl" -le 0 ]; then
            continue
        fi
        elem=$addr
        if [ "$bits" != "32" ] && [ "$bits" != "128" ]; then
            elem="$addr/$bits"
        fi
        echo "add element $FAMILY $TABLE $set { $elem timeout ${ttl}s }"
    done < "$FILE"
} > "$batch"

nft -f "$batch"
