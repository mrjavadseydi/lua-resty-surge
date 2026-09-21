#!/bin/sh
# Read the file surge writes at export_path and refresh an nftables set.
# Each line is: family bits address ttl incident
# Lua does not call nft. Run this from cron or a timer.
set -eu

FILE=${1:-/var/run/surge/blocks.txt}
TABLE=${TABLE:-inet surge}
SET4=${SET4:-block4}
SET6=${SET6:-block6}

[ -f "$FILE" ] || exit 0

nft list table "$TABLE" >/dev/null 2>&1 || nft add table "$TABLE"
nft list set "$TABLE" "$SET4" >/dev/null 2>&1 \
    || nft add set "$TABLE" "$SET4" '{ type ipv4_addr; flags timeout; }'
nft list set "$TABLE" "$SET6" >/dev/null 2>&1 \
    || nft add set "$TABLE" "$SET6" '{ type ipv6_addr; flags timeout; }'

nft flush set "$TABLE" "$SET4"
nft flush set "$TABLE" "$SET6"

while read -r family bits addr ttl incident; do
    [ -n "$family" ] || continue
    case "$family" in
        v4) set=$SET4 ;;
        v6) set=$SET6 ;;
        *) continue ;;
    esac
    elem=$addr
    if [ "$bits" != "32" ] && [ "$bits" != "128" ]; then
        elem="$addr/$bits"
    fi
    nft add element "$TABLE" "$set" "{ $elem timeout ${ttl}s }"
done < "$FILE"
