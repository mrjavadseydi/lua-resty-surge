#!/bin/sh
# examples/nftables-sidecar.sh against a fake nft that records its calls.
# Checks: ttl minus the file's age, no re-apply of an unchanged file, and a
# re-apply once the table is gone. From the repo root: make sidecar
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/bin"

cat > "$D/bin/nft" <<EOF
#!/bin/sh
echo "\$*" >> "$D/calls"
case "\$*" in
    "list table"*) [ -f "$D/table" ] ;;
    "add table"*) touch "$D/table" ;;
    "list set"*) [ -f "$D/table" ] && echo "flags interval" ;;
    "-f "*) cat "\$2" >> "$D/batches" ;;
esac
EOF
chmod +x "$D/bin/nft"

fail() {
    echo "FAIL $1" >&2
    cat "$D/batches" >&2 2>/dev/null || true
    exit 1
}

run() {
    PATH="$D/bin:$PATH" sh "$ROOT/examples/nftables-sidecar.sh" "$D/blocks.txt"
}

applies() {
    grep -c '^flush set .* block4$' "$D/batches" 2>/dev/null || echo 0
}

echo "v4 32 192.0.2.7 600 srg-1" > "$D/blocks.txt"
touch -d "@$(( $(date +%s) - 100 ))" "$D/blocks.txt"

run
[ "$(applies)" = 1 ] || fail "first run did not apply"
# 600s written 100s ago: 500 left, 499 if the second ticked over.
grep -Eq '192\.0\.2\.7 timeout (500|499)s' "$D/batches" || fail "ttl not aged"

run
[ "$(applies)" = 1 ] || fail "unchanged file was re-applied"

rm -f "$D/table"
run
[ "$(applies)" = 2 ] || fail "lost table was not re-applied"

echo "sidecar ok"
