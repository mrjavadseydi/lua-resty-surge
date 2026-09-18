#!/bin/sh
# A file feed blocks the listed client and yields to a path allow.
# Rewriting the file is picked up on the worker poll, without a restart.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OR=${OR:-openresty}
PORT=${PORT:-18183}
PREFIX=${PREFIX:-/tmp/surge-feeds-nginx}
FEED=${FEED:-/tmp/surge-feeds-nginx/local.list}

if ! command -v "$OR" >/dev/null 2>&1; then
    echo "openresty is not on PATH. From the repo root run: make feeds" >&2
    exit 1
fi

fail() {
    echo "FAIL $1" >&2
    tail -40 "$PREFIX/logs/error.log" >&2 || true
    exit 1
}

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf"
printf '10.0.0.0/8\n' > "$FEED"

cat > "$PREFIX/conf/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log info;
pid logs/nginx.pid;
daemon off;
events { worker_connections 256; }
http {
    lua_package_path "$ROOT/lib/?.lua;;";
    lua_shared_dict surge 64m;
    init_worker_by_lua_block {
        require("resty.surge").start({
            allow = { "/health" },
            feed_dir = "$PREFIX",
            feeds = { { name = "localbad", path = "$FEED" } },
            advanced = { feed_poll = 0.25, tick = 0.25 },
        })
    }
    server {
        listen 127.0.0.1:$PORT;
        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.say("ok") }
        }
    }
}
EOF

"$OR" -p "$PREFIX" >/tmp/surge-feeds.out 2>&1 &
trap 'if [ -f "$PREFIX/logs/nginx.pid" ]; then kill "$(cat "$PREFIX/logs/nginx.pid")" 2>/dev/null || true; fi' EXIT

i=0
while [ "$i" -lt 50 ]; do
    if curl -sf -o /dev/null "http://127.0.0.1:$PORT/health"; then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done
curl -sf -o /dev/null "http://127.0.0.1:$PORT/health" || fail "startup"

code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/")
if [ "$code" != "200" ]; then
    fail "unlisted client was blocked ($code)"
fi

printf '10.0.0.0/8\n127.0.0.1/32\n' > "$FEED"
sleep 1

headers=$(curl -sS -D - -o /tmp/surge-feed-body.txt "http://127.0.0.1:$PORT/")
echo "$headers" | grep -q "403" || fail "expected 403 after reload: $headers"
echo "$headers" | grep -qi "X-Surge-Reason: reputation:localbad" || fail "reason header: $headers"
echo "$headers" | grep -qi "X-Surge-Incident: srg-feed-localbad" || fail "incident header: $headers"
grep -q srg-feed-localbad /tmp/surge-feed-body.txt || fail "body missing incident"

health=$(curl -sf "http://127.0.0.1:$PORT/health") || fail "allowlisted path blocked"
echo "$health" | grep -q ok || fail "health body"

echo "feeds ok"
