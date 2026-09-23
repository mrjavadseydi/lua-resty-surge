#!/bin/sh
# Phase 6: fingerprint, proof-of-work cookie, JA4 hand-off, early().
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OR=${OR:-openresty}
PREFIX=${PREFIX:-/tmp/surge-phase6}
TRUST=${TRUST:-/tmp/surge-phase6-trust}
ALLOW=${ALLOW:-/tmp/surge-phase6-allow}
HTTP=${HTTP:-18450}
SSL=${SSL:-18451}
H2=${H2:-18452}
TPORT=${TPORT:-18453}

if ! command -v "$OR" >/dev/null 2>&1; then
    echo "openresty is not on PATH. From the repo root run: make phase6" >&2
    exit 1
fi

stop() {
    prefix=$1
    if [ -f "$prefix/logs/nginx.pid" ]; then
        kill "$(cat "$prefix/logs/nginx.pid")" 2>/dev/null || true
        sleep 0.2
    fi
}

fail() {
    echo "FAIL $1" >&2
    echo "---- error log ----" >&2
    tail -50 "$2/logs/error.log" >&2 || true
    exit 1
}

wait_port() {
    port=$1
    i=0
    while [ "$i" -lt 50 ]; do
        if curl -sf -o /dev/null "http://127.0.0.1:$port/_surge"; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

write_conf() {
    prefix=$1
    trusted=$2
    http=$3
    ssl=$4
    h2=$5
    allow_extra=${6:-}
    mkdir -p "$prefix/logs" "$prefix/conf"
    if [ ! -f "$prefix/conf/cert.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout "$prefix/conf/key.pem" \
            -out "$prefix/conf/cert.pem" -days 1 -nodes -subj /CN=localhost \
            >/dev/null 2>&1
    fi
    cat > "$prefix/conf/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log info;
pid logs/nginx.pid;
daemon off;
events { worker_connections 256; }
http {
    lua_package_path "$ROOT/lib/?.lua;;";
    lua_shared_dict surge 64m;
    init_worker_by_lua_block {
        require("resty.surge").start({
            allow = { "/health"$allow_extra },
            api = { "/api/" },
            trusted_proxies = $trusted,
            advanced = { test_hooks = true, tick = 0.25, pow_bits = 8, pow_ttl = 120 },
        })
    }
    server {
        listen 127.0.0.1:$http;
        location = /_surge {
            content_by_lua_block { require("resty.surge").status() }
        }
        location = /_challenge {
            content_by_lua_block {
                local ok, err = require("resty.surge")._publish({
                    { cidr = "127.0.0.1/32", action = "challenge",
                      reason = "heavy_hitter", message = "prove you are a browser",
                      manual = false },
                })
                ngx.say(ok and "published" or err)
            }
        }
        location = /_block {
            content_by_lua_block {
                local ok, err = require("resty.surge")._publish({
                    { cidr = "127.0.0.1/32", action = "block",
                      reason = "manual", message = "manual block" },
                })
                ngx.say(ok and "published" or err)
            }
        }
        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.say("ok") }
        }
    }
    server {
        listen 127.0.0.1:$h2;
        http2 on;
        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.say("ok") }
        }
    }
    server {
        listen 127.0.0.1:$ssl ssl;
        ssl_certificate $prefix/conf/cert.pem;
        ssl_certificate_key $prefix/conf/key.pem;
        ssl_client_hello_by_lua_block { require("resty.surge").early() }
        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.say("ok") }
        }
    }
}
EOF
}

rm -rf "$PREFIX" "$TRUST" "$ALLOW"
write_conf "$PREFIX" "{}" "$HTTP" "$SSL" "$H2"
"$OR" -p "$PREFIX" >/tmp/surge-phase6.out 2>&1 &
trap 'stop "$PREFIX"; stop "$TRUST"; stop "$ALLOW"' EXIT
wait_port "$HTTP" || fail "startup" "$PREFIX"

curl -sf "http://127.0.0.1:$HTTP/" | grep -q ok || fail "allow" "$PREFIX"

fp=$(curl -sS -D - -o /dev/null "http://127.0.0.1:$HTTP/?surge_fp=1" \
    | awk 'tolower($1)=="x-surge-fp:" { print $2 }' | tr -d '\r')
echo "$fp" | grep -q '^1' || fail "http/1 fingerprint: $fp" "$PREFIX"

if ! curl -V | grep -q HTTP2; then
    fail "curl was built without HTTP/2" "$PREFIX"
fi
h2=$(curl -sS --http2-prior-knowledge -D - -o /dev/null \
    "http://127.0.0.1:$H2/?surge_fp=1" \
    | awk 'tolower($1)=="x-surge-fp:" { print $2 }' | tr -d '\r')
echo "$h2" | grep -q '^2' || fail "http/2 fingerprint: $h2" "$PREFIX"

ja=$(curl -sk --resolve "localhost:${SSL}:127.0.0.1" -D - -o /dev/null \
    "https://localhost:${SSL}/?surge_fp=1" \
    | awk 'tolower($1)=="x-surge-ja4:" { print $2 }' | tr -d '\r')
echo "$ja" | grep -Eq '^t1[23]d[0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$' \
    || fail "ja4: $ja" "$PREFIX"
ja2=$(curl -sk --resolve "localhost:${SSL}:127.0.0.1" -D - -o /dev/null \
    "https://localhost:${SSL}/?surge_fp=1" \
    | awk 'tolower($1)=="x-surge-ja4:" { print $2 }' | tr -d '\r')
if [ "$ja" != "$ja2" ]; then
    fail "ja4 changed between requests ($ja vs $ja2)" "$PREFIX"
fi

curl -sf "http://127.0.0.1:$HTTP/_challenge" | grep -q published \
    || fail "publish challenge" "$PREFIX"
sleep 0.8

api=$(curl -sS -D - -H 'Accept: application/json' "http://127.0.0.1:$HTTP/api/x")
echo "$api" | grep -q " 403" || fail "api challenge was not denied: $api" "$PREFIX"
echo "$api" | grep -q '<script' && fail "api client received the page" "$PREFIX"

page=$(curl -sS "http://127.0.0.1:$HTTP/")
echo "$page" | grep -q "Checking your browser" || fail "no challenge page" "$PREFIX"
token=$(printf '%s' "$page" | sed -n 's/.*var srg=\["\([^"]*\)".*/\1/p')
if [ -z "$token" ]; then
    fail "challenge token missing" "$PREFIX"
fi

nonce=$(resty -e "
local c = require 'resty.surge.challenge'
local bin = string.char(127, 0, 0, 1)
local token = [[$token]]
for i = 0, 20000 do
    local n = tostring(i)
    if c.proof_ok(token, n, 8, ngx.now(), bin, 120) then
        io.write(n)
        break
    end
end
")
if [ -z "$nonce" ]; then
    fail "proof of work produced no nonce" "$PREFIX"
fi

hdr=$(curl -sS -D - -o /dev/null \
    "http://127.0.0.1:$HTTP/?srg_pow=${nonce}&srg_ch=${token}")
echo "$hdr" | grep -q " 204" || fail "pow was not accepted: $hdr" "$PREFIX"
cookie=$(printf '%s\n' "$hdr" | awk 'tolower($1)=="set-cookie:" { print $2 }' \
    | tr -d '\r' | cut -d';' -f1)
echo "$cookie" | grep -q '^srg_pow=' || fail "cookie missing: $hdr" "$PREFIX"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $cookie" \
    "http://127.0.0.1:$HTTP/")
if [ "$code" != "200" ]; then
    fail "solved cookie was rejected ($code)" "$PREFIX"
fi

curl -sf "http://127.0.0.1:$HTTP/_block" | grep -q published || fail "publish block" "$PREFIX"
sleep 0.8
closed=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
    "https://127.0.0.1:${SSL}/" || true)
if [ "$closed" != "000" ]; then
    fail "early() did not close the handshake ($closed)" "$PREFIX"
fi

echo "direct path ok"
stop "$PREFIX"

write_conf "$TRUST" '{ "127.0.0.1/32" }' "$TPORT" "$((SSL + 10))" "$((H2 + 10))"
"$OR" -p "$TRUST" >/tmp/surge-phase6-trust.out 2>&1 &
wait_port "$TPORT" || fail "trusted startup" "$TRUST"
curl -sf "http://127.0.0.1:$TPORT/_block" | grep -q published \
    || fail "trusted publish" "$TRUST"
sleep 0.8
kept=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
    "https://127.0.0.1:$((SSL + 10))/" || true)
if [ "$kept" != "403" ]; then
    fail "early() closed a trusted proxy ($kept)" "$TRUST"
fi
stop "$TRUST"

# An allowlisted address is also on the manual block list. The handshake
# must complete; protect() then allows the address.
write_conf "$ALLOW" "{}" 18470 18471 18472 ', "127.0.0.1/32"'
"$OR" -p "$ALLOW" >/tmp/surge-phase6-allow.out 2>&1 &
wait_port 18470 || fail "allow startup" "$ALLOW"
curl -sf "http://127.0.0.1:18470/_block" | grep -q published \
    || fail "allow publish" "$ALLOW"
sleep 0.8
opened=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
    "https://127.0.0.1:18471/" || true)
if [ "$opened" != "200" ]; then
    fail "early() closed an allowlisted address ($opened)" "$ALLOW"
fi

echo "phase6 ok"
