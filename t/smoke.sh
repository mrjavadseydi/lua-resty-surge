#!/bin/sh
# Phase 3 smoke test. Starts OpenResty, checks the 3-line install, a block
# that shows up on every worker, path allow, fail-open, and dry-run.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OR=${OR:-openresty}
PORT=${PORT:-18181}
PREFIX=${PREFIX:-/tmp/surge-smoke}
DRY_PORT=${DRY_PORT:-18182}
DRY_PREFIX=${DRY_PREFIX:-/tmp/surge-smoke-dry}

if ! command -v "$OR" >/dev/null 2>&1; then
    echo "openresty is not on PATH. From the repo root run: make smoke" >&2
    exit 1
fi

write_conf() {
    prefix=$1
    port=$2
    dry=$3
    mkdir -p "$prefix/logs" "$prefix/conf" "$prefix/export"
    # Workers run as nobody; they write the export.
    chmod 777 "$prefix/export"
    cat > "$prefix/conf/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log info;
pid logs/nginx.pid;
daemon off;
env SURGE_DRY_RUN;

events { worker_connections 1024; }

http {
    lua_package_path "$ROOT/lib/?.lua;;";
    lua_shared_dict surge 64m;

    init_worker_by_lua_block {
        require("resty.surge").start({
            allow = { "/health" },
            dry_run = $dry,
            -- gcra_burst 100 so a per-worker burst (2 x 100) would show.
            advanced = { test_hooks = true, tick = 0.25, pow_bits = 8, gcra_burst = 100 },
            export_path = "$prefix/export/blocks.txt",
            on_decision = function(d)
                -- A slow hook. It must not undo a block published meanwhile.
                if d.target == "127.0.0.9" then ngx.sleep(1.5) end
                ngx.log(ngx.WARN, "surge-hook: ", d.action, " ", d.target, " ", d.reason)
            end,
        })
    }

    server {
        listen 127.0.0.1:$port;

        location = /_surge {
            content_by_lua_block { require("resty.surge").status() }
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

        location = /_host {
            content_by_lua_block {
                local ok, err = require("resty.surge")._publish({
                    -- Mixed case on purpose: ngx.var.host is lowercase.
                    { host = "Victim.test", action = "challenge",
                      reason = "host_surge", message = "site challenge" },
                })
                ngx.say(ok and "published" or err)
            }
        }

        # A token and a nonce that solves it, as the page's script would.
        location = /_pow {
            content_by_lua_block {
                local ch = require "resty.surge.challenge"
                local sha = require "resty.surge.sha256"
                local t = ch.token(ngx.var.binary_remote_addr, ngx.now(), 60, 8)
                for n = 0, 1000000 do
                    if sha.leading_zeros(sha.sha256(t .. n)) >= 8 then
                        return ngx.print(t, " ", n)
                    end
                end
            }
        }

        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.say("ok") }
        }
    }
}
EOF
}

stop() {
    prefix=$1
    if [ -f "$prefix/logs/nginx.pid" ]; then
        kill "$(cat "$prefix/logs/nginx.pid")" 2>/dev/null || true
        sleep 0.2
    fi
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
    echo "server on $port did not come up" >&2
    return 1
}

fail() {
    echo "FAIL $1" >&2
    echo "---- error log ----" >&2
    tail -40 "$2/logs/error.log" >&2 || true
    exit 1
}

rm -rf "$PREFIX" "$DRY_PREFIX"
write_conf "$PREFIX" "$PORT" false
"$OR" -p "$PREFIX" >/tmp/surge-smoke.out 2>&1 &
trap 'stop "$PREFIX"; stop "$DRY_PREFIX"' EXIT
wait_port "$PORT" || fail "startup" "$PREFIX"

body=$(curl -sf "http://127.0.0.1:$PORT/") || fail "zero-config allow" "$PREFIX"
echo "$body" | grep -q ok || fail "body was not ok: $body" "$PREFIX"

status=$(curl -sf "http://127.0.0.1:$PORT/_surge") || fail "status" "$PREFIX"
echo "$status" | grep -q '"mode":"normal"' || fail "status mode: $status" "$PREFIX"
echo "$status" | grep -q '"decisions":\[\]' || fail "empty decisions is not []: $status" "$PREFIX"

page=$(curl -sf -D - "http://127.0.0.1:$PORT/_surge?format=html") || fail "dashboard" "$PREFIX"
echo "$page" | grep -qi "Content-Type: text/html" || fail "dashboard type" "$PREFIX"
echo "$page" | grep -qi "Content-Security-Policy: default-src 'none'" || fail "dashboard csp" "$PREFIX"
echo "$page" | grep -q "<title>surge status</title>" || fail "dashboard body" "$PREFIX"

curl -sf "http://127.0.0.1:$PORT/_block" | grep -q published || fail "publish" "$PREFIX"
sleep 0.8

headers=$(curl -sS -D - -o /tmp/surge-body.txt "http://127.0.0.1:$PORT/login")
echo "$headers" | grep -q "403" || fail "expected 403: $headers" "$PREFIX"
echo "$headers" | grep -qi "X-Surge-Incident: srg-" || fail "incident header: $headers" "$PREFIX"
echo "$headers" | grep -qi "X-Surge-Reason: manual" || fail "reason header: $headers" "$PREFIX"
grep -q srg- /tmp/surge-body.txt || fail "body missing incident" "$PREFIX"

json=$(curl -sS -H 'Accept: application/json' "http://127.0.0.1:$PORT/login")
echo "$json" | grep -q incident || fail "json body: $json" "$PREFIX"

health=$(curl -sf "http://127.0.0.1:$PORT/health") || fail "allowlisted path was blocked" "$PREFIX"
echo "$health" | grep -q ok || fail "health body: $health" "$PREFIX"

# Several hits so both workers are exercised after the snapshot tick.
i=0
while [ "$i" -lt 20 ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/again")
    if [ "$code" != "403" ]; then
        fail "worker missed the block ($code)" "$PREFIX"
    fi
    i=$((i + 1))
done

incident=$(echo "$headers" | awk 'tolower($1)=="x-surge-incident:" { print $2 }' | tr -d '\r')
if [ -z "$incident" ]; then
    fail "no incident to unblock" "$PREFIX"
fi
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?unblock=$incident" | grep -q unblock || fail "unblock" "$PREFIX"
sleep 0.8
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/")
if [ "$code" != "200" ]; then
    fail "unblock did not clear the block ($code)" "$PREFIX"
fi

# Every worker reports the leader's numbers, not nulls.
i=0
while [ "$i" -lt 10 ]; do
    s=$(curl -sf "http://127.0.0.1:$PORT/_surge") || fail "status" "$PREFIX"
    echo "$s" | grep -q '"rps":[0-9]' || fail "status without rps: $s" "$PREFIX"
    i=$((i + 1))
done

# Block and unblock by address. Both go through the leader's queue.
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/_surge?block=bad")
[ "$code" = "400" ] || fail "bad cidr was accepted ($code)" "$PREFIX"
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?block=127.0.0.1&ttl=60" | grep -q '"op":"block"' \
    || fail "block by address" "$PREFIX"
sleep 0.8
s=$(curl -sf "http://127.0.0.1:$PORT/_surge")
echo "$s" | grep -q '"target":"127.0.0.1"' || fail "status target: $s" "$PREFIX"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/")
[ "$code" = "403" ] || fail "block by address did not apply ($code)" "$PREFIX"
# A queued block is a new decision: one log line and one on_decision call.
grep -q "surge-hook: block 127.0.0.1 manual" "$PREFIX/logs/error.log" \
    || fail "on_decision not called for a queued block" "$PREFIX"
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?unblock=127.0.0.1" | grep -q unblock \
    || fail "unblock by address" "$PREFIX"
sleep 0.8
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/")
[ "$code" = "200" ] || fail "unblock by address did not clear ($code)" "$PREFIX"
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?block=127.0.0.9&ttl=60" >/dev/null
sleep 0.5
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?block=127.0.0.10&ttl=60" >/dev/null
sleep 2.5
s=$(curl -sf "http://127.0.0.1:$PORT/_surge")
echo "$s" | grep -q '"target":"127.0.0.10"' || fail "slow on_decision undid a block: $s" "$PREFIX"
grep -q "surge-hook: block 127.0.0.9 manual" "$PREFIX/logs/error.log" \
    || fail "slow on_decision not called" "$PREFIX"
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?unblock=127.0.0.9" >/dev/null
curl -sf -X POST "http://127.0.0.1:$PORT/_surge?unblock=127.0.0.10" >/dev/null

curl -sf "http://127.0.0.1:$PORT/x?surge_fail=1" >/dev/null || fail "fail-open returned an error" "$PREFIX"
sleep 0.6
grep -q "internal error" "$PREFIX/logs/error.log" || fail "fail-open was not logged" "$PREFIX"

# A site-wide challenge: other sites pass, the API is rate-held instead of
# 403, and an address that keeps ignoring the page is blocked and exported.
# Last in this block because it ends with 127.0.0.1 blocked.
curl -sf "http://127.0.0.1:$PORT/_host" | grep -q published || fail "host publish" "$PREFIX"
sleep 0.8
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.test' "http://127.0.0.1:$PORT/")
[ "$code" = "200" ] || fail "other site was denied ($code)" "$PREFIX"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: victim.test' \
    -H 'Accept: application/json' "http://127.0.0.1:$PORT/api")
[ "$code" = "200" ] || fail "api under a site challenge was denied ($code)" "$PREFIX"
# The site rate and burst are the node's: 80 x 2s + 100 = 260. Per worker
# it was 2 x (40 x 2s + 100) = 360.
out=$(wrk -t1 -c1 -d2s -H 'Host: victim.test' -H 'Accept: application/json' \
    "http://127.0.0.1:$PORT/api")
total=$(echo "$out" | awk '/requests in/ { print $1 }')
denied=$(echo "$out" | awk '/Non-2xx/ { print $5 }')
passed=$((total - ${denied:-0}))
[ "$passed" -ge 230 ] && [ "$passed" -le 300 ] \
    || fail "site limit let $passed of $total through in 2s" "$PREFIX"
page=$(curl -s -H 'Host: victim.test' "http://127.0.0.1:$PORT/")
echo "$page" | grep -q '/.srg-pow.v1.js' || fail "no challenge page: $page" "$PREFIX"
[ "$(printf %s "$page" | wc -c)" -lt 400 ] || fail "challenge page is too big" "$PREFIX"
# The script is one cached static file, served only while a challenge is live.
js=$(curl -sS -D - -H 'Host: victim.test' "http://127.0.0.1:$PORT/.srg-pow.v1.js")
echo "$js" | grep -qi "Cache-Control: public" || fail "script not cacheable: $js" "$PREFIX"
echo "$js" | grep -q "window.srg" || fail "script body: $js" "$PREFIX"
# A browser's fetch cannot run the page, so it is not ignoring it.
i=0
while [ "$i" -lt 12 ]; do
    curl -s -o /dev/null -H 'Host: victim.test' -H 'Sec-Fetch-Dest: empty' \
        "http://127.0.0.1:$PORT/"
    i=$((i + 1))
done
# A solve takes one page back. 1 page so far, minus 1, plus 9 stays under 10.
set -- $(curl -sf "http://127.0.0.1:$PORT/_pow")
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: victim.test' \
    "http://127.0.0.1:$PORT/?srg_ch=$1&srg_pow=$2")
[ "$code" = "204" ] || fail "solve was not accepted ($code)" "$PREFIX"
i=0
while [ "$i" -lt 9 ]; do
    curl -s -o /dev/null -H 'Host: victim.test' "http://127.0.0.1:$PORT/"
    i=$((i + 1))
done
sleep 0.8
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.test' "http://127.0.0.1:$PORT/" || true)
[ "$code" = "200" ] || fail "blocked despite fetches and a solve ($code)" "$PREFIX"
curl -s -o /dev/null -H 'Host: victim.test' "http://127.0.0.1:$PORT/"
sleep 0.8
# A bot that ignored the page gets a closed socket (444), not a body.
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: other.test' "http://127.0.0.1:$PORT/" || true)
[ "$code" = "000" ] || fail "ignored challenge not closed ($code)" "$PREFIX"
curl -sf "http://127.0.0.1:$PORT/_surge" | grep -q '"reason":"challenge_ignored"' \
    || fail "block reason missing from status" "$PREFIX"
grep -q "^v4 32 127.0.0.1 " "$PREFIX/export/blocks.txt" || fail "block not exported" "$PREFIX"
grep -q "surge: Blocked 127.0.0.1: ignored the challenge page" "$PREFIX/logs/error.log" \
    || fail "challenge_ignored block not logged" "$PREFIX"
grep -q "surge-hook: block 127.0.0.1 challenge_ignored" "$PREFIX/logs/error.log" \
    || fail "on_decision not called for challenge_ignored" "$PREFIX"
# The script path is not a way around a block while a challenge is live.
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: victim.test' \
    "http://127.0.0.1:$PORT/.srg-pow.v1.js" || true)
[ "$code" = "000" ] || fail "blocked address got the script ($code)" "$PREFIX"

echo "block path ok"

# Dry-run: same block, nothing denied, the would-be decision is logged.
write_conf "$DRY_PREFIX" "$DRY_PORT" true
SURGE_DRY_RUN=1 "$OR" -p "$DRY_PREFIX" >/tmp/surge-smoke-dry.out 2>&1 &
wait_port "$DRY_PORT" || fail "dry startup" "$DRY_PREFIX"
curl -sf "http://127.0.0.1:$DRY_PORT/_block" | grep -q published || fail "dry publish" "$DRY_PREFIX"
sleep 0.8
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$DRY_PORT/")
if [ "$code" != "200" ]; then
    fail "dry-run denied the request ($code)" "$DRY_PREFIX"
fi
grep -q "dry-run would block" "$DRY_PREFIX/logs/error.log" || fail "dry-run did not log" "$DRY_PREFIX"

echo "smoke ok"
