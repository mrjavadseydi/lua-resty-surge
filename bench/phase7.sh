#!/bin/sh
# Phase 7 wrk comparison. The file records whatever this container measured.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OR=${OR:-openresty}
DUR=${DUR:-8s}
OUT="$ROOT/bench/results/phase7.txt"
mkdir -p "$ROOT/bench/results"

start_one() {
    prefix=$1
    "$OR" -p "$prefix" >/tmp/surge-bench7.out 2>&1 &
    echo $!
}

wait_http() {
    port=$1
    path=$2
    i=0
    while [ "$i" -lt 50 ]; do
        if curl -sf -o /dev/null "http://127.0.0.1:$port$path"; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

write_http() {
    prefix=$1
    port=$2
    init=$3
    extra=$4
    mkdir -p "$prefix/logs" "$prefix/conf"
    cat > "$prefix/conf/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log warn;
pid logs/nginx.pid;
daemon off;
events { worker_connections 4096; }
http {
    lua_package_path "$ROOT/lib/?.lua;;";
    lua_shared_dict surge 64m;
    init_worker_by_lua_block { $init }
    server {
        listen 127.0.0.1:$port;
        $extra
    }
}
EOF
}

{
    echo "date $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "uname $(uname -srvm)"
    echo "nproc $(nproc)"
    echo "openresty $(openresty -v 2>&1)"
    echo "workers 2"
    echo "command wrk -t2 -c32 -d$DUR --latency"
    echo "Docker image lua-resty-surge/harness (openresty 1.31.1.1). Numbers are from this container, not a bare-metal host."
    echo
} > "$OUT"

# (a) and (b): normal mode, no decisions.
P=/tmp/surge-bench7-normal
write_http "$P" 18231 \
    'require("resty.surge").start({ advanced = { hard_ip_rps = 1e9, warmup = 3600 } })' \
    'location = /bare { return 200 "ok\n"; }
        location = /open {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }
        location = /gc {
            content_by_lua_block {
                local s = require("resty.surge")
                collectgarbage("collect")
                local before = collectgarbage("count")
                for _ = 1, 20000 do s.protect() end
                local after = collectgarbage("count")
                ngx.say(string.format("%.3f", after - before))
            }
        }'
pid=$(start_one "$P")
wait_http 18231 /bare
{
    echo "===== (a) no module, return 200 ====="
    wrk -t2 -c32 -d"$DUR" --latency "http://127.0.0.1:18231/bare"
    echo
    echo "===== (b) protect, normal mode ====="
    wrk -t2 -c32 -d"$DUR" --latency "http://127.0.0.1:18231/open"
    echo
    echo "===== gc kb over 20000 protect() calls, normal mode ====="
    curl -s "http://127.0.0.1:18231/gc"
    echo
} >> "$OUT"
kill "$pid" 2>/dev/null || true
sleep 0.2

# (c) and (d): attack mode pinned, block only on /blocked.
P=/tmp/surge-bench7-attack
write_http "$P" 18232 \
    'local s = require("resty.surge")
        s.start({ advanced = { test_hooks = true } })
        s._bench_mode("attack")
        s._publish({
            { cidr = "0.0.0.0/0", uri = "/blocked", action = "block",
              reason = "bench", message = "bench block" },
        })' \
    'location = /attack {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }
        location = /blocked {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }
        location = /gc {
            content_by_lua_block {
                local s = require("resty.surge")
                collectgarbage("collect")
                local before = collectgarbage("count")
                for _ = 1, 20000 do s.protect() end
                local after = collectgarbage("count")
                ngx.say(string.format("%.3f", after - before))
            }
        }'
pid=$(start_one "$P")
wait_http 18232 /attack
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:18232/blocked")
if [ "$code" != "403" ]; then
    echo "blocked returned $code" >&2
    tail -20 "$P/logs/error.log" >&2 || true
    exit 1
fi
{
    echo "===== (c) protect, attack mode, request allowed ====="
    echo "mode pinned with _bench_mode; test_hooks required. One wrk client would otherwise be blocked as the attacker."
    wrk -t2 -c32 -d"$DUR" --latency "http://127.0.0.1:18232/attack"
    echo
    echo "===== (d) block decision ====="
    wrk -t2 -c32 -d"$DUR" --latency "http://127.0.0.1:18232/blocked"
    echo
    echo "===== gc kb over 20000 protect() calls, attack mode ====="
    curl -s "http://127.0.0.1:18232/gc"
    echo
} >> "$OUT"
kill "$pid" 2>/dev/null || true
sleep 0.2

# (e) early close. Unscoped block. TLS.
P=/tmp/surge-bench7-early
mkdir -p "$P/logs" "$P/conf"
openssl req -x509 -newkey rsa:2048 -keyout "$P/conf/key.pem" \
    -out "$P/conf/cert.pem" -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1
cat > "$P/conf/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log warn;
pid logs/nginx.pid;
daemon off;
events { worker_connections 4096; }
http {
    lua_package_path "$ROOT/lib/?.lua;;";
    lua_shared_dict surge 64m;
    init_worker_by_lua_block {
        local s = require("resty.surge")
        s.start()
        s._publish({
            { cidr = "0.0.0.0/0", action = "block",
              reason = "bench", message = "bench block" },
        })
    }
    server {
        listen 127.0.0.1:18233 ssl;
        ssl_certificate $P/conf/cert.pem;
        ssl_certificate_key $P/conf/key.pem;
        ssl_client_hello_by_lua_block { require("resty.surge").early() }
        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }
    }
}
EOF
pid=$(start_one "$P")
sleep 0.4
closed=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "https://127.0.0.1:18233/" || true)
if [ "$closed" != "000" ]; then
    echo "early did not close the handshake ($closed)" >&2
    tail -20 "$P/logs/error.log" >&2 || true
    exit 1
fi
{
    echo "===== (e) early() closes the handshake ====="
    echo "curl http_code was $closed (000 means the handshake did not complete)."
    wrk -t2 -c32 -d"$DUR" --latency "https://127.0.0.1:18233/" || true
    echo
    echo "===== perf ====="
} >> "$OUT"
if command -v perf >/dev/null 2>&1; then
    if perf record -F 99 -g -p "$pid" -o "$P/perf.data" -- sleep 2 >/tmp/surge-perf.err 2>&1; then
        echo "perf record succeeded; top of report:" >> "$OUT"
        perf report -i "$P/perf.data" --stdio --no-children 2>/dev/null | head -30 >> "$OUT" || true
    else
        echo "perf record failed. No flame graph was produced." >> "$OUT"
        cat /tmp/surge-perf.err >> "$OUT"
    fi
else
    echo "perf is not installed in this image. No flame graph was produced." >> "$OUT"
fi
kill "$pid" 2>/dev/null || true

echo "wrote $OUT"
cat "$OUT"
