#!/bin/sh
# Benchmark (a) return 200, (b) protect() in normal mode, (d) a block decision.
# Numbers below are whatever `ab` printed on this machine.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OR=${OR:-$HOME/opt/openresty/bin/openresty}
PORT=${PORT:-18201}
PREFIX=${PREFIX:-/tmp/surge-bench}
OUT="$ROOT/bench/results/phase3.txt"
N=${N:-20000}
C=${C:-32}

mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$ROOT/bench/results"
cat > "$PREFIX/conf/nginx.conf" <<EOF
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
            { cidr = "0.0.0.0/0", uri = "/blocked", action = "block",
              reason = "bench", message = "bench block" },
        })
    }

    server {
        listen 127.0.0.1:$PORT;

        location = /bare {
            return 200 "ok\n";
        }

        location = /lua {
            content_by_lua_block { ngx.print("ok\n") }
        }

        # The return directive runs in rewrite, before access_by_lua, so the
        # measured locations generate the body in the content phase instead.
        location = /open {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }

        location = /blocked {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }
    }
}
EOF

"$OR" -p "$PREFIX" >/tmp/surge-bench.out 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT

i=0
while [ "$i" -lt 50 ]; do
    if curl -sf -o /dev/null "http://127.0.0.1:$PORT/bare"; then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done
curl -sf -o /dev/null "http://127.0.0.1:$PORT/bare"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/blocked")
if [ "$code" != "403" ]; then
    echo "blocked location returned $code" >&2
    tail -30 "$PREFIX/logs/error.log" >&2 || true
    exit 1
fi

{
    echo "lua-resty-surge phase 3 http benchmark"
    echo "client: ab -n $N -c $C"
    echo "openresty: $("$OR" -v 2>&1)"
    uname -sm
    sysctl -n machdep.cpu.brand_string 2>/dev/null || true
    echo "workers: 2"
    echo
} > "$OUT"

run_one() {
    name=$1
    path=$2
    echo "=== $name ($path) ===" | tee -a "$OUT"
    ab -n "$N" -c "$C" -r -e "/tmp/surge-ab-$name.csv" "http://127.0.0.1:$PORT$path" > "/tmp/surge-ab-$name.txt"
    grep -E "Requests per second|Time per request|Failed requests|Non-2xx" "/tmp/surge-ab-$name.txt" | tee -a "$OUT"
    echo "percentiles (ms):" | tee -a "$OUT"
    awk -F, '$1==50 || $1==99 || $1==100 { printf "  p%s %s ms\n", $1, $2 }' "/tmp/surge-ab-$name.csv" | tee -a "$OUT"
    echo | tee -a "$OUT"
}

run_one bare /bare
run_one lua /lua
run_one normal /open
run_one block /blocked

echo "wrote $OUT"
