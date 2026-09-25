#!/bin/sh
# What each path costs while a site is under a site-wide challenge, attack
# mode pinned. From the repo root: make bench-cost
#
# The loop lines time protect() inside one request. No timer fires there,
# so sampling stays at 1 in N=1: that is the worst case, a flood too small
# to raise the sampling interval. The wrk lines include adaptive sampling.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
P=/tmp/surge-cost
PORT=18240
DUR=${DUR:-5s}
rm -rf $P; mkdir -p $P/logs $P/conf
cat > $P/conf/nginx.conf <<CONF
worker_processes 2;
error_log logs/error.log warn;
pid logs/nginx.pid;
daemon off;
events { worker_connections 4096; }
http {
    lua_package_path "$ROOT/lib/?.lua;;";
    lua_shared_dict surge 64m;
    access_log off;
    init_worker_by_lua_block {
        local s = require("resty.surge")
        s.start({ advanced = { test_hooks = true, chal_ignore = 0 } })
        s._bench_mode("attack")
        s._publish({
            { host = "victim.test", action = "challenge", reason = "host_surge", message = "b" },
            { cidr = "0.0.0.0/0", uri = "/blocked", action = "block", reason = "bench", message = "b" },
            { cidr = "0.0.0.0/0", uri = "/closed", action = "block", close = true, reason = "bench", message = "b" },
        })
    }
    server {
        listen 127.0.0.1:$PORT;
        location = /mk {
            content_by_lua_block {
                local d = ngx.shared.surge
                local ch = require "resty.surge.challenge"
                ngx.print(ch.issue(ngx.var.binary_remote_addr, ngx.now(), 1200, 16,
                    d:get("pow:ver"), d:get("pow:cur")))
            }
        }
        location = /pg {
            content_by_lua_block {
                local ch = require "resty.surge.challenge"
                local bin = ngx.var.binary_remote_addr
                local n = 0
                for _ = 1, 20000 do n = n + #ch.page(ch.token(bin, ngx.now(), 1200, 16), 16, "/x?a=1", "GET") end
                collectgarbage("collect")
                local before = collectgarbage("count")
                ngx.update_time()
                local t0 = ngx.now()
                for _ = 1, 20000 do n = n + #ch.page(ch.token(bin, ngx.now(), 1200, 16), 16, "/x?a=1", "GET") end
                ngx.update_time()
                ngx.say(string.format("%.1f kb/20k, %.0f ns per page", collectgarbage("count") - before,
                    (ngx.now() - t0) / 20000 * 1e9))
            }
        }
        location = /gc {
            content_by_lua_block {
                local s = require("resty.surge")
                for _ = 1, 20000 do s.protect() end
                collectgarbage("collect")
                collectgarbage("stop")
                local before = collectgarbage("count")
                for _ = 1, 20000 do s.protect() end
                local after = collectgarbage("count")
                collectgarbage("restart")
                local best = 1e9
                for _ = 1, 3 do
                    ngx.update_time()
                    local t0 = ngx.now()
                    for _ = 1, 100000 do s.protect() end
                    ngx.update_time()
                    best = math.min(best, (ngx.now() - t0) / 100000 * 1e9)
                end
                ngx.say(string.format("%.1f kb/20k, %.0f ns per call (min of 3)", after - before, best))
            }
        }
        location / {
            access_by_lua_block { require("resty.surge").protect() }
            content_by_lua_block { ngx.print("ok\n") }
        }
    }
}
CONF
openresty -p $P >/dev/null 2>&1 &
sleep 1.5
U=http://127.0.0.1:$PORT
C="srg_pow=$(curl -s $U/mk)"
echo "loop, attack, allowed (other site):  $(curl -s -H 'Host: other.test' $U/gc)"
echo "loop, attack, site challenge + valid cookie: $(curl -s -H 'Host: victim.test' -H "Cookie: $C" $U/gc)"
echo "page build (token + html):          $(curl -s $U/pg)"
echo "page bytes on the wire:               $(curl -s -H 'Host: victim.test' $U/ | wc -c)"
r() { printf '%-40s' "$1"; shift; wrk -t2 -c32 -d$DUR "$@" | awk '/Requests\/sec/ {print $2 " req/s"}'; }
r "wrk allowed (other site)" -H 'Host: other.test' $U/
r "wrk site challenge, valid cookie" -H 'Host: victim.test' -H "Cookie: $C" $U/
r "wrk site challenge, page served" -H 'Host: victim.test' $U/
r "wrk site limit, api (mostly 429)" -H 'Host: victim.test' -H 'Accept: application/json' $U/api
r "wrk block 403" $U/blocked
r "wrk pow script (cached by browsers)" -H "Host: victim.test" $U/.srg-pow.v1.js
kill $(cat $P/logs/nginx.pid)
