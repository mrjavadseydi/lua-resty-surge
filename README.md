# lua-resty-surge

lua-resty-surge tells an L7 flood apart from a busy hour. It blocks the sources that are actually attacking and leaves a readable reason, instead of slowing every visitor down.

```nginx
http {
    lua_shared_dict surge 64m;
    init_worker_by_lua_block { require("resty.surge").start() }
    server {
        listen 80;
        access_by_lua_block { require("resty.surge").protect() }
    }
}
```

A decision looks like this in the error log:

```
surge: Blocked 10.1.2.9: 38% of traffic in the last 0.2s (normal: 0%), 1200 requests/s.
```

The client sees `X-Surge-Incident` and, unless you set `expose_reason = "id"`, a short `X-Surge-Reason`.

## Rolling out safely

Start with `dry_run = true`. Every path runs except the final deny, and the log says what would have happened. Watch `GET /_surge`. When the decisions match what you expect, turn dry run off.

```nginx
location = /_surge {
    allow 127.0.0.1;
    deny all;
    content_by_lua_block { require("resty.surge").status() }
}
```

`GET /_surge?format=prometheus` is the same data as text. Labels are `result` and `reason` only. Addresses are not labels.

`POST /_surge?block=203.0.113.4&ttl=600` and `POST /_surge?unblock=<incident>` update the manual list.

## Behind a CDN or load balancer

If every request comes from the proxy, the module will treat the proxy as the attacker. Prefer nginx `real_ip`, which rewrites the address `protect()` already reads. Or set `trusted_proxies` to the proxy CIDRs. The client is then the rightmost untrusted hop in `X-Forwarded-For` (or `client_header`), looking at only the last eight hops.

`early()` closes a manual block or a reputation hit during the TLS handshake. It does nothing when `trusted_proxies` is set, because that handshake belongs to the proxy. A path such as `/health` is allowed on the HTTP request. The handshake does not know the path yet.

URL reputation feeds need one more line, in `init_by_lua`, plus `lua-resty-http`:

```nginx
init_by_lua_block { require("resty.surge").init() }
```

A feed that is only a local file does not need that.

## What it does

In normal mode a request reads the client address once, checks the allow list, the decision table, and the reputation table, and sometimes updates a small sketch. It does not read headers and it does not touch the shared dictionary.

A leader tick (worker 0, with a lease so a reload cannot run two leaders) merges those sketches. The request rate is an EWMA with a frozen baseline during a surge, a cooldown before the mode drops, and a cap on how fast the baseline can grow. Entropy over subnets, URLs, and fingerprints says whether the surge is a few sources, a botnet, one URL, or one client program. Heavy keys move from observe to limit, then a proof-of-work challenge, then a block. URLs are never blocked on their own. A dominant URL only narrows an IP or fingerprint decision to that path. A solved challenge sets a cookie bound to a /24 or a /64. The cookie skips later heavy-hitter limits. It does not skip a manual block or a reputation hit.

Presets are `relaxed`, `balanced` (the default), and `strict`. `advanced = { ... }` overrides one parameter at a time. `start()` rejects an unknown name and tells you the legal ones.

## Limits

This is not a firewall for volumetric L3 or L4 floods. A repeat block can be written to `export_path` for `examples/nftables-sidecar.sh` to load into nftables. The module never runs a shell command itself.

The rate limit is per worker, so a client that hits every worker can burst about `workers` times the configured burst. The sketch overestimates a little. Fingerprints are computed only after the mode leaves normal, because reading headers on every quiet request costs too much. `early()` cannot see a path allow. ASN lookup is not included.

## Measured results

Commands, from the repo root, in the Docker harness (`openresty/openresty:1.31.1.1`, Linux 6.4.16-linuxkit aarch64, 1 container CPU, 2 nginx workers, 2026-09-23):

```
make sim
make bench7
```

`make sim` runs `sim/run.lua`: the real analyzer, one merged top-K per tick, fingerprints omitted while the mode is normal. It is not a live packet flood. Balanced mode:

| Scenario | Detect | Block | Legit requests denied |
|---|---|---|---|
| Legit baseline | none | none | 0 / 6000 |
| Legit spike ×10 | 0.25s | none | 0 / 60000 (mode went attack) |
| Single-source flood | 0.25s | 0.75s | 0 / 1600 |
| Botnet on `/login` | 0.25s | 1.00s, fingerprint scoped to `/login` | 0 / 2000 |
| Random-path cache bust | 0.25s | 0.75s, the /24 | 0 / 2000 |
| Slow ramp, 2%/min | 30s, at 1.01× | 319s, at 1.11× | 0 / 69850 |
| Attack during a legit spike | 0.25s | 0.75s | 0 / 30000 |

False positives on legitimate requests were 0, under the 0.1% target. Relaxed mode did not flag the slow ramp: its growth cap is wide enough that a 2% per minute increase stays inside the baseline. Strict mode blocked that ramp at 1.05×. The full table is `sim/results/phase7.txt`.

`make bench7` is `wrk -t2 -c32 -d8s --latency`. Normal mode uses a high per-IP cap and a long warmup so this one client is not turned into an attacker during the run. Attack mode is pinned with `_bench_mode`, which only works when `test_hooks` is on, for the same reason.

| Path | Requests/s | p50 | p99 |
|---|---|---|---|
| No module, `return 200` | 97398 | 323 µs | 665 µs |
| `protect()`, normal mode | 85890 | 370 µs | 505 µs |
| `protect()`, attack mode, allowed | 67261 | 469 µs | 791 µs |
| Block response | 73621 | 430 µs | 633 µs |
| `early()` handshake close | 0 completed; 100767 connect errors in 8.06s | | |

The block response was not faster than a normal allow. It sends a body, and at this concurrency that costs more than the allow path. It was faster than the attack-mode allow path, which reads headers and checks the challenge cookie. `early()` never completes a request. wrk records the failures as connect errors.

A loop of 20000 `protect()` calls in normal mode allocated 15.2 KB (about 0.8 bytes per call). The same loop in attack mode allocated 932 KB, because the fingerprint is built then. `perf` is not installed in the harness image, so this run has no flame graph. `luajit -jv bench/jit_hot.lua` compiled the sketch and top-K loops. The trace log is `bench/results/jit-phase7.txt`.

## License

MIT. See `LICENSE`.
