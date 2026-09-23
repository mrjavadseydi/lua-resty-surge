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

Each decision lists its `target` (address, CIDR, or fingerprint id) and `expires_in` seconds. Every worker answers with the same rate and baseline numbers.

`POST /_surge?block=203.0.113.4&ttl=600` and `POST /_surge?unblock=<incident or address>` update the manual list. Unblock takes the incident id or the exact address or CIDR of a decision (`1.2.3.0/24` for a subnet block). Both are queued for the leader and take effect within one tick.

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

This is not a firewall for volumetric L3 or L4 floods. A block can be written to `export_path` for `examples/nftables-sidecar.sh` to load into nftables. That file is not written while `dry_run` is on, so a dry run cannot drop clients in the kernel. The module never runs a shell command itself.

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
| No module, `return 200` | 50084 | 628 µs | 1.14 ms |
| Empty `access_by_lua`, same `content_by_lua` | 45712 | 688 µs | 1.50 ms |
| `protect()`, normal mode | 44171 | 719 µs | 1.46 ms |
| `protect()`, attack mode, allowed | 36849 | 843 µs | 2.04 ms |
| Block response | 36969 | 844 µs | 1.60 ms |
| `early()` handshake close | 0 completed; 52626 connect errors in 8s | | |

This run shared one container CPU between wrk and nginx, so it is about half the throughput of an earlier run on the same image, and requests per second moved ±10% between identical runs. Compare `protect()` with the empty `access_by_lua` row, not with `return 200`: the gap to `return 200` is mostly the Lua phases themselves. `early()` never completes a request. wrk records the failures as connect errors.

Steadier numbers come from timing `protect()` in a loop inside one request, after a 20000-call warmup (the `gc` lines of `make bench7`):

| Mode | ns per call | KB allocated per 20000 calls |
|---|---|---|
| Normal | 105 | 9.4 |
| Attack, allowed | 2955 | 789 |

The same loop against the previous commit, five runs each with `test_hooks` on: attack mode went from 3425–4020 ns to 2830–3040 ns and from 1346–1440 KB to 98–502 KB, after hashing each key once and skipping the cookie read when there is no decision. Normal mode stayed at 215–235 ns (the `test_hooks` query-arg read is most of that). Attack mode allocates because the fingerprint is built on every request. `perf` is not installed in the harness image, so this run has no flame graph. `luajit -jv bench/jit_hot.lua` compiled the sketch and top-K loops. The trace log is `bench/results/jit-phase7.txt`.

## License

MIT. See `LICENSE`.
