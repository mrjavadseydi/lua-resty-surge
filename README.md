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

`GET /_surge?format=html` is a small dashboard: mode, request rate against the baseline, and the live decisions with a Remove button (the same `unblock` POST). It polls the JSON every 2s and loads nothing from outside. It is behind the same `allow`/`deny` as the location.

`on_decision` is called once for each new or changed decision, on the leader, with the same fields a decision has in the JSON. Its `dry_run` field marks proposed actions during a dry run. It runs in a timer, so it can make HTTP calls. Queued hooks are retried each tick if timer capacity is exhausted. Hooks run one at a time and at most 256 wait, so give HTTP calls a short timeout. A hook that hangs delays every alert after it. For example, to post to a Slack webhook with `lua-resty-http`:

```lua
on_decision = function(d)
    require("resty.http").new():request_uri(SLACK_WEBHOOK, {
        method = "POST",
        headers = { ["Content-Type"] = "application/json" },
        body = require("cjson").encode({ text = (d.dry_run and "surge dry-run: " or "surge: ") .. d.message }),
    })
end,
```

Each decision lists its `target` (address, CIDR, or fingerprint id) and `expires_in` seconds. Every worker answers with the same rate and baseline numbers.

`POST /_surge?block=203.0.113.4&ttl=600` and `POST /_surge?unblock=<incident or address>` update the manual list. Unblock takes the incident id or the exact address or CIDR of a decision (`1.2.3.0/24` for a subnet block). Both are queued for the leader and take effect within one tick. Unblocking an automatic decision restarts that key at observe; it is not an exemption, and a key still flooding is limited again after `consecutive` ticks. Put an address in `allow` to exempt it. An unblock that matches no decision gets 404. Manual blocks live in the shared dictionary: they survive a reload, not a full restart. Keep the ones you need in nginx `deny` or a `custom` feed file. Blocking a network that already has a manual block replaces it, ttl included. A POST whose `Origin` is another host, or whose `Sec-Fetch-Site` is `cross-site` or `same-site`, gets 403: another page cannot drive the operator's browser into a block. A block wider than /8 (IPv4) or /16 (IPv6) is refused, and host bits are cleared (`1.2.3.4/24` is `1.2.3.0/24`).

Manual blocks take precedence over automatic decisions for overlapping networks.

## Behind a CDN or load balancer

If every request comes from the proxy, the module will treat the proxy as the attacker. Prefer nginx `real_ip`, which rewrites the address `protect()` already reads. Or set `trusted_proxies` to the proxy CIDRs. The client is then the rightmost untrusted hop in `X-Forwarded-For` (or `client_header`), looking at only the last eight hops.

`early()` closes a manual block or a reputation hit during the TLS handshake. It does nothing when `trusted_proxies` is set, because that handshake belongs to the proxy. A path such as `/health` is allowed on the HTTP request. The handshake does not know the path yet.

URL reputation feeds need one more line, in `init_by_lua`, plus `lua-resty-http`:

```nginx
init_by_lua_block { require("resty.surge").init() }
```

A feed that is only a local file does not need that.

## What it does

In normal mode a request reads the client address once, checks the allow list, the decision table, and the reputation table, and sometimes updates a small sketch. Only that sampled request reads headers, for its fingerprint. It does not touch the shared dictionary.

The sampling interval grows with load. Each worker aims for about 512 sampled requests per tick, so a flood ten times bigger does not cost the sketches ten times more. Attack mode builds a fingerprint only for a sampled request, or for every request while a fingerprint decision is live.

A leader tick (worker 0, with a lease so a reload cannot run two leaders) merges those sketches. The request rate is an EWMA with a frozen baseline during a surge, a cooldown before the mode drops, and a cap on how fast the baseline can grow. Warmup starts with the first traffic and calibrates from the samples received. A tick above the attack line is not learned, even during warmup. The rate and key-share baselines are saved together and continue across reloads. Upgrading from an older rate-only snapshot recalibrates shares for one warmup window; existing decisions keep their TTLs. The entropy baselines start over after a reload, and their signal is off until they have seen a warmup's worth of windows. Empty windows do not seed the rate or entropy baselines. Entropy over subnets, URLs, and fingerprints says whether the surge is a few sources, a botnet, one URL, or one client program. Heavy keys move from observe to limit, then a proof-of-work challenge, then a block. URLs are never blocked on their own. A dominant URL only narrows an IP or fingerprint decision to that path. A solved challenge sets a cookie bound to a /24 or a /64. The cookie skips later heavy-hitter decisions on a /24 or a fingerprint, and the challenge on the solver's own address. A limit or block on that address (/32, or its /64) still applies, so one solve does not let a flooding address through. It does not skip a manual block or a reputation hit.

## Many sites on one node

Each request is also counted by `Host`. During a surge, a site whose share of the node's traffic rises by `host_share_rise` (0.25 in balanced) gets a site-wide decision: first a limit at about twice its normal rate, then the challenge page. A site is never blocked outright. API requests (`api` prefixes, or `Accept: json` with no cookie) are rate-held instead of challenged. A solved cookie skips the site challenge. The other sites on the node are not touched.

This is the case per-address rules miss: a botnet of thousands of addresses, each under `min_key_rps`, with randomized headers. An address that gets `chal_ignore` challenge pages (10 in balanced) within 10s without solving one is blocked. An address that solved one in the last `pow_ttl` is not counted: a real browser is behind it, and a feed reader on the same NAT must not get that browser blocked. That block is a manual block with no path, so `early()` closes it during the handshake, `protect()` answers it with a bare 444, and `export_path` hands it to nftables. IPv6 is blocked as its /64.

The challenge page is 211 bytes. The proof-of-work script is one static file, `/.srg-pow.v1.js`, that the browser caches for a day. A bot that never runs JavaScript never downloads it. A solved cookie is verified with one HMAC per worker every 30s, not on every request, so a site's real viewers cost little more than normal traffic while it is challenged.

Site detection compares traffic shares. With balanced settings, a site already carrying more than 75% of the traffic cannot gain the required 25 percentage points; a single-site node cannot change its site share at all. A distributed flood without heavy IPs or fingerprints can therefore enter attack mode without producing a site decision.

Also add `limit_req_zone $host` and `limit_conn_zone $host` in nginx as a fixed per-site ceiling. See `examples/nginx.conf`.

Presets are `relaxed`, `balanced` (the default), and `strict`. `advanced = { ... }` overrides one parameter at a time. `start()` rejects an unknown name and tells you the legal ones. Invalid values, including zero sampling intervals and non-finite numbers, are rejected at startup. nginx keeps running after that error, unprotected, and `nginx -t` cannot see it: `/_surge` then answers 500 with the reason, in JSON and Prometheus alike.

## Limits

This is not a firewall for volumetric L3 or L4 floods. If the uplink is full, nothing in nginx helps. Check the NIC graphs during an incident to tell a full link from busy workers. A block can be written to `export_path` for `examples/nftables-sidecar.sh --watch` to load into nftables within a second. Load `examples/nftables.conf` once with `nft -f examples/nftables.conf`, then run the sidecar under systemd, not cron. The sidecar only fills sets; the ruleset supplies the actual drops on TCP ports 80 and 443. These rules match the TCP peer and run before HTTP allow rules, so export only networks intended for node-wide blocking, and adapt the rules to your existing firewall. Include the ruleset in your system nftables configuration so firewall reloads restore the drop rules. A minute of cron delay is a minute of blocked clients still costing a TLS handshake each. That file is not written while `dry_run` is on, so a dry run cannot drop clients in the kernel. The module never runs a shell command itself.

The rate limit is one GCRA per decision in the shared dictionary, so its rate and burst hold for the node whichever worker a request lands on. Only a request that hits a limit decision touches it. A non-yielding shared lock serializes the clock update. A request that finds the lock busy receives 429 without adding debt; a full dictionary fails open. The sketch overestimates a little. Fingerprints are computed on sampled requests, and on every request while a fingerprint decision is live. `early()` cannot see a path allow. ASN lookup is not included.

## Measured results

Commands, from the repo root, in the Docker harness (`openresty/openresty:1.31.1.1`, Linux 6.4.16-linuxkit aarch64, 1 container CPU, 2 nginx workers, 2026-09-23):

```
make sim
make bench7
make bench-cost
```

`make sim` runs `sim/run.lua`: the real analyzer, one merged top-K per tick, fingerprints omitted while the mode is normal (the server samples them in every mode). It is not a live packet flood. It does not cover the `chal_ignore` blocks, which happen on the request path; `make smoke` checks those. Balanced mode:

| Scenario | Detect | Block | Legit requests denied |
|---|---|---|---|
| Legit baseline | none | none | 0 / 6000 |
| Legit spike ×10 | 0.25s | none | 0 / 60000 (mode went attack) |
| Single-source flood | 0.25s | 0.75s | 0 / 1600 |
| Botnet on `/login` | 0.25s | 1.00s, fingerprint scoped to `/login` | 0 / 2000 |
| Random-path cache bust | 0.25s | 0.75s, the /24 | 0 / 2000 |
| Slow ramp, 2%/min | 30s, at 1.01× | 319s, at 1.11× | 0 / 69850 |
| Attack during a legit spike | 0.25s | 0.75s | 0 / 30000 |
| Botnet (5000 IPs, random paths and fingerprints) on 1 of 20 sites | 0.25s | limit 0.25s, challenge 0.50s, the site | 0 / 1980 on the other sites; all 20 legit requests to the attacked site challenged |

False positives on legitimate requests were 0, under the 0.1% target. Relaxed mode did not flag the slow ramp: its growth cap is wide enough that a 2% per minute increase stays inside the baseline. Strict mode blocked that ramp at 1.05×. The full table is `sim/results/phase7.txt`.

`make bench7` is `wrk -t2 -c32 -d8s --latency`. Normal mode uses a high per-IP cap and a long warmup so this one client is not turned into an attacker during the run. Attack mode is pinned with `_bench_mode`, which only works when `test_hooks` is on, for the same reason.

| Path | Requests/s | p50 | p99 |
|---|---|---|---|
| No module, `return 200` | 51490 | 612 µs | 0.93 ms |
| Empty `access_by_lua`, same `content_by_lua` | 46682 | 685 µs | 0.97 ms |
| `protect()`, normal mode | 44764 | 707 µs | 1.25 ms |
| `protect()`, attack mode, allowed | 42602 | 743 µs | 1.86 ms |
| Block response | 37390 | 846 µs | 1.33 ms |
| `early()` handshake close | 0 completed; 55758 connect errors in 8s | | |

This run shared one container CPU between wrk and nginx, so it is about half the throughput of an earlier run on the same image, and requests per second moved ±10% between identical runs. Compare `protect()` with the empty `access_by_lua` row, not with `return 200`: the gap to `return 200` is mostly the Lua phases themselves. `early()` never completes a request. wrk records the failures as connect errors.

Steadier numbers come from timing `protect()` in a loop inside one request, after a 20000-call warmup (the `gc` lines of `make bench7`):

| Mode | ns per call | KB allocated per 20000 calls |
|---|---|---|
| Normal | 105–110 | 15–17 |
| Attack, allowed | 3165–3705 | 262–630 |

The attack row is the worst case. No timer fires inside the loop, so sampling stays at every request, as in a flood too small to raise the interval. Under wrk the interval does rise. With adaptive sampling switched off in a copy of the tree, attack mode served 40.9k–41.4k requests/s. With it on, 50.8k–52.6k, three alternating runs each, access log off. That is above the empty `access_by_lua` row. KB numbers here are GC-sensitive. With the collector stopped, the attack loop allocates about 640 bytes per call, mostly the fingerprint.

`make bench-cost` pins attack mode with one site under a site-wide challenge. Before and after the cookie cache, the small page, and adaptive sampling:

| Path | Before | After |
|---|---|---|
| Viewer with a solved cookie, loop | 14540 ns | 5240–5360 ns |
| Viewer with a solved cookie, wrk | 25.0k req/s | 41.1k–43.5k req/s |
| Challenge page, wrk | 25.9k req/s | 38.5k–40.3k req/s |
| Challenge page size | 3360 bytes | 211 bytes |
| Other site, attack mode, wrk | 41.2k req/s | 48.2k–49.7k req/s |

At 20000 bot requests/s, the page size is the difference between about 540 Mbit/s and 34 Mbit/s of egress spent on bots.

The same loop against the commit before that, five runs each with `test_hooks` on: attack mode went from 3425–4020 ns to 2830–3040 ns and from 1346–1440 KB to 98–502 KB, after hashing each key once and skipping the cookie read when there is no decision. Normal mode stayed at 215–235 ns (the `test_hooks` query-arg read is most of that). Attack mode allocates because the fingerprint is built on every request. `perf` is not installed in the harness image, so this run has no flame graph. `luajit -jv bench/jit_hot.lua` compiled the sketch and top-K loops. The trace log is `bench/results/jit-phase7.txt`.

## License

MIT. See `LICENSE`.
