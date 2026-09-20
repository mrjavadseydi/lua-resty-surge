# lua-resty-surge design check

Verified against the OpenResty **1.31.1.1** source tree (nginx 1.31.1, ngx_lua 0.10.31rc5, lua-resty-core 0.1.34rc3, LuaJIT 2.1-20260415, lua-resty-openssl 1.7.1, lua-resty-string 0.17). That is the current stable release. The core module targets **OpenResty 1.21.4.1+**. JA4 needs **1.29.2.1+** and is enabled only when the getters below exist.

No request-path code in this document. Phase 2 implements the algorithms against this contract.

## What the install is allowed to do

Zero config is three lines and does not enable the privileged agent, feeds, or `early()`. `start()` validates everything and raises before any worker accepts traffic. `protect()` never raises: `xpcall`, allow the request, add to a worker-local error counter, log once per tick.

`ngx.worker.id()` is `nil` outside a worker or single process (the FFI returns -1 for the privileged agent and the master). Worker 0 is the leader candidate. During `nginx -s reload` two processes both have id 0, so a shared-dict lease (`pid` plus an expiry of one tick) decides who actually merges. The new worker 0 takes over on the first tick after the previous pid disappears (`ngx.worker.pids()` when present, otherwise when the lease expires). Baselines live in the dict, so a new leader does not start from zero.

## API check

| API | Result |
|---|---|
| `ngx.var.binary_remote_addr` | Exists. It is the raw `sockaddr` bytes: 4 for IPv4, 16 for IPv6, the path text for a unix socket. Not available in `init_*` or any SSL phase. `ngx_http_realip` replaces `c->sockaddr`, so this variable is already the client address when `real_ip` is on. |
| `ngx.req.raw_header()` | Exists in rewrite/access/content/header_filter. On HTTP/2 the C handler `luaL_error`s with `http2 requests not supported yet`. It does not return a synthetic header. `ngx.req.http_version()` returns `0.9`, `1.0`, `1.1`, `2.0`, `3.0`, or `nil`. Never call `raw_header` unless the version is `< 2`. |
| `ngx.req.get_headers(max, raw)` | Exists. `resty.core` copies headers in nginx list order, then stores them in a hash keyed by name. `pairs()` is not wire order. HTTP/2 fingerprints omit header order and use a different version tag. |
| `ngx.ssl.raw_client_addr()` | `lua-resty-core` `ngx.ssl`. Returns `(binary, type, err)` with `type` `inet`, `inet6`, or `unix`. This is the address API for `early()`. `ngx.var` is not available there. |
| `ssl_client_hello_by_lua_block` | ngx_lua 0.10.21+, works out of the box on OpenResty 1.21.4.1+ (OpenSSL >= 1.1.1). `ngx.exit(ngx.ERROR)` aborts the handshake. The handler runs only on the default server for a shared address. `early()` has to be configured there. |
| `ngx.ssl.clienthello` | In 1.31.1.1: `get_client_hello_server_name`, `get_supported_versions`, `get_client_hello_ciphers`, `get_client_hello_ext_present`, `get_client_hello_ext`. GREASE values are already removed. These getters are not in 1.21.4; feature-detect and skip JA4 when missing. |
| `ngx.ctx` across ClientHello | The phase runs on a fake request. `resty.core.ctx` stores the table on the SSL connection (`ctx_ref`) and, in later phases, exposes it as the `__index` metatable of `ngx.ctx`. Reading `ngx.ctx.ja4` in access is the supported hand-off. An integration test has to pass before JA4 is turned on. If it fails, JA4 stays off. |
| `ngx.process.enable_privileged_agent()` | `init_by_lua*` only. Too late to call from `start()` in `init_worker`. `init_worker` does run inside the agent; `process.type()` is `"privileged agent"`. |
| Cosockets | Disabled directly in `init_by_lua` and `init_worker_by_lua`. Feed downloads run inside `ngx.timer.at` / `ngx.timer.every`. |
| `ngx.timer.every` | Available in `init_worker`, including the privileged agent. |
| `ngx.shared.DICT` | `get/set/safe_set/add/safe_add/incr/delete/expire/ttl/flush_all/get_keys`, plus `capacity()` and `free_space()` via FFI. `safe_set` returns `nil, "no memory"`. No shared-dict call on the request path. |
| `ngx.crc32_short` | FFI in `resty.core.hash` (`ngx_http_lua_ffi_crc32_short`). Legal in access, timer, and `ssl_client_hello`. Not legal in `init_by_lua` / `init_worker`. |
| `ngx.worker.id` / `count` / `pid` / `pids` | Present in this lua-resty-core. `id()` is `nil` off a worker. |
| `ngx.now` | Cached nginx time, no syscall. Legal in timers. The request path does not call `ngx.update_time`, `os.time`, `os.*`, or `io.*`. |
| `ngx.exit(444)` | Legal in `access_by_lua`. Closes without a body. |
| `ngx.socket.udp` `setpeername("unix:...")` | `ngx_parse_url` accepts `unix:` paths, and the UDP connect path autobinds `AF_UNIX`. Not enabled until a runtime test passes. Default export is an atomically renamed file. No `os.execute`. |
| HMAC | `lua-resty-openssl` 1.7.1 is bundled in 1.31.1.1 and is not guaranteed in 1.21.4. `resty.hmac` from `lua-resty-string` is bundled in both. Use openssl when `require` succeeds, otherwise `resty.hmac`. Compare cookies with a byte XOR loop. |
| Not bundled | `lua-resty-http`, `lua-resty-ipmatcher`, `lua-resty-maxminddb`. |

## Adjustments where the spec does not match the platform

**Prefixes without allocating.** `string.sub(binary_remote_addr, 1, 3)` creates a new string on every request, which breaks the normal-mode allocation budget. The prefix *is* still the leading 3, 2, 8, or 6 bytes. The hot path hashes those bytes in place. A Lua string is materialized only when a key is admitted into top-K. IPv4 and IPv6 never share a table. An IPv6 address whose first 12 bytes are the v4-mapped prefix is stored as the last 4 bytes, so one client is not two keys. Unix sockets are not IP keys.

**HTTP fingerprint.** HTTP/1 uses `raw_header(true)` for the fixed header-name order, capped. HTTP/2 and HTTP/3 do not. Calling `raw_header` there aborts the request. Order is omitted and the fingerprint version byte changes. User-Agent is hashed, not stored. Cookie presence is one bit, ignoring the challenge cookie so solving it does not mint a new key. An empty fingerprint window is not entropy 0. The mix seen in elevated mode is the baseline, and only a drop in that entropy is an attack signal. The readable form is built only when a decision is created.

**JA4.** The ClientHello getters exist on 1.31.1.1, and `t/phase6.sh` shows `ngx.ctx` written in `ssl_client_hello_by_lua` is readable on the request. `early()` stores a JA4 string there for direct clients. The protocol character is `t` because this hook is TCP. If the supported-versions extension is absent the version field is `00`. No private FFI into `ngx_connection_t`. Behind `trusted_proxies`, `early()` returns before computing JA4: the handshake belongs to the proxy.

**`early()`.** `ngx.ssl.raw_client_addr()` plus the worker-local block table and radix. If `trusted_proxies` is set, `early()` returns immediately and `start()` logs once that the TCP peer is the proxy, so a pre-handshake block would blackhole the CDN. An allowlisted address or a good-bot range is not closed. A path allow has no URI yet, so it is applied in `protect()`. Heavy-hitter blocks are not closed here. The challenge cookie is only visible on the HTTP request, so those blocks are enforced in `protect()`. Manual blocks and reputation hits still abort the handshake.

**Real client IP.** Prefer nginx `real_ip` so the hot path stays a single `binary_remote_addr` read. Use `trusted_proxies` only when `real_ip` is not in play. If both are configured and `$realip_remote_addr` is set, the connecting address was already rewritten and XFF is not parsed. XFF parsing is bounded and runs only when the peer sits in `trusted_proxies`. With neither configured, `start()` logs one notice.

**Feeds and the 3-line install.** URL feeds need the privileged agent, and that can only be switched on in `init_by_lua`:

```nginx
init_by_lua_block { require("resty.surge").init() }
```

`init()` calls `enable_privileged_agent()` and sets a master-process flag that workers inherit. `start({ feeds = { ... } })` errors with that snippet when a URL feed is configured and `init()` did not run. A `custom` feed that is a local file does not need the agent. URL feeds also require `lua-resty-http`; `start()` names the install command (`opm get pintsized/lua-resty-http`) instead of embedding an HTTP client. Workers load the last good file at start. The agent downloads on a timer, validates, atomically renames, and bumps `feeds:version`. A missing network leaves the previous file in place.

**Radix.** A bundled FFI/pure-Lua matcher is the default, because `lua-resty-ipmatcher` is not part of OpenResty. If that module is installed it is used, and phase 5 records both timings.

**Warmup hard limit.** During warmup there is no baseline block. Reputation still blocks. The absolute limit is a per-key rate (`hard_ip_rps` in the preset), not a global switch that would drop a legitimate spike.

**Entropy thresholds.** The preset table has no entropy numbers. `entropy_drop` and `entropy_rise` (absolute change in normalized H) will be added and tuned in the simulation. Starting point for balanced: `0.20`.

**Stale baseline.** A dict baseline older than one half-life is kept as the seed, and warmup runs again. A reload inside the half-life does not re-warmup.

**Export.** Atomic file rewrite is the v1 path. The unix datagram path is wired only after the runtime check. The sidecar example reads the file and fills an nftables set with timeouts.

## Hot path (normal mode)

Worker-local data only. One read of the client address. Allowlist radix or hash, and a path-prefix check only when a path allowlist exists. Decision lookup on the binary address, then on the prefix, in separate v4 and v6 structures. Reputation radix. A module upvalue counts requests; every Nth one updates the sketches. No `math.random`, no shared dict, no header read, no `ngx.update_time`, no new table, no key concatenation.

`string.byte` walks the key for the hash so the hot path does not allocate a pointer cdata per call. Phase 2 measures this against `ngx.crc32_short`. The winner is the one that is faster on 4-byte and 16-byte keys and does not abort the LuaJIT trace.

Sampled counts are scaled by N when the leader merges, not when the worker increments.

Elevated and attack modes may read a capped header set and may check a challenge cookie. That cookie check is one HMAC and only runs for a challenged or blocked key, or while the global mode is attack.

Deny responses are built once, when the decision is published, and stored on the record. Repeat high-confidence offenders use `ngx.exit(444)`. Rate limits use 429. Other blocks use 403.

## Algorithms

**Sketch.** `uint32_t[depth * width]`, default `2048 x 4`. `ε ≈ e / 2048 ≈ 0.00133`, `δ ≈ e^-4 ≈ 0.0183`. Width must be a power of two. Depth is fixed at 4 and unrolled. Two hashes, `h_i = h1 + i * h2`, `h2` forced odd. Conservative update: raise every counter that sits below `min + weight`, saturating at `2^32 - 1`. Saturation can underestimate; below the cap the sketch must not. Two buffers, swapped with `ffi.fill`, not reallocated.

**Top-K.** Space-Saving, K entries, tables reused, `table.clear` on the index. A new key is admitted only when its sketch estimate is at least `admit_share * window_total`. Replacement stores `count = min + weight`, `error = min`. The minimum slot is rescanned only when a current minimum is removed or incremented off the minimum.

**Baseline.** `α = 1 - exp(-tick / half_life)`, then `diff = r - mean`, `incr = α * diff`, `mean = mean + incr`, `var = (1 - α) * (var + diff * incr)`. Frozen in elevated and attack. While not frozen, a positive step is clamped to `mean * max_growth_per_hour * tick / 3600` so a slow ramp cannot hide inside the average. The first sample sets the mean. Elevated when `r > max(mean + k_elev * σ, min_rps)`. Attack when `r > max(mean + k_attack * σ, min_rps * 2)` or an entropy signal says so. Leaving a raised mode requires the entry condition to stay false for `cooldown` seconds.

**Entropy.** Normalized Shannon over the merged buckets plus an "other" bucket, `H / log2(n)`, with `n` the number of positive buckets. `n <= 1` yields 0. The leader keeps an EWMA of `H_norm` per dimension and freezes it with the rate baseline.

**GCRA.** One theoretical arrival time per limited key, held on the worker-local decision. `interval = workers / global_rate`, `tau = (burst - 1) * interval`. Allow when `now >= tat - tau`, then `tat = max(now, tat) + interval`. Each worker enforces `rate / workers`. A client that hits every worker can burst about `workers` times the configured burst. That is the cost of not taking a shared-dict lock per request. Unlimited keys do not consult the limiter.

**Decisions.** A key is an offender only when its share beats both the absolute floor and `baseline_share * multiplier`, its rate beats `min_key_rps`, and it is not allowlisted, not a good bot, and not challenge-verified. URIs are never blocked on their own. A decision may carry a URI prefix. ASN blocks require a hosting/datacenter flag and a higher confidence. Escalation is `observe → limit → challenge → block`, with the tick counts from the preset. API paths skip `challenge`. Repeat blocks double the TTL up to the preset cap. `dry_run` stops at observe and logs the action that was not taken.

## Shared dict

Sized at startup from `capacity()`. Below 8 MB, `start()` errors and prints `lua_shared_dict surge 64m;`. The 64 MB line is the recommendation, not the minimum. Every write checks `no memory` and drops the lowest-confidence decision first. Status reports `free_space`.

Keys are fixed strings built once per worker (`w0:ip`, `w0:subnet4`, …). The request path does not build them. The leader publishes one versioned decision blob. Workers copy it into a local table when the version changes, then swap the pointer.

## Tests that lock this down

Phase 2: sketch bound and saturation, Space-Saving on a Zipf 1.1 stream of 1e6 draws, sketch-gated admission against 1e6 uniques, EWMA freeze and cooldown, entropy of known distributions, GCRA rate and burst. Run with `luajit spec/run.lua` and, once this tree is built, `resty spec/run.lua`.

Later phases add the HTTP/2 `raw_header` error test, the `ngx.ctx` JA4 hand-off test, XFF parsing, feed validation, and the reload lease test. Those are integration tests because they need nginx phases.
