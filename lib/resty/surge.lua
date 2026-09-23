-- Public API: init(), start(), protect(), early(), status().
--
-- protect() never raises. ngx.exit is called outside the xpcall: OpenResty
-- implements it as a yield, and a yield inside xpcall does not deny the
-- request. Anything else that throws is logged once per tick and the
-- request is allowed.

local byte = string.byte
local config = require "resty.surge.config"
local clientip = require "resty.surge.clientip"
local decisions = require "resty.surge.decisions"
local respond = require "resty.surge.respond"
local log = require "resty.surge.log"
local sketch = require "resty.surge.sketch"
local hash_pair, add_hashed = sketch.hash_pair, sketch.add_hashed
local topk = require "resty.surge.topk"
local sync = require "resty.surge.sync"
local analyzer = require "resty.surge.analyzer"
local baseline = require "resty.surge.baseline"
local gcra = require "resty.surge.gcra"
local feeds = require "resty.surge.feeds"
local ipdb = require "resty.surge.ipdb"
local fingerprint = require "resty.surge.fingerprint"
local challenge = require "resty.surge.challenge"
local ja4 = require "resty.surge.ja4"
local sha = require "resty.surge.sha256"
local export = require "resty.surge.export"
local metrics = require "resty.surge.metrics"
local messages = require "resty.surge.messages"
local cjson = require "cjson.safe"

local _M = { _VERSION = "0.1.0" }

local agent_on = false
local an
local on_merged
local started = false
local bench_mode
local cfg
local state
local box
local allow4, allow6, allow_paths
local sample_n = 0
local tats = {}
local sig = ""
local baseline_saved = ""
local shared
local feed_rt = {
    loaded = false,
    sig = "",
    next_check = 0,
    next_fetch = {},
    etag = {},
}
local err_n = 0
local err_at = 0
local err_last
local seq = 0
local secret_cur, secret_prev
local secret_ver, secret_prev_ver = 0, 0
local stats_allowed, stats_limited, stats_challenged, stats_blocked = 0, 0, 0, 0
local stats_reasons = {}
local stats_log_at = 0
local name_retry = {}

local function has_prefix(s, p)
    local n = #p
    if #s < n then
        return false
    end
    for i = 1, n do
        if byte(s, i) ~= byte(p, i) then
            return false
        end
    end
    return true
end

-- Samples per worker per tick the analyzer needs. Above that, counting
-- more requests costs CPU without changing a share, so the sampling
-- interval grows with load: a 10x bigger flood is not a 10x bigger bill.
local SAMPLE_TARGET = 512
local load_sample = 1

local function sample_of(mode)
    local floor = cfg.params.sample
    if mode == "attack" then
        floor = 1
    elseif mode == "elevated" then
        floor = 4
    end
    return load_sample > floor and load_sample or floor
end

local function note_error(err)
    err_n = err_n + 1
    err_last = err
    -- The timer emits one line. This counter is what status() shows.
    err_at = err_at + 1
end

local function empty_box()
    return {
        trie4 = decisions.new_trie(),
        trie6 = decisions.new_trie(),
        mode = "normal",
        sample = 16,
        ver = 0,
        count = 0,
        fp = {},
        fp_n = 0,
        hosts = {},
        host_n = 0,
        chal_n = 0,
    }
end

local function index_family(list, family)
    local out = {}
    local n = 0
    for i = 1, #list do
        local r = list[i]
        if r.family == family then
            out[r.key] = r
            n = n + 1
        end
    end
    return out, n
end

local function install(snap)
    -- Limiter state lives only as long as its decision.
    local live = {}
    for i = 1, #snap.list do
        local r = snap.list[i]
        respond.build(r, cfg.expose)
        if r.incident and tats[r.incident] then
            live[r.incident] = tats[r.incident]
        end
    end
    tats = live
    local t4, t6 = decisions.build(snap.list)
    box.trie4 = t4
    box.trie6 = t6
    box.mode = snap.mode or "normal"
    box.sample = sample_of(box.mode)
    box.count = #snap.list
    box.list = snap.list
    box.rps = snap.rps
    box.mean = snap.mean
    box.sigma = snap.sigma
    box.entropy = snap.entropy
    box.fp, box.fp_n = index_family(snap.list, "fp")
    box.hosts, box.host_n = index_family(snap.list, "host")
    local chal_n = 0
    for i = 1, #snap.list do
        if snap.list[i].action == "challenge" then
            chal_n = chal_n + 1
        end
    end
    box.chal_n = chal_n
end

local function dim(slot, suffix, sk, tk)
    return {
        slot = slot,
        suffix = suffix,
        topk = tk,
        sketch = sk,
        topk_reset = topk.reset,
        sketch_rotate = sketch.rotate,
        sketch_total = sketch.total,
    }
end

local function make_state(dict, id)
    local p = cfg.params
    local w = p.sketch_width
    local prefix = "w" .. id .. ":"
    local sk_ip4 = sketch.new(w, 4)
    local sk_ip6 = sketch.new(w, 4)
    local sk_sub4 = sketch.new(w, 4)
    local sk_sub6 = sketch.new(w, 4)
    local sk_uri = sketch.new(w, 4)
    local sk_fp = sketch.new(w, 4)
    local sk_host = sketch.new(w, 4)
    local k = p.topk
    state = {
        dict = dict,
        id = id,
        pid = ngx.worker.pid(),
        nworkers = ngx.worker.count() or 1,
        tick = p.tick,
        box = box,
        install = install,
        merged = {},
        dims = {
            dim(prefix .. "i4", "i4", sk_ip4, topk.new(k)),
            dim(prefix .. "i6", "i6", sk_ip6, topk.new(k)),
            dim(prefix .. "s4", "s4", sk_sub4, topk.new(k)),
            dim(prefix .. "s6", "s6", sk_sub6, topk.new(k)),
            dim(prefix .. "u", "u", sk_uri, topk.new(k)),
            dim(prefix .. "f", "f", sk_fp, topk.new(k)),
            dim(prefix .. "h", "h", sk_host, topk.new(k)),
        },
    }
    -- Named handles for the request path. The dims array is what the timer walks.
    state.ip4, state.ip6 = state.dims[1], state.dims[2]
    state.sub4, state.sub6 = state.dims[3], state.dims[4]
    state.uri = state.dims[5]
    state.fp = state.dims[6]
    state.host = state.dims[7]
    state.analyze = on_merged
end

local function signature(snap)
    local parts = { snap.mode or "" }
    local list = snap.list or {}
    for i = 1, #list do
        local r = list[i]
        parts[#parts + 1] = (r.incident or "")
            .. (r.action or "")
            .. (r.key or "")
            .. (r.uri or "")
            .. (r.manual and "m" or "")
            .. tostring(math.floor(r.until_ts or 0))
    end
    return table.concat(parts, "\0")
end

local function tally(kind, reason)
    if kind == "allowed" then
        stats_allowed = stats_allowed + 1
    elseif kind == "limited" then
        stats_limited = stats_limited + 1
    elseif kind == "challenged" then
        stats_challenged = stats_challenged + 1
    elseif kind == "blocked" then
        stats_blocked = stats_blocked + 1
        if type(reason) == "string" and reason ~= "" then
            local safe = reason:gsub("[^%w_:]", "_")
            stats_reasons[safe] = (stats_reasons[safe] or 0) + 1
        end
    end
end

local remember_reasons
local log_window

local function flush_stats()
    if not shared then
        return
    end
    local reasons = stats_reasons
    stats_reasons = {}
    if stats_allowed > 0 then
        shared:incr("m:allowed", stats_allowed, 0)
        stats_allowed = 0
    end
    if stats_limited > 0 then
        shared:incr("m:limited", stats_limited, 0)
        stats_limited = 0
    end
    if stats_challenged > 0 then
        shared:incr("m:challenged", stats_challenged, 0)
        stats_challenged = 0
    end
    if stats_blocked > 0 then
        shared:incr("m:blocked", stats_blocked, 0)
        stats_blocked = 0
    end
    local pending = {}
    for reason, n in pairs(reasons) do
        shared:incr("m:r:" .. reason, n, 0)
        pending[#pending + 1] = reason
    end
    remember_reasons(pending)
    log_window()
end

-- The name list is one shared string. add() is the lock so two workers
-- cannot each write a copy that drops the other's new reason.
function remember_reasons(pending)
    for i = 1, #pending do
        name_retry[pending[i]] = true
    end
    if not shared or not next(name_retry) then
        return
    end
    local deadline = ngx.now() + 0.05
    while not shared:add("m:reason-lock", 1, 0.5) do
        if ngx.now() >= deadline then
            return
        end
        ngx.sleep(0.001)
    end
    local known = shared:get("m:reason-names") or ""
    local grew = false
    for reason in pairs(name_retry) do
        if not metrics.has_line(known, reason) then
            if known ~= "" and known:sub(-1) ~= "\n" then
                known = known .. "\n"
            end
            known = known .. reason .. "\n"
            grew = true
        end
    end
    if grew then
        shared:set("m:reason-names", known)
    end
    name_retry = {}
    shared:delete("m:reason-lock")
end

-- One line per 10s from the shared counters, not from this tick's locals.
-- Worker 0 logs it. Every worker has already incr'd the same keys.
function log_window()
    if not state or state.id ~= 0 then
        return
    end
    local now = ngx.now()
    if stats_log_at == 0 then
        stats_log_at = now
        shared:set("m:log:blocked", shared:get("m:blocked") or 0)
        shared:set("m:log:limited", shared:get("m:limited") or 0)
        shared:set("m:log:challenged", shared:get("m:challenged") or 0)
        return
    end
    if now - stats_log_at < 10 then
        return
    end
    stats_log_at = now
    local function delta(name)
        local cur = shared:get("m:" .. name) or 0
        local prev = shared:get("m:log:" .. name) or 0
        shared:set("m:log:" .. name, cur)
        local d = cur - prev
        if d < 0 then
            d = cur
        end
        return d
    end
    local blocked_n = delta("blocked")
    local limited_n = delta("limited")
    local challenged_n = delta("challenged")
    if blocked_n > 0 then
        ngx.log(ngx.NOTICE, "surge: blocked ", blocked_n, " requests in the last 10s")
    end
    if limited_n > 0 then
        ngx.log(ngx.NOTICE, "surge: limited ", limited_n, " requests in the last 10s")
    end
    if challenged_n > 0 then
        ngx.log(ngx.NOTICE, "surge: challenged ", challenged_n,
            " requests in the last 10s")
    end
end

local function log_decisions(prev, list)
    local old = {}
    for i = 1, #(prev or {}) do
        local r = prev[i]
        old[r.incident or ""] = r.action
    end
    for i = 1, #list do
        local r = list[i]
        if r.action ~= "observe" and old[r.incident or ""] ~= r.action then
            ngx.log(ngx.NOTICE, "surge: ", r.message or r.action or "")
        end
    end
end

local function publish(snap, snap_sig)
    local list = snap.list or {}
    for i = 1, #list do
        if not list[i].body_html then
            respond.build(list[i], cfg.expose)
        end
    end
    local blob = decisions.encode(snap)
    local ok, err = state.dict:safe_set("dec", blob)
    if not ok then
        ngx.log(ngx.ERR, "surge: publish failed: ", err or "")
        return nil, err
    end
    local ver, verr = state.dict:incr("v:dec", 1, 0)
    if not ver then
        return nil, verr
    end
    install(snap)
    box.ver = ver
    sig = snap_sig or signature(snap)
    -- Dry run must not install kernel blocks. The HTTP request is still allowed.
    if cfg.export_path and not cfg.dry_run then
        local wrote, werr = export.write(cfg.export_path, snap.list, ngx.now(), 0.9)
        if not wrote then
            ngx.log(ngx.ERR, "surge: export failed: ", werr or "")
        end
    end
    return true
end

local function new_secret()
    local ok, random = pcall(require, "resty.random")
    if ok and random.bytes then
        local raw = random.bytes(32, true)
        if raw then
            return sha.hex(raw)
        end
    end
    return sha.hex(sha.sha256(tostring(ngx.now()) .. ":" .. tostring(ngx.worker.pid())))
end

local function load_secrets()
    if not shared then
        return
    end
    local ver = shared:get("pow:ver") or 0
    if ver == secret_ver and secret_cur then
        return
    end
    secret_cur = shared:get("pow:cur")
    secret_prev = shared:get("pow:prev")
    secret_ver = ver
    secret_prev_ver = shared:get("pow:prev_ver") or 0
end

local function ensure_secret()
    if shared:get("pow:cur") then
        load_secrets()
        return
    end
    if shared:add("pow:cur", new_secret()) then
        shared:set("pow:at", ngx.now())
        shared:set("pow:ver", 1)
        shared:set("pow:prev_ver", 0)
    end
    load_secrets()
end

local function maybe_rotate_secret(now)
    local at = shared:get("pow:at") or 0
    local every = cfg.params.secret_rotate or 86400
    if now - at < every then
        return
    end
    local cur = shared:get("pow:cur")
    local ver = shared:get("pow:ver") or 1
    if cur then
        shared:set("pow:prev", cur)
        shared:set("pow:prev_ver", ver)
    end
    shared:set("pow:cur", new_secret())
    shared:set("pow:at", now)
    shared:incr("pow:ver", 1, 0)
    load_secrets()
end

-- A manual decision from a parsed CIDR. Kept across analyzer ticks.
local function manual_record(it, rule, now)
    seq = seq + 1
    local ttl = it.ttl or cfg.params.ttl_base
    return {
        family = rule.v6 and "v6" or "v4",
        key = rule.bin,
        bits = rule.bits,
        action = it.action or "block",
        reason = it.reason or "manual",
        message = it.message or it.reason or "manual block",
        uri = it.uri,
        close = it.close and true or false,
        status = it.status or 403,
        ttl = ttl,
        until_ts = now + ttl,
        manual = it.manual ~= false,
        incident = it.incident or string.format("srg-%x-%x", state.id or 0, seq),
    }
end

-- True when decision `r` is exactly the network `rule` names. Auto /24 and
-- /64 keys are stored as the prefix bytes only, so pad before comparing.
local function same_net(r, rule)
    if r.family ~= (rule.v6 and "v6" or "v4") or r.bits ~= rule.bits then
        return false
    end
    local key = r.key or ""
    if #key < #rule.bin then
        key = key .. string.rep("\0", #rule.bin - #key)
    end
    return clientip.matches(rule, key)
end

-- A worker reports an address that keeps getting the challenge page
-- without solving it. The op carries it as hex because the op format is
-- split on NUL. IPv6 is blocked as its /64.
local function ignored_rule(hex)
    if not hex or (#hex ~= 8 and #hex ~= 32) or hex:find("[^%x]") then
        return nil
    end
    local bin = hex:gsub("%x%x", function(h)
        return string.char(tonumber(h, 16))
    end)
    if #bin == 16 then
        return { bin = bin:sub(1, 8) .. string.rep("\0", 8), bits = 64, v6 = true }
    end
    return { bin = bin, bits = 32, v6 = false }
end

-- status() queues block/unblock here instead of publishing from whatever
-- worker served it. A worker's list can be a tick stale, and publishing it
-- would drop a live block the leader then forgets. The leader is the only
-- writer of the snapshot.
local function apply_ops(now)
    local dict = state.dict
    local list = box.list or {}
    local changed = false
    local blocked
    -- ponytail: every challenge_ignored block rides in the one decision blob
    -- (~150 B each). Past tens of thousands, give them their own blob.
    for _ = 1, 4096 do
        local op = dict:lpop("ops")
        if not op then
            break
        end
        local kind, arg, ttl_s = op:match("^(%a)%z(.-)%z(.*)$")
        local ttl = tonumber(ttl_s) or cfg.params.ttl_base
        local rule
        if kind == "c" then
            rule = ignored_rule(arg)
        else
            rule = arg and clientip.parse_cidr(arg)
        end
        if kind == "c" and rule then
            -- Several workers can report the same address in one window.
            if not blocked then
                blocked = {}
                for i = 1, #list do
                    local r = list[i]
                    if r.action == "block" and r.key then
                        blocked[r.key .. "/" .. (r.bits or 0)] = true
                    end
                end
            end
            local id = rule.bin .. "/" .. rule.bits
            if not blocked[id] then
                blocked[id] = true
                -- close: a bot gets no body and no headers, just a closed socket.
                list[#list + 1] = manual_record({
                    ttl = ttl,
                    close = true,
                    reason = "challenge_ignored",
                    message = "Blocked " .. messages.label(rule.bin, rule.bits)
                        .. ": ignored the challenge page",
                }, rule, now)
                changed = true
            end
        elseif kind == "b" and rule then
            list[#list + 1] = manual_record({ ttl = ttl }, rule, now)
            changed = true
        elseif kind == "u" then
            local keep = {}
            for i = 1, #list do
                local r = list[i]
                if r.incident == arg or (rule and r.family ~= "fp" and same_net(r, rule)) then
                    dict:set("supk:" .. r.family .. ":" .. r.key, 1, ttl)
                else
                    keep[#keep + 1] = r
                end
            end
            list = keep
            changed = true
        end
    end
    if changed then
        box.list = list
    end
end

on_merged = function(merged)
    maybe_rotate_secret(ngx.now())
    apply_ops(ngx.now())
    -- Another leader may have saved a newer clock while this worker waited
    -- on the lease. Continue from that snapshot instead of overwriting it.
    local saved = state.dict:get("baseline")
    if type(saved) == "string" and saved ~= baseline_saved then
        local prior = baseline.import(saved)
        if prior then
            baseline.restore(an.baseline, prior, ngx.now())
            baseline_saved = saved
        end
    end
    local snap = analyzer.run(an, merged, ngx.now(), box.list)
    local kept = {}
    local list = snap.list or {}
    for i = 1, #list do
        local r = list[i]
        local banned = state.dict:get("supk:" .. (r.family or "") .. ":" .. (r.key or ""))
        if r.manual or not banned then
            kept[#kept + 1] = r
        end
    end
    snap.list = kept
    if not bench_mode and snap.mode ~= box.mode then
        ngx.log(ngx.NOTICE, string.format(
            "surge: mode %s, rps %.0f, baseline %.0f",
            snap.mode or "", snap.rps or 0, snap.mean or 0))
    end
    local snap_sig = signature(snap)
    if bench_mode then
        -- Keep the decisions published for the benchmark. The analyzer
        -- would otherwise block the single load-generator address.
        box.mode = bench_mode
        box.sample = sample_of(bench_mode)
    elseif snap_sig ~= sig then
        log_decisions(box.list, snap.list)
        publish(snap, snap_sig)
    end
    box.rps = snap.rps
    box.mean = snap.mean
    box.sigma = snap.sigma
    box.entropy = snap.entropy
    box.warming = snap.warming
    -- Only the leader computes these. status() on any worker reads this copy.
    state.dict:set("stat", cjson.encode({
        rps = snap.rps,
        mean = snap.mean,
        sigma = snap.sigma,
        entropy = snap.entropy,
        warming = snap.warming and true or false,
    }), state.tick * 8)
    -- The next start() continues this clock. Otherwise every reload spends
    -- the whole warmup with no automatic decisions.
    local text = baseline.export(an.baseline)
    if text ~= baseline_saved then
        local ok, berr = state.dict:safe_set("baseline", text)
        if ok then
            baseline_saved = text
        else
            ngx.log(ngx.ERR, "surge: baseline save failed: ", berr or "")
        end
    end
end

local function rule_trie(rules)
    if #rules == 0 then
        return nil
    end
    local t = decisions.new_trie()
    for i = 1, #rules do
        decisions.insert(t, rules[i].bin, rules[i].bits, true)
    end
    return t
end

local function allowed_ip(family, bin)
    return ipdb.hit(family == "v6" and allow6 or allow4, bin) ~= nil
end

local function allowed_path()
    local n = #allow_paths
    if n == 0 then
        return false
    end
    local uri = ngx.var.uri
    if not uri then
        return false
    end
    for i = 1, n do
        if has_prefix(uri, allow_paths[i]) then
            return true
        end
    end
    return false
end

local function accept_dec(dec)
    local p = dec.uri
    if not p then
        return true
    end
    local uri = ngx.var.uri
    return uri ~= nil and has_prefix(uri, p)
end

-- One hash per key. The estimate after the add is the top-K gate: a new
-- key enters only at admit_share of this window.
local function tally_key(d, key, nbytes)
    local sk = d.sketch
    local h1, h2 = hash_pair(key, nbytes)
    local admit = add_hashed(sk, h1, h2, 1) >= cfg.params.admit_share * sk.total
    if nbytes then
        topk.add_prefix(d.topk, key, nbytes, h1, 1, admit)
    else
        topk.add(d.topk, key, 1, admit)
    end
end

local function observe(family, bin, fp_key)
    sample_n = sample_n + 1
    local mod = box.sample
    if mod > 1 and sample_n < mod then
        return
    end
    sample_n = 0

    if family == "v4" then
        tally_key(state.ip4, bin)
        tally_key(state.sub4, bin, 3)
    else
        tally_key(state.ip6, bin)
        tally_key(state.sub6, bin, 8)
    end

    local uri = ngx.var.uri
    if not uri or uri == "" then
        return
    end
    tally_key(state.uri, uri, #uri > 128 and 128 or nil)
    if fp_key and state.fp then
        tally_key(state.fp, fp_key)
    end
    local host = ngx.var.host
    if host and host ~= "" then
        tally_key(state.host, host, #host > 128 and 128 or nil)
    end
end

local function due_sample()
    local mod = box.sample or 1
    if mod <= 1 then
        return true
    end
    return sample_n + 1 >= mod
end

local function api_request()
    local uri = ngx.var.uri or ""
    local prefs = cfg.api or {}
    for i = 1, #prefs do
        if has_prefix(uri, prefs[i]) then
            return true
        end
    end
    local accept = ngx.var.http_accept
    if accept and string.find(accept, "json", 1, true) then
        local cookie = ngx.var.http_cookie
        if not cookie or cookie == "" then
            return true
        end
    end
    return false
end

local cookie_checked, cookie_pass

-- Verified cookie value -> the address it was last verified from. A viewer
-- sends the same cookie on every request; one HMAC per worker per 30s
-- instead of one per request. A different address re-verifies, because the
-- cookie is bound to a /24 or /64.
-- ponytail: 30s cache ttl, so a cookie can outlive its expiry by up to 30s.
local pass_cache = require("resty.lrucache").new(20000)
local PASS_TTL = 30

-- Decisions a solved challenge cookie lets a browser through. A site-wide
-- challenge, manual or not, exists to be solved.
local function skippable(dec)
    if dec.family == "host" then
        return true
    end
    return not dec.manual and dec.reason == "heavy_hitter"
end

-- Count unsolved challenge pages per address across workers. At
-- chal_ignore pages in 10s the address is queued for a block, which
-- early() and the nftables export then pick up.
local function note_page(bin)
    local limit = cfg.params.chal_ignore
    if not shared or not limit or limit <= 0 then
        return
    end
    local n = shared:incr("cf:" .. bin, 1, 0, 10)
    if n == limit then
        shared:rpush("ops", "c\0" .. sha.hex(bin) .. "\0" .. cfg.params.ttl_base)
    end
end

local function verified(bin)
    if cookie_checked then
        return cookie_pass
    end
    cookie_checked = true
    cookie_pass = false
    local value = challenge.find(ngx.var.http_cookie)
    if not value then
        return false
    end
    if pass_cache:get(value) == bin then
        cookie_pass = true
        return true
    end
    cookie_pass = challenge.valid_value(value, bin, ngx.now(),
        secret_cur, secret_prev, secret_ver, secret_prev_ver)
    if cookie_pass then
        pass_cache:set(value, bin, PASS_TTL)
    end
    return cookie_pass
end

local function wants_cookie(dec)
    if box.mode == "attack" then
        return true
    end
    return dec and skippable(dec)
        and (dec.action == "block" or dec.action == "challenge"
            or dec.action == "limit" or dec.close)
end

local function limit_denied(dec)
    local rate = (dec.rate or cfg.params.limit_rps) / (state.nworkers or 1)
    if rate < 0.001 then
        rate = 0.001
    end
    local interval, tau = gcra.params(rate, cfg.params.gcra_burst)
    local allowed, tat = gcra.check(tats[dec.incident], ngx.now(), interval, tau)
    if not allowed then
        return dec, 429
    end
    tats[dec.incident] = tat
    return nil
end

local function try_pow(bin)
    local nonce = ngx.var.arg_srg_pow
    local token = ngx.var.arg_srg_ch
    if not nonce or nonce == "" or not token or token == "" then
        return nil
    end
    local bits = cfg.params.pow_bits or 16
    local ttl = cfg.params.pow_ttl or 1200
    if not challenge.proof_ok(token, nonce, bits, ngx.now(), bin, ttl) then
        return nil
    end
    if not secret_cur then
        return nil
    end
    local value = challenge.issue(bin, ngx.now(), ttl, bits, secret_ver, secret_cur)
    if not value then
        return nil
    end
    return challenge.cookie_header(value, ttl, ngx.var.scheme == "https")
end

local function return_target()
    -- request_uri is the raw path and query, percent-encoding included.
    local uri = ngx.var.request_uri
    return challenge.safe_target(uri)
end

-- Returns a decision, "page", "redirect", or nil. No ngx.exit in here.
local function apply_dec(dec, bin, pass)
    if not dec then
        return nil
    end
    if cfg.dry_run then
        if dec.action == "block" or dec.close then
            if cfg.on_block then
                pcall(cfg.on_block, dec)
            end
        end
        if dec.action and dec.action ~= "observe" then
            log.limited("dry:" .. (dec.incident or ""), ngx.NOTICE,
                "surge: dry-run would " .. dec.action .. " "
                .. (dec.incident or "") .. " " .. (dec.reason or ""))
        end
        return nil
    end
    if pass and skippable(dec) then
        return nil
    end
    if dec.action == "block" or dec.close then
        return dec
    end
    if dec.action == "challenge" then
        if api_request() then
            -- A whole site cannot 403 its API. Hold it to the site rate.
            if dec.family == "host" then
                return limit_denied(dec)
            end
            return dec, 403
        end
        local baked = try_pow(bin)
        if baked then
            -- 204 keeps the document in place so a POST can be resubmitted.
            return "solved", baked
        end
        local bits = cfg.params.pow_bits or 16
        local ttl = cfg.params.pow_ttl or 1200
        local token = challenge.token(bin, ngx.now(), ttl, bits)
        local html = token and challenge.page(token, bits, return_target(),
            ngx.req.get_method())
        if not html then
            return nil
        end
        note_page(bin)
        return "page", html
    end
    if dec.action == "limit" then
        return limit_denied(dec)
    end
    return nil
end

-- Returns a decision to deny, or nil to continue. No ngx.exit in here.
local function protect_inner()
    cookie_checked = false
    cookie_pass = false
    if cfg.test_hooks and ngx.var.arg_surge_fail == "1" then
        error("injected")
    end

    local raw = ngx.var.binary_remote_addr
    if not raw then
        return nil
    end
    -- Header read only for a trusted peer that real_ip has not already
    -- rewritten. Everyone else stays on the one binary address.
    local xff, rewritten
    if cfg.trusted[1] then
        local fam0, bin0 = clientip.identity(raw)
        if fam0 and clientip.peer_trusted(bin0, cfg.trusted) then
            local orig = ngx.var.realip_remote_addr
            local cur = ngx.var.remote_addr
            rewritten = orig and orig ~= "" and cur and orig ~= cur or false
            if not rewritten then
                xff = ngx.var[cfg.client_var]
            end
        end
    end
    local family, bin = clientip.identity(raw)
    if not family then
        return nil
    end
    -- No options table on this path. client_addr() allocates one and is
    -- only used when the peer is a trusted proxy.
    if xff then
        local fam2, bin2 = clientip.client_from_xff(xff, cfg.trusted, 8)
        if fam2 and not rewritten then
            family, bin = fam2, bin2
        end
    end
    local good = family == "v6" and box.good6 or box.good4
    if allowed_ip(family, bin) or allowed_path() or ipdb.hit(good, bin) then
        return nil
    end
    -- The uri is read only while some challenge is live.
    if box.chal_n > 0 and ngx.var.uri == challenge.SCRIPT_PATH then
        return "script"
    end

    local trie = family == "v6" and box.trie6 or box.trie4
    local dec = decisions.lookup(trie, bin, accept_dec)

    local rep = family == "v6" and box.rep6 or box.rep4
    local listed = ipdb.hit(rep, bin)
    if listed and not cfg.dry_run then
        return listed
    end
    if listed then
        log.limited("dry:" .. listed.incident, ngx.NOTICE,
            "surge: dry-run would block " .. listed.incident
            .. " " .. (listed.reason or ""))
    end

    -- Header reads stay off the normal path. Attack mode and an existing
    -- fingerprint decision need the key on every request; elevated mode
    -- otherwise fingerprints only the sampled requests.
    local want_fp = false
    if cfg.test_hooks and ngx.var.arg_surge_fp == "1" then
        want_fp = true
    elseif box.mode ~= "normal" and ((box.fp_n or 0) > 0 or due_sample()) then
        -- A live fingerprint decision needs every request. Otherwise only
        -- the sampled ones are counted, so only those are built.
        want_fp = true
    end
    local fp_key
    if want_fp then
        fp_key = fingerprint.capture()
    end
    local fpdec
    if fp_key and box.fp then
        fpdec = box.fp[fp_key]
        if fpdec and not accept_dec(fpdec) then
            fpdec = nil
        end
    end

    -- Host is read only while some site has a decision.
    local hostdec
    if box.host_n > 0 then
        hostdec = box.hosts[ngx.var.host or ""]
    end

    -- No decision means nothing for the cookie to skip. Attack mode would
    -- otherwise read and parse Cookie on every request.
    local pass = false
    if (dec or fpdec or hostdec)
        and (wants_cookie(dec) or wants_cookie(fpdec) or wants_cookie(hostdec))
    then
        pass = verified(bin)
    end
    -- A heavy-hitter block is enforced here, not in early(), so this cookie
    -- can still let a solved browser through.
    local out, extra = apply_dec(dec, bin, pass)
    if out then
        return out, extra
    end
    out, extra = apply_dec(fpdec, bin, pass)
    if out then
        return out, extra
    end
    out, extra = apply_dec(hostdec, bin, pass)
    if out then
        return out, extra
    end

    if cfg.test_hooks and ngx.var.arg_surge_fp == "1" and fp_key then
        ngx.header["X-Surge-Fp"] = fp_key
        if ngx.ctx and type(ngx.ctx.ja4) == "string" then
            ngx.header["X-Surge-Ja4"] = ngx.ctx.ja4
        end
    end

    observe(family, bin, fp_key)
    return nil
end

local function deny(dec)
    if cfg.on_block then
        pcall(cfg.on_block, dec)
    end
    if dec.close then
        return ngx.exit(444)
    end
    local status = dec.status or 403
    ngx.status = status
    ngx.header["X-Surge-Incident"] = dec.incident
    if dec.reason_hdr and dec.reason_hdr ~= "" then
        ngx.header["X-Surge-Reason"] = dec.reason_hdr
    end
    local accept = ngx.var.http_accept
    local body, kind
    if accept and string.find(accept, "json", 1, true) then
        body = dec.body_json
        kind = "application/json"
    else
        body = dec.body_html
        kind = "text/html; charset=utf-8"
    end
    ngx.header["Content-Type"] = kind
    ngx.header["Content-Length"] = #body
    ngx.print(body)
    return ngx.exit(status)
end

local function feed_groups()
    local groups, parts = {}, {}
    for i = 1, #cfg.feeds do
        local d = feeds.describe(cfg.feeds[i])
        local path = d.kind == "file" and d.path or feeds.list_path(cfg.feed_dir, d.name)
        -- A saved remote list is always plain CIDR lines; d.format only
        -- describes the source document.
        local cidrs, sum = feeds.read_list(path,
            d.kind == "file" and d.format or "cidr")
        local err = feeds.read_note(cfg.feed_dir, d.name)
        groups[#groups + 1] = {
            name = d.name,
            allow = d.allow,
            cidrs = cidrs or {},
            error = err,
        }
        parts[#parts + 1] = d.name .. ":" .. tostring(sum or 0) .. ":" .. (err or "")
    end
    return groups, table.concat(parts, "|")
end

local function apply_feeds()
    if not cfg or #cfg.feeds == 0 or not box then
        return
    end
    local groups, stamp = feed_groups()
    if feed_rt.loaded and stamp == feed_rt.sig then
        return
    end
    local db = ipdb.compile(groups, cfg.expose)
    box.rep4, box.rep6 = db.block4, db.block6
    box.good4, box.good6 = db.allow4, db.allow6
    box.feed_report = db.report
    feed_rt.sig = stamp
    feed_rt.loaded = true
end

local function maybe_reload_feeds()
    if not cfg or #cfg.feeds == 0 or not shared then
        return
    end
    local ver = shared:get("feeds:version") or 0
    local now = ngx.now()
    if feed_rt.loaded and ver == box.feed_ver and now < feed_rt.next_check then
        return
    end
    apply_feeds()
    box.feed_ver = ver
    feed_rt.next_check = now + (cfg.params.feed_poll or 30)
end

local function refresh_remote()
    local changed = false
    local now = ngx.now()
    for i = 1, #cfg.feeds do
        local d = feeds.describe(cfg.feeds[i])
        if d.kind == "remote" and d.url then
            local due = feed_rt.next_fetch[d.name]
            if not due or now >= due then
                local path = feeds.list_path(cfg.feed_dir, d.name)
                local old = feeds.read_list(path, "cidr")
                local old_n = old and #old or 0
                local body, ferr, res = feeds.fetch(d.url, { etag = feed_rt.etag[d.name] })
                feed_rt.next_fetch[d.name] = now + d.interval
                if ferr == "not modified" then
                    -- The copy on disk stays the active list.
                elseif not body then
                    feeds.write_note(cfg.feed_dir, d.name, ferr or "fetch failed")
                    ngx.log(ngx.ERR, "surge: feed ", d.name, " fetch failed: ", ferr or "")
                else
                    local status, why = feeds.apply_body(
                        cfg.feed_dir, d.name, body, d.format, old_n)
                    local stored = status == "updated"
                    -- ETag is recorded only after the list is on disk. A 304
                    -- on the next fetch would otherwise freeze a missing file.
                    feeds.remember_etag(feed_rt.etag, d.name, res, stored)
                    if not stored then
                        ngx.log(ngx.ERR, "surge: feed ", d.name, " rejected: ", why or "")
                    else
                        changed = true
                        ngx.log(ngx.NOTICE, "surge: feed ", d.name, " updated, ",
                            why, " networks")
                    end
                end
            end
        end
    end
    if changed then
        shared:incr("feeds:version", 1, 0)
    end
end

local function on_feed_timer(premature)
    if premature then
        return
    end
    local ok, err = xpcall(refresh_remote, debug.traceback)
    if not ok then
        ngx.log(ngx.ERR, "surge: feed refresh failed: ", err)
    end
end

local function on_tick(premature)
    if premature then
        return
    end
    maybe_reload_feeds()
    load_secrets()
    -- Requests that reached observe() this tick, before flush clears them.
    local seen = stats_allowed
    flush_stats()
    local ok, err = xpcall(sync.tick, debug.traceback, state)
    if not ok then
        ngx.log(ngx.ERR, "surge: tick failed: ", err)
    end
    -- After the flush, so the window just sent was counted at one interval.
    load_sample = math.floor(seen / SAMPLE_TARGET)
    if box then
        box.sample = sample_of(box.mode)
    end
    if err_n > 0 then
        ngx.log(ngx.ERR, "surge: ", err_n, " internal error(s) this tick: ",
            err_last or "")
        err_n = 0
        err_last = nil
    end
end

function _M.init()
    local process = require "ngx.process"
    local ok, err = process.enable_privileged_agent()
    if not ok then
        error("surge: enable_privileged_agent failed: " .. (err or "unknown"))
    end
    agent_on = true
end

function _M.start(opts)
    local phase = ngx.get_phase()
    if phase ~= "init_worker" then
        error("surge: start() must be called from init_worker_by_lua (called in "
            .. phase .. ")")
    end

    cfg = config.parse(opts)
    cfg.params.api_prefixes = cfg.api
    if config.needs_agent(cfg.feeds) and not agent_on then
        error("surge: url feeds need the privileged agent. Add this in the http {} block:\n"
            .. "    init_by_lua_block { require(\"resty.surge\").init() }")
    end
    if config.needs_agent(cfg.feeds) and not pcall(require, "resty.http") then
        error("surge: url feeds need lua-resty-http. Install it with: "
            .. "opm get pintsized/lua-resty-http")
    end

    local dict = config.open_dict(cfg.dict)
    shared = dict
    box = empty_box()
    box.sample = cfg.params.sample
    allow4 = rule_trie(cfg.allow4)
    allow6 = rule_trie(cfg.allow6)
    allow_paths = cfg.paths
    if #cfg.feeds > 0 then
        feeds.ensure_dir(cfg.feed_dir)
        apply_feeds()
    end

    local id = ngx.worker.id()
    if id == nil then
        -- Privileged agent. Downloads run here because workers may be
        -- unprivileged and must not all hit the feed URLs.
        local ptype = require("ngx.process").type()
        if ptype == "privileged agent" and config.needs_agent(cfg.feeds) then
            local ok, err = ngx.timer.at(0, on_feed_timer)
            if not ok then
                error("surge: feed timer failed: " .. (err or ""))
            end
            ok, err = ngx.timer.every(60, on_feed_timer)
            if not ok then
                error("surge: feed timer failed: " .. (err or ""))
            end
        end
        started = true
        return
    end

    make_state(dict, id)
    an = analyzer.new(cfg.params)
    an.dry_run = cfg.dry_run
    local saved = dict:get("baseline")
    if type(saved) == "string" then
        local snap = baseline.import(saved)
        if snap then
            baseline.restore(an.baseline, snap, ngx.now())
            baseline_saved = saved
        end
    end
    started = true

    ensure_secret()
    if id == 0 and #cfg.trusted == 0 then
        ngx.log(ngx.NOTICE,
            "surge: no trusted_proxies set; the TCP peer is treated as the client. "
            .. "Behind a CDN or load balancer, set trusted_proxies or use nginx real_ip, "
            .. "or a block can take the proxy down with the attacker.")
    end
    if id == 0 and #cfg.trusted > 0 then
        ngx.log(ngx.NOTICE,
            "surge: trusted_proxies is set; early() will not close the handshake, "
            .. "because the TCP peer is the proxy.")
    end

    local ok, err = ngx.timer.at(0, on_tick)
    if not ok then
        error("surge: timer.at failed: " .. (err or ""))
    end
    ok, err = ngx.timer.every(cfg.params.tick, on_tick)
    if not ok then
        error("surge: timer.every failed: " .. (err or ""))
    end
end

function _M.protect()
    if not started or not state then
        return
    end
    local ok, dec, status = xpcall(protect_inner, debug.traceback)
    if not ok then
        note_error(dec)
        tally("allowed")
        return
    end
    if dec == "page" then
        tally("challenged")
        ngx.status = 403
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
        ngx.header["Cache-Control"] = "no-store"
        ngx.print(status or "")
        return ngx.exit(403)
    end
    if dec == "script" then
        tally("allowed")
        ngx.header["Content-Type"] = "application/javascript"
        ngx.header["Cache-Control"] = "public, max-age=86400"
        ngx.header["Content-Length"] = #challenge.SCRIPT
        ngx.print(challenge.SCRIPT)
        return ngx.exit(200)
    end
    if dec == "solved" then
        tally("allowed")
        ngx.status = 204
        ngx.header["Set-Cookie"] = status
        ngx.header["Cache-Control"] = "no-store"
        ngx.header["Content-Length"] = 0
        return ngx.exit(204)
    end
    if dec then
        local reason = dec.reason
        if status == 429 or dec.action == "limit" then
            tally("limited", reason)
        elseif dec.action == "challenge" then
            tally("challenged", reason)
        else
            tally("blocked", reason)
        end
        if status then
            dec = {
                incident = dec.incident,
                reason_hdr = dec.reason_hdr,
                body_json = dec.body_json,
                body_html = dec.body_html,
                close = false,
                status = status,
            }
        end
        deny(dec)
        return
    end
    tally("allowed")
end

local function early_hit(bin, family)
    -- Same allow rules as protect(), minus paths: ClientHello has no URI,
    -- so a path allow is applied on the HTTP request instead.
    if allowed_ip(family, bin) then
        return nil
    end
    local good = family == "v6" and box.good6 or box.good4
    if ipdb.hit(good, bin) then
        return nil
    end
    local trie = family == "v6" and box.trie6 or box.trie4
    local dec = decisions.lookup(trie, bin, function(d)
        if d.uri or d.reason == "heavy_hitter" then
            return false
        end
        return d.action == "block" or d.close
    end)
    if dec then
        return dec
    end
    local rep = family == "v6" and box.rep6 or box.rep4
    return ipdb.hit(rep, bin)
end

function _M.early()
    if not started or not state or not box then
        return
    end
    -- The TCP peer is the proxy. Closing it would blackhole the CDN.
    if cfg.trusted[1] then
        return
    end
    if ja4.available() then
        local ok, val = pcall(ja4.capture)
        if ok and type(val) == "string" then
            ngx.ctx.ja4 = val
        end
    end
    local dec
    local ok, err = xpcall(function()
        local ssl = require "ngx.ssl"
        local addr, typ = ssl.raw_client_addr()
        if typ ~= "inet" and typ ~= "inet6" then
            return
        end
        local family, bin = clientip.identity(addr)
        if not family then
            return
        end
        dec = early_hit(bin, family)
    end, debug.traceback)
    if not ok then
        note_error(err)
        return
    end
    if not dec then
        return
    end
    if cfg.dry_run then
        log.limited("dry-early:" .. (dec.incident or ""), ngx.NOTICE,
            "surge: dry-run would close the handshake for " .. (dec.incident or ""))
        return
    end
    return ngx.exit(ngx.ERROR)
end

function _M.status()
    ngx.header["Content-Type"] = "application/json"
    if not started or not box then
        ngx.status = 500
        ngx.print('{"error":"surge not started"}')
        return
    end

    if ngx.req.get_method() == "POST" and state then
        local unblock = ngx.var.arg_unblock
        local blockip = ngx.var.arg_block
        local ttl = tonumber(ngx.var.arg_ttl)
        if not ttl or ttl <= 0 then
            ttl = cfg.params.ttl_base
        elseif ttl > 31536000 then
            ttl = 31536000
        end
        local op, name
        if unblock and unblock ~= "" then
            -- An incident id, or the exact address/CIDR of a decision.
            op, name = "u\0" .. unblock .. "\0" .. ttl, "unblock"
        elseif blockip and blockip ~= "" then
            local rule, err = clientip.parse_cidr(blockip)
            if not rule then
                ngx.status = 400
                ngx.print(cjson.encode({ ok = false, error = err }))
                return
            end
            op, name = "b\0" .. blockip .. "\0" .. ttl, "block"
        end
        if op then
            local ok, err = state.dict:rpush("ops", op)
            if not ok then
                ngx.status = 500
                ngx.print(cjson.encode({ ok = false, error = err }))
                return
            end
            -- The leader applies it on its next tick.
            ngx.print(cjson.encode({ ok = true, op = name, applies_within = cfg.params.tick }))
            return
        end
    end

    local dict = state and state.dict
    if ngx.var.arg_format == "prometheus" then
        local reasons = {}
        if dict then
            local names = dict:get("m:reason-names") or ""
            for reason in names:gmatch("[^\n]+") do
                reasons[reason] = dict:get("m:r:" .. reason) or 0
            end
        end
        ngx.header["Content-Type"] = "text/plain; version=0.0.4"
        ngx.print(metrics.prometheus({
            mode = box.mode,
            decisions = box.list and #box.list or 0,
            feeds = box.feed_report,
            totals = {
                allowed = dict and dict:get("m:allowed") or 0,
                limited = dict and dict:get("m:limited") or 0,
                challenged = dict and dict:get("m:challenged") or 0,
                blocked = dict and dict:get("m:blocked") or 0,
            },
            reasons = reasons,
        }))
        return
    end

    local now = ngx.now()
    local view = {}
    local list = box.list or {}
    for i = 1, #list do
        local r = list[i]
        view[i] = {
            incident = r.incident,
            action = r.action,
            reason = r.reason,
            target = (r.family == "fp" and fingerprint.short(r.key))
                or (r.family == "host" and r.key)
                or messages.label(r.key or "", r.bits),
            uri = r.uri,
            message = r.message,
            ttl = r.ttl,
            expires_in = r.until_ts and math.max(0, math.floor(r.until_ts - now)) or nil,
        }
    end
    local st = dict and cjson.decode(dict:get("stat") or "null")
    if type(st) ~= "table" then
        st = {}
    end
    local body = {
        mode = box.mode,
        dry_run = cfg.dry_run,
        warming = st.warming and true or false,
        rps = st.rps,
        baseline_mean = st.mean,
        baseline_sigma = st.sigma,
        entropy = st.entropy,
        version = box.ver,
        decisions = view,
        errors = err_at,
        worker = state and state.id or nil,
        shared_free = dict and dict:free_space() or nil,
        shared_capacity = dict and dict:capacity() or nil,
        feeds = box.feed_report,
    }
    ngx.print(cjson.encode(body))
end

-- Pin the mode for a benchmark. Refuses to run unless test_hooks is on,
-- so a production config cannot stick the process in attack mode.
function _M._bench_mode(mode)
    if not cfg or not cfg.test_hooks then
        return nil, "surge: test hooks are off"
    end
    if mode ~= "normal" and mode ~= "elevated" and mode ~= "attack" then
        return nil, "surge: bad bench mode"
    end
    bench_mode = mode
    box.mode = mode
    box.sample = sample_of(mode)
    return true
end

-- Add manual decisions and publish. Kept across analyzer ticks because
-- they are marked manual. This worker applies them now; the others on
-- the next tick.
function _M._publish(items, mode)
    if not started or not state then
        return nil, "surge not started"
    end
    local list = {}
    local prev = box.list or {}
    for i = 1, #prev do
        list[#list + 1] = prev[i]
    end
    local now = ngx.now()
    for i = 1, #items do
        local it = items[i]
        if it.host then
            local rec = manual_record(it, { bin = it.host, bits = 0 }, now)
            rec.family = "host"
            list[#list + 1] = rec
        else
            local rule, err = clientip.parse_cidr(it.cidr)
            if not rule then
                return nil, err
            end
            list[#list + 1] = manual_record(it, rule, now)
        end
    end
    return publish({
        mode = mode or box.mode,
        list = list,
        rps = box.rps,
        mean = box.mean,
        sigma = box.sigma,
        entropy = box.entropy,
    })
end

return _M
