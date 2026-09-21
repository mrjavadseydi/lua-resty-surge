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

local function sample_of(mode)
    if mode == "attack" then
        return 1
    end
    if mode == "elevated" then
        return 4
    end
    return cfg.params.sample
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
    }
end

local function index_fp(list)
    local fp = {}
    local n = 0
    for i = 1, #list do
        local r = list[i]
        if r.family == "fp" then
            fp[r.key] = r
            n = n + 1
        end
    end
    return fp, n
end

local function install(snap)
    for i = 1, #snap.list do
        respond.build(snap.list[i], cfg.expose)
    end
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
    box.fp, box.fp_n = index_fp(snap.list)
end

local function gate_for(sk)
    local admit = cfg.params.admit_share
    return function(key)
        local total = sketch.total(sk)
        if total <= 0 then
            return true
        end
        return sketch.query(sk, key) >= admit * total
    end
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
            dim(prefix .. "i4", "i4", sk_ip4, topk.new(k, gate_for(sk_ip4))),
            dim(prefix .. "i6", "i6", sk_ip6, topk.new(k, gate_for(sk_ip6))),
            dim(prefix .. "s4", "s4", sk_sub4, topk.new(k)),
            dim(prefix .. "s6", "s6", sk_sub6, topk.new(k)),
            dim(prefix .. "u", "u", sk_uri, topk.new(k, gate_for(sk_uri))),
            dim(prefix .. "f", "f", sk_fp, topk.new(k, gate_for(sk_fp))),
        },
    }
    -- Named handles for the request path. The dims array is what the timer walks.
    state.ip4, state.ip6 = state.dims[1], state.dims[2]
    state.sub4, state.sub6 = state.dims[3], state.dims[4]
    state.uri = state.dims[5]
    state.fp = state.dims[6]
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

local function publish(snap)
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
    sig = signature(snap)
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

on_merged = function(merged)
    maybe_rotate_secret(ngx.now())
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
    if bench_mode then
        -- Keep the decisions published for the benchmark. The analyzer
        -- would otherwise block the single load-generator address.
        box.mode = bench_mode
        box.sample = sample_of(bench_mode)
    elseif signature(snap) ~= sig then
        publish(snap)
    end
    box.rps = snap.rps
    box.mean = snap.mean
    box.sigma = snap.sigma
    box.entropy = snap.entropy
    box.warming = snap.warming
    if bench_mode then
        box.mode = bench_mode
        box.sample = sample_of(bench_mode)
    end
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

local function allowed_ip(family, bin)
    local list = family == "v6" and allow6 or allow4
    for i = 1, #list do
        if clientip.matches(list[i], bin) then
            return true
        end
    end
    return false
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

local function prefix_hit(sk, full, nbytes)
    local total = sketch.total(sk)
    if total <= 0 then
        return false
    end
    return sketch.query(sk, full, nbytes) >= cfg.params.admit_share * total
end

local function observe(family, bin, fp_key)
    sample_n = sample_n + 1
    local mod = box.sample
    if mod > 1 and sample_n < mod then
        return
    end
    sample_n = 0

    if family == "v4" then
        local d = state.ip4
        sketch.add(d.sketch, bin, 1)
        topk.add(d.topk, bin, 1)
        local sub = state.sub4
        sketch.add(sub.sketch, bin, 1, 3)
        local h = sketch.hash_pair(bin, 3)
        topk.add_prefix(sub.topk, bin, 3, h, 1, prefix_hit(sub.sketch, bin, 3))
    else
        local d = state.ip6
        sketch.add(d.sketch, bin, 1)
        topk.add(d.topk, bin, 1)
        local sub = state.sub6
        sketch.add(sub.sketch, bin, 1, 8)
        local h = sketch.hash_pair(bin, 8)
        topk.add_prefix(sub.topk, bin, 8, h, 1, prefix_hit(sub.sketch, bin, 8))
    end

    local uri = ngx.var.uri
    if not uri or uri == "" then
        return
    end
    local ud = state.uri
    if #uri > 128 then
        sketch.add(ud.sketch, uri, 1, 128)
        local h = sketch.hash_pair(uri, 128)
        topk.add_prefix(ud.topk, uri, 128, h, 1, prefix_hit(ud.sketch, uri, 128))
    else
        sketch.add(ud.sketch, uri, 1)
        topk.add(ud.topk, uri, 1)
    end
    if fp_key and state.fp then
        local d = state.fp
        sketch.add(d.sketch, fp_key, 1)
        topk.add(d.topk, fp_key, 1)
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

local function verified(bin)
    if cookie_checked then
        return cookie_pass
    end
    cookie_checked = true
    cookie_pass = challenge.valid(ngx.var.http_cookie, bin, ngx.now(),
        secret_cur, secret_prev, secret_ver, secret_prev_ver)
    return cookie_pass
end

local function wants_cookie(dec)
    if box.mode == "attack" then
        return true
    end
    return dec and not dec.manual and dec.reason == "heavy_hitter"
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
    if pass and not dec.manual and dec.reason == "heavy_hitter" then
        return nil
    end
    if dec.action == "block" or dec.close then
        return dec
    end
    if dec.action == "challenge" then
        if api_request() then
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
    elseif box.mode == "attack"
        or (box.mode == "elevated" and ((box.fp_n or 0) > 0 or due_sample()))
    then
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

    local pass = false
    if wants_cookie(dec) or wants_cookie(fpdec) then
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
    local ok, err = xpcall(sync.tick, debug.traceback, state)
    if not ok then
        ngx.log(ngx.ERR, "surge: tick failed: ", err)
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
    allow4 = cfg.allow4
    allow6 = cfg.allow6
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
        return
    end
    if dec == "page" then
        ngx.status = 403
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
        ngx.header["Cache-Control"] = "no-store"
        ngx.print(status or "")
        return ngx.exit(403)
    end
    if dec == "solved" then
        ngx.status = 204
        ngx.header["Set-Cookie"] = status
        ngx.header["Cache-Control"] = "no-store"
        ngx.header["Content-Length"] = 0
        return ngx.exit(204)
    end
    if dec then
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
    end
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
    local cjson = require "cjson.safe"
    ngx.header["Content-Type"] = "application/json"
    if not started or not box then
        ngx.status = 500
        ngx.print('{"error":"surge not started"}')
        return
    end

    if ngx.req.get_method() == "POST" then
        local unblock = ngx.var.arg_unblock
        local blockip = ngx.var.arg_block
        local ttl = tonumber(ngx.var.arg_ttl) or cfg.params.ttl_base
        if unblock and unblock ~= "" then
            local list = {}
            local prev = box.list or {}
            for i = 1, #prev do
                local rec = prev[i]
                if rec.incident == unblock then
                    state.dict:set("supk:" .. rec.family .. ":" .. rec.key, 1, ttl)
                else
                    list[#list + 1] = rec
                end
            end
            publish({
                mode = box.mode, list = list,
                rps = box.rps, mean = box.mean, sigma = box.sigma,
            })
            ngx.print('{"ok":true,"op":"unblock"}')
            return
        end
        if blockip and blockip ~= "" then
            local ok, err = _M._publish({
                {
                    cidr = blockip, action = "block", reason = "manual",
                    message = "manual block", ttl = ttl,
                },
            })
            if not ok then
                ngx.status = 400
                ngx.print(cjson.encode({ ok = false, error = err }))
                return
            end
            ngx.print('{"ok":true,"op":"block"}')
            return
        end
    end

    local dict = state and state.dict
    local view = {}
    local list = box.list or {}
    for i = 1, #list do
        local r = list[i]
        view[i] = {
            incident = r.incident,
            action = r.action,
            reason = r.reason,
            message = r.message,
            ttl = r.ttl,
        }
    end
    local body = {
        mode = box.mode,
        dry_run = cfg.dry_run,
        warming = box.warming and true or false,
        rps = box.rps,
        baseline_mean = box.mean,
        baseline_sigma = box.sigma,
        entropy = box.entropy,
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
        local rule, err = clientip.parse_cidr(it.cidr)
        if not rule then
            return nil, err
        end
        seq = seq + 1
        local ttl = it.ttl or cfg.params.ttl_base
        list[#list + 1] = {
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
