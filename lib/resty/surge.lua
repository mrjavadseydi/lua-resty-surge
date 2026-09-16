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

local _M = { _VERSION = "0.1.0" }

local agent_on = false
local started = false
local cfg
local state
local box
local allow4, allow6, allow_paths
local sample_n = 0
local err_n = 0
local err_at = 0
local err_last
local seq = 0
local early_logged = false

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
    }
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
        },
    }
    -- Named handles for the request path. The dims array is what the timer walks.
    state.ip4, state.ip6 = state.dims[1], state.dims[2]
    state.sub4, state.sub6 = state.dims[3], state.dims[4]
    state.uri = state.dims[5]
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

local function observe(family, bin)
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
end

-- Returns a decision to deny, or nil to continue. No ngx.exit in here.
local function protect_inner()
    if cfg.test_hooks and ngx.var.arg_surge_fail == "1" then
        error("injected")
    end

    local raw = ngx.var.binary_remote_addr
    if not raw then
        return nil
    end
    local family, bin = clientip.identity(raw)
    if not family then
        return nil
    end
    if allowed_ip(family, bin) or allowed_path() then
        return nil
    end

    local trie = family == "v6" and box.trie6 or box.trie4
    local dec = decisions.lookup(trie, bin, accept_dec)
    local blocking = dec and (dec.action == "block" or dec.close)
    if blocking and not cfg.dry_run then
        -- Denied requests are not counted. They must stay cheaper than a
        -- request we actually serve, and the decision already remembers them.
        return dec
    end
    if blocking then
        log.limited("dry:" .. dec.incident, ngx.NOTICE,
            "surge: dry-run would block " .. dec.incident
            .. " " .. (dec.reason or ""))
        if cfg.on_block then
            pcall(cfg.on_block, dec)
        end
    end

    observe(family, bin)
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

local function on_tick(premature)
    if premature then
        return
    end
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
    if config.needs_agent(cfg.feeds) and not agent_on then
        error("surge: url feeds need the privileged agent. Add this in the http {} block:\n"
            .. "    init_by_lua_block { require(\"resty.surge\").init() }")
    end

    local dict = config.open_dict(cfg.dict)
    box = empty_box()
    box.sample = cfg.params.sample
    allow4 = cfg.allow4
    allow6 = cfg.allow6
    allow_paths = cfg.paths

    local id = ngx.worker.id()
    if id == nil then
        -- Privileged agent. It does not serve requests and has no worker id.
        started = true
        return
    end

    make_state(dict, id)
    started = true

    if id == 0 and #cfg.trusted == 0 then
        ngx.log(ngx.NOTICE,
            "surge: no trusted_proxies set; the TCP peer is treated as the client. "
            .. "Behind a CDN or load balancer, set trusted_proxies or use nginx real_ip, "
            .. "or a block can take the proxy down with the attacker.")
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
    local ok, dec = xpcall(protect_inner, debug.traceback)
    if not ok then
        note_error(dec)
        return
    end
    if dec then
        deny(dec)
    end
end

function _M.early()
    if early_logged then
        return
    end
    early_logged = true
    ngx.log(ngx.NOTICE, "surge: early() does not reject yet; "
        .. "pre-handshake blocking is not enabled")
end

function _M.status()
    local cjson = require "cjson.safe"
    ngx.header["Content-Type"] = "application/json"
    if not started or not box then
        ngx.status = 500
        ngx.print('{"error":"surge not started"}')
        return
    end
    local dict = state and state.dict
    local body = {
        mode = box.mode,
        dry_run = cfg.dry_run,
        version = box.ver,
        decisions = box.count,
        errors = err_at,
        worker = state and state.id or nil,
        shared_free = dict and dict:free_space() or nil,
        shared_capacity = dict and dict:capacity() or nil,
    }
    ngx.print(cjson.encode(body))
end

-- Install a decision list and publish it. Other workers apply it on the
-- next tick; this worker applies it now. Used by the status endpoint later
-- and by tests.
function _M._publish(items, mode)
    if not started or not state then
        return nil, "surge not started"
    end
    local list = {}
    for i = 1, #items do
        local it = items[i]
        local rule, err = clientip.parse_cidr(it.cidr)
        if not rule then
            return nil, err
        end
        seq = seq + 1
        list[i] = {
            family = rule.v6 and "v6" or "v4",
            key = rule.bin,
            bits = rule.bits,
            action = it.action or "block",
            reason = it.reason or "manual",
            message = it.message or it.reason or "manual block",
            uri = it.uri,
            close = it.close and true or false,
            status = it.status or 403,
            ttl = it.ttl or cfg.params.ttl_base,
            incident = it.incident or string.format("srg-%x-%x", state.id or 0, seq),
        }
    end
    local snap = { mode = mode or box.mode, list = list }
    local blob = decisions.encode(snap)
    local ok, err = state.dict:safe_set("dec", blob)
    if not ok then
        return nil, err
    end
    local ver, verr = state.dict:incr("v:dec", 1, 0)
    if not ver then
        return nil, verr
    end
    install(snap)
    box.ver = ver
    return true
end

return _M
