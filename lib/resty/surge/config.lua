-- Validate start() options before any worker accepts traffic.
-- Failures here are loud on purpose: a bad feed name must not show up as a
-- request-time error.

local presets = require "resty.surge.presets"
local clientip = require "resty.surge.clientip"
local band = require("bit").band

local _M = {}

local MODES = { relaxed = true, balanced = true, strict = true }
local EXPOSE = { id = true, short = true, full = true }
local FEED_NAMES = {
    "custom", "firehol_level1", "goodbots",
    "spamhaus_drop", "spamhaus_edrop", "tor_exits",
}
local FEED_SET = {}
for i = 1, #FEED_NAMES do
    FEED_SET[FEED_NAMES[i]] = true
end

local MIN_DICT = 8 * 1024 * 1024

local ZERO_OK = {
    warmup = true, cooldown = true, min_rps = true, min_key_rps = true,
    max_growth_per_hour = true, k_elev = true, k_attack = true, chal_ignore = true,
}
local INTEGERS = {
    sample = true, topk = true, consecutive = true, gcra_burst = true,
    pow_bits = true, chal_ignore = true, sketch_width = true, sketch_depth = true,
}
local FRACTIONS = {
    abs_share = true, admit_share = true, entropy_drop = true,
    entropy_rise = true, confidence_skip = true, host_share_rise = true,
}

-- 0 is legal for these. A zero abs_share, entropy or host threshold
-- makes every key, tick or site an offender.
local ZERO_FRACTION = { admit_share = true, confidence_skip = true }

local function validate_params(params)
    for k, v in pairs(params) do
        local valid
        if k == "test_hooks" or k == "challenge_ready" then
            valid = type(v) == "boolean"
        else
            valid = type(v) == "number" and v == v and v < math.huge
                and (v > 0 or (v == 0 and (ZERO_OK[k] or ZERO_FRACTION[k] or k == "multiplier")))
            if valid and INTEGERS[k] then
                valid = v == math.floor(v)
            end
            if valid and FRACTIONS[k] then
                valid = v <= 1
            end
        end
        if not valid then
            error('surge: invalid value for parameter "' .. k .. '"')
        end
    end
    if params.sample > 65535 or params.topk > 65535 then
        error("surge: sample and topk must be <= 65535")
    end
    local width = params.sketch_width
    if width < 4 or width > 2147483647 or band(width, width - 1) ~= 0 then
        error("surge: sketch_width must be a power of two >= 4")
    end
    if params.sketch_depth ~= 4 then
        error("surge: sketch_depth must be 4")
    end
    -- 2^24 hashes is tens of seconds of a phone's JavaScript.
    if params.pow_bits > 24 then
        error("surge: pow_bits must be <= 24")
    end
    -- A browser gets one page before its script runs; 1 or 2 blocks it.
    if params.chal_ignore ~= 0 and params.chal_ignore < 3 then
        error("surge: chal_ignore must be 0 (off) or >= 3")
    end
    -- Every tick merges every worker's sketches in a timer.
    if params.tick < 0.05 then
        error("surge: tick must be >= 0.05")
    end
    if params.half_life < 10 then
        error("surge: half_life must be >= 10 seconds")
    end
    if params.ttl_max < params.ttl_base or params.k_attack < params.k_elev then
        error("surge: ttl_max and k_attack must be >= ttl_base and k_elev")
    end
end

local function feed_list()
    return table.concat(FEED_NAMES, ", ")
end

local function one_feed(entry)
    if type(entry) == "string" then
        if entry == "custom" then
            return nil, 'surge: custom feed needs a path or url'
        end
        if not FEED_SET[entry] then
            return nil, 'surge: unknown feed "' .. entry
                .. '"; valid feeds: ' .. feed_list()
        end
        return { kind = "remote", name = entry }
    end
    if type(entry) ~= "table" then
        return nil, "surge: feed entries must be names or tables"
    end
    local name = entry.name or "custom"
    if entry.url and entry.url ~= "" then
        return {
            kind = "remote", name = name, url = entry.url,
            format = entry.format, allow = entry.allow,
        }
    end
    if entry.path and entry.path ~= "" then
        return {
            kind = "file", name = name, path = entry.path,
            format = entry.format, allow = entry.allow,
        }
    end
    return nil, 'surge: custom feed "' .. name .. '" needs a path or url'
end

function _M.parse(opts)
    opts = opts or {}
    if type(opts) ~= "table" then
        error("surge: options must be a table")
    end

    local mode = opts.mode or "balanced"
    if not MODES[mode] then
        error('surge: unknown mode "' .. tostring(mode)
            .. '"; valid modes: relaxed, balanced, strict')
    end

    local params = presets.copy(mode)
    if opts.advanced ~= nil then
        if type(opts.advanced) ~= "table" then
            error("surge: advanced must be a table")
        end
        for k, v in pairs(opts.advanced) do
            if params[k] == nil then
                error('surge: unknown parameter "' .. tostring(k) .. '"')
            end
            params[k] = v
        end
    end
    validate_params(params)

    local expose = opts.expose_reason or "short"
    if not EXPOSE[expose] then
        error('surge: expose_reason must be "id", "short", or "full"')
    end

    if opts.dry_run ~= nil and type(opts.dry_run) ~= "boolean" then
        error("surge: dry_run must be true or false")
    end
    if opts.on_block ~= nil and type(opts.on_block) ~= "function" then
        error("surge: on_block must be a function")
    end
    if opts.on_decision ~= nil and type(opts.on_decision) ~= "function" then
        error("surge: on_decision must be a function")
    end

    local allow4, allow6, paths = {}, {}, {}
    if opts.allow ~= nil then
        if type(opts.allow) ~= "table" then
            error("surge: allow must be a list")
        end
        for i = 1, #opts.allow do
            local rule, err = clientip.allow_rule(opts.allow[i])
            if not rule then
                error("surge: allow[" .. i .. "]: " .. (err or "bad entry"))
            end
            if rule.path then
                paths[#paths + 1] = rule.path
            elseif rule.v6 then
                allow6[#allow6 + 1] = rule
            else
                allow4[#allow4 + 1] = rule
            end
        end
    end

    local trusted = {}
    if opts.trusted_proxies ~= nil then
        if type(opts.trusted_proxies) ~= "table" then
            error("surge: trusted_proxies must be a list")
        end
        for i = 1, #opts.trusted_proxies do
            local spec = opts.trusted_proxies[i]
            if type(spec) ~= "string" or spec:sub(1, 1) == "/" then
                error("surge: trusted_proxies[" .. i .. "] must be a CIDR")
            end
            local rule, err = clientip.parse_cidr(spec)
            if not rule then
                error("surge: trusted_proxies[" .. i .. "]: " .. (err or "bad cidr"))
            end
            trusted[#trusted + 1] = rule
        end
    end

    -- Read only when the TCP peer is a trusted proxy. Default is the
    -- header a CDN appends; CF-Connecting-IP and similar are one option.
    local client_header = opts.client_header or "X-Forwarded-For"
    if type(client_header) ~= "string" or not client_header:match("^[%w%-]+$") then
        error("surge: client_header must be an HTTP header name")
    end
    local client_var = "http_" .. client_header:lower():gsub("-", "_")

    local feeds, seen = {}, {}
    if opts.feeds ~= nil then
        if type(opts.feeds) ~= "table" then
            error("surge: feeds must be a list")
        end
        for i = 1, #opts.feeds do
            local feed, err = one_feed(opts.feeds[i])
            if not feed then
                error(err)
            end
            if seen[feed.name] then
                error('surge: duplicate feed name "' .. feed.name
                    .. '"; each feed needs a unique name')
            end
            seen[feed.name] = true
            feeds[#feeds + 1] = feed
        end
    end

    local dict = opts.dict or "surge"
    if type(dict) ~= "string" or dict == "" then
        error("surge: dict must be the lua_shared_dict name")
    end
    local api = {}
    if opts.api ~= nil then
        if type(opts.api) ~= "table" then
            error("surge: api must be a list of path prefixes")
        end
        for i = 1, #opts.api do
            local spec = opts.api[i]
            if type(spec) ~= "string" or spec:sub(1, 1) ~= "/" then
                error("surge: api[" .. i .. "] must be a path prefix")
            end
            api[#api + 1] = spec
        end
    end

    local export_path = opts.export_path
    if export_path ~= nil and (type(export_path) ~= "string" or export_path == "") then
        error("surge: export_path must be a file path")
    end

    local feed_dir = opts.feed_dir or "/tmp/surge-feeds"
    if type(feed_dir) ~= "string" or feed_dir == "" then
        error("surge: feed_dir must be a directory path")
    end

    return {
        mode = mode,
        params = params,
        expose = expose,
        dry_run = opts.dry_run and true or false,
        on_block = opts.on_block,
        on_decision = opts.on_decision,
        allow4 = allow4,
        allow6 = allow6,
        paths = paths,
        trusted = trusted,
        client_header = client_header,
        client_var = client_var,
        api = api,
        feeds = feeds,
        feed_dir = feed_dir,
        export_path = export_path,
        dict = dict,
        test_hooks = params.test_hooks and true or false,
    }
end

function _M.needs_agent(feeds)
    for i = 1, #feeds do
        if feeds[i].kind ~= "file" then
            return true
        end
    end
    return false
end

function _M.open_dict(name)
    local dict = ngx.shared[name]
    if not dict then
        error('surge: shared dict "' .. name .. '" is missing.\n'
            .. "Add this in the http {} block:\n"
            .. "    lua_shared_dict " .. name .. " 64m;")
    end
    local cap = dict:capacity()
    if cap < MIN_DICT then
        error('surge: shared dict "' .. name .. '" is ' .. cap
            .. " bytes; need at least " .. MIN_DICT .. ".\n"
            .. "    lua_shared_dict " .. name .. " 64m;")
    end
    return dict
end

_M.MIN_DICT = MIN_DICT
_M.FEED_NAMES = FEED_NAMES

return _M
