-- Feed parsers, validation, and on-disk activation.
--
-- A new list is rejected when it is empty, when more than 1% of its lines
-- fail to parse, or when its size moves by more than half versus the last
-- good copy. The previous file is left in place. Activation is an atomic
-- rename, so a worker never reads a half-written list.
--
-- Spamhaus EDROP is still a separate URL, but as of 2026-09-22 the file
-- contains only comments (the networks were merged into DROP). Validation
-- treats that as empty and does not activate it.

local ffi = require "ffi"
local bit = require "bit"
local clientip = require "resty.surge.clientip"

local band, bxor, rshift = bit.band, bit.bxor, bit.rshift

ffi.cdef[[
int mkdir(const char *pathname, unsigned int mode);
]]

local _M = {}

_M.MAX_BODY = 32 * 1024 * 1024
_M.MAX_ERROR_RATIO = 0.01
_M.MAX_CHANGE = 0.5

-- interval is seconds. allow=true loads into the allow trie (good bots).
_M.catalog = {
    firehol_level1 = {
        url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        format = "cidr",
        interval = 3600,
    },
    spamhaus_drop = {
        url = "https://www.spamhaus.org/drop/drop.txt",
        format = "spamhaus",
        interval = 3600,
    },
    spamhaus_edrop = {
        url = "https://www.spamhaus.org/drop/edrop.txt",
        format = "spamhaus",
        interval = 3600,
    },
    tor_exits = {
        url = "https://check.torproject.org/torbulkexitlist",
        format = "ip",
        interval = 1800,
    },
    -- Google's old googlebot.json URL now redirects at this combined list.
    goodbots = {
        url = "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
        format = "goodbots",
        interval = 86400,
        allow = true,
    },
}

function _M.describe(feed)
    local cat = _M.catalog[feed.name]
    local format = feed.format
    if not format and cat then
        format = cat.format
    end
    if not format then
        format = "cidr"
    end
    return {
        name = feed.name,
        kind = feed.kind,
        path = feed.path,
        url = feed.url or (cat and cat.url),
        format = format,
        interval = (cat and cat.interval) or 3600,
        allow = feed.allow or (cat and cat.allow) or false,
    }
end

function _M.ensure_dir(path)
    -- A relative feed_dir must stay relative. Prefixing every segment with
    -- "/" would create /feeds at the filesystem root and every write would miss.
    local abs = path:sub(1, 1) == "/"
    local acc = abs and "" or nil
    for part in path:gmatch("[^/]+") do
        if acc == nil then
            acc = part
        elseif acc == "" then
            acc = "/" .. part
        else
            acc = acc .. "/" .. part
        end
        ffi.C.mkdir(acc, 493)
    end
    return acc
end

local function strip(line, spamhaus)
    local s = line:match("^%s*(.-)%s*$")
    if not s or s == "" then
        return nil
    end
    local lead = s:sub(1, 1)
    if lead == "#" or (spamhaus and lead == ";") then
        return nil
    end
    if spamhaus then
        s = s:match("^([^;]+)")
        s = s and s:match("^%s*(.-)%s*$")
    end
    return s
end

local function parse_lines(body, spamhaus)
    local cidrs, errors, lines = {}, 0, 0
    for line in (body or ""):gmatch("[^\r\n]+") do
        local token = strip(line, spamhaus)
        if token then
            lines = lines + 1
            local rule = clientip.parse_cidr(token)
            if rule then
                cidrs[#cidrs + 1] = token
            else
                errors = errors + 1
            end
        end
    end
    return { cidrs = cidrs, errors = errors, lines = lines }
end

function _M.parse(body, format)
    format = format or "cidr"
    if format == "goodbots" then
        local cidrs, lines = {}, 0
        for token in (body or ""):gmatch('"ipv[46]Prefix"%s*:%s*"([^"]+)"') do
            lines = lines + 1
            if clientip.parse_cidr(token) then
                cidrs[#cidrs + 1] = token
            end
        end
        local errors = lines - #cidrs
        return { cidrs = cidrs, errors = errors, lines = lines }
    end
    if format == "spamhaus" then
        return parse_lines(body, true)
    end
    -- cidr (firehol, custom) and ip (tor). A bare address is a /32 or /128.
    return parse_lines(body, false)
end

function _M.validate(parsed, old_count)
    local n = #parsed.cidrs
    if n == 0 then
        return nil, "empty"
    end
    if parsed.lines > 0 and (parsed.errors / parsed.lines) > _M.MAX_ERROR_RATIO then
        return nil, string.format(
            "parse errors %.0f%% (%d/%d)",
            100 * parsed.errors / parsed.lines, parsed.errors, parsed.lines)
    end
    if old_count and old_count > 0 then
        local change = math.abs(n - old_count) / old_count
        if change > _M.MAX_CHANGE then
            return nil, string.format(
                "size changed by %.0f%% (%d -> %d)", change * 100, old_count, n)
        end
    end
    return true
end

local function write_atomic(path, body)
    local tmp = path .. ".tmp"
    local f, err = io.open(tmp, "wb")
    if not f then
        return nil, err
    end
    local ok, werr = f:write(body)
    f:close()
    if not ok then
        os.remove(tmp)
        return nil, werr or "write failed"
    end
    ok, werr = os.rename(tmp, path)
    if not ok then
        os.remove(tmp)
        return nil, werr or "rename failed"
    end
    return true
end

function _M.list_path(dir, name)
    return dir .. "/" .. name .. ".list"
end

local crc_tab
local function body_hash(body)
    if ngx and ngx.crc32_long then
        return ngx.crc32_long(body)
    end
    if not crc_tab then
        crc_tab = {}
        for i = 0, 255 do
            local c = i
            for _ = 1, 8 do
                if band(c, 1) == 1 then
                    c = bxor(rshift(c, 1), 0xEDB88320)
                else
                    c = rshift(c, 1)
                end
            end
            crc_tab[i + 1] = c
        end
    end
    local c = 0xffffffff
    for i = 1, #body do
        c = bxor(rshift(c, 8), crc_tab[band(bxor(c, body:byte(i)), 0xff) + 1])
    end
    c = bxor(c, 0xffffffff)
    if c < 0 then
        c = c + 4294967296
    end
    return c
end

function _M.read_list(path, format)
    local f = io.open(path, "rb")
    if not f then
        return nil
    end
    local body = f:read("*a") or ""
    f:close()
    local parsed = _M.parse(body, format or "cidr")
    return parsed.cidrs, body_hash(body)
end

function _M.write_list(dir, name, cidrs)
    _M.ensure_dir(dir)
    local parts = { "# surge " .. #cidrs .. "\n" }
    for i = 1, #cidrs do
        parts[#parts + 1] = cidrs[i] .. "\n"
    end
    return write_atomic(_M.list_path(dir, name), table.concat(parts))
end

function _M.write_note(dir, name, text)
    _M.ensure_dir(dir)
    return write_atomic(dir .. "/" .. name .. ".err", (text or "") .. "\n")
end

function _M.read_note(dir, name)
    local f = io.open(dir .. "/" .. name .. ".err", "rb")
    if not f then
        return nil
    end
    local text = f:read("*l")
    f:close()
    return text
end

-- Returns "updated", count  or  nil, reason. The old file is kept on failure.
function _M.apply_body(dir, name, body, format, old_count)
    local parsed = _M.parse(body, format)
    local ok, err = _M.validate(parsed, old_count)
    if not ok then
        _M.write_note(dir, name, err)
        return nil, err
    end
    local wrote, werr = _M.write_list(dir, name, parsed.cidrs)
    if not wrote then
        return nil, werr
    end
    os.remove(dir .. "/" .. name .. ".err")
    return "updated", #parsed.cidrs
end

function _M.fetch(url, opts, http_mod)
    opts = opts or {}
    http_mod = http_mod or require("resty.http")
    local httpc = http_mod.new()
    httpc:set_timeout(opts.timeout or 15000)
    local headers = {}
    if opts.etag then
        headers["If-None-Match"] = opts.etag
    end
    if opts.modified then
        headers["If-Modified-Since"] = opts.modified
    end
    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = headers,
        ssl_verify = true,
    })
    if not res then
        return nil, err or "request failed"
    end
    if res.status == 304 then
        return nil, "not modified", res
    end
    if res.status ~= 200 then
        return nil, "status " .. tostring(res.status), res
    end
    local body = res.body or ""
    if #body > _M.MAX_BODY then
        return nil, "body too large", res
    end
    return body, nil, res
end

-- Call only after the list file is in place. Saving the ETag first turns a
-- failed write into a permanent 304.
function _M.remember_etag(bag, name, res, stored)
    if not stored or type(res) ~= "table" or type(res.headers) ~= "table" then
        return false
    end
    local tag = res.headers.etag or res.headers.ETag
    if not tag or tag == "" then
        return false
    end
    bag[name] = tag
    return true
end

return _M
