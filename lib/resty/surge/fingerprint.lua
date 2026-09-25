-- Compact HTTP fingerprint, computed only in elevated and attack mode.
--
-- The key records method, version, a fixed header set, a hash of the
-- User-Agent, the first Accept-Language tag, and whether a cookie exists.
-- The cookie value is never part of the key. HTTP/1 keeps the wire order of
-- that header set. HTTP/2 and HTTP/3 do not: raw_header() aborts those
-- requests, so the version tag changes and the order is omitted.

local bit = require "bit"
local clear = require "table.clear"
local byte = string.byte
local find, sub, lower = string.find, string.sub, string.lower
local band, bxor, rshift = bit.band, bit.bxor, bit.rshift

local _M = {}

_M.CAP = 32

-- One letter per header so the order string stays short.
local CODE = {
    ["accept"] = "a",
    ["accept-language"] = "l",
    ["accept-encoding"] = "e",
    ["user-agent"] = "u",
    ["cookie"] = "c",
    ["referer"] = "r",
    ["connection"] = "n",
    ["sec-ch-ua"] = "h",
    ["sec-fetch-site"] = "s",
    ["sec-fetch-mode"] = "m",
    ["sec-fetch-dest"] = "d",
}

local crc_tab
local function crc_table()
    if crc_tab then
        return crc_tab
    end
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
    return crc_tab
end

function _M.crc32(s)
    local tab = crc_table()
    local c = 0xffffffff
    for i = 1, #s do
        c = bxor(rshift(c, 8), tab[band(bxor(c, byte(s, i)), 0xff) + 1])
    end
    c = bxor(c, 0xffffffff)
    if c < 0 then
        c = c + 4294967296
    end
    return c
end

-- Same IEEE CRC-32, in C. The Lua loop stays for plain-luajit specs.
if ngx and ngx.crc32_short then
    _M.crc32 = ngx.crc32_short
end

local function hex8(n)
    return string.format("%08x", n)
end

local function first_lang(s)
    if type(s) ~= "string" then
        return ""
    end
    s = s:match("^%s*([^,;]+)") or ""
    s = s:lower():gsub("[^a-z0-9%-]", "")
    if #s > 8 then
        s = s:sub(1, 8)
    end
    return s
end

-- The challenge cookie must not change the key. A solved browser would
-- otherwise become a new fingerprint and miss the decision it just passed.
function _M.foreign_cookie(value)
    if type(value) == "table" then
        for i = 1, #value do
            if _M.foreign_cookie(value[i]) then
                return true
            end
        end
        return false
    end
    if type(value) ~= "string" or value == "" then
        return false
    end
    for part in value:gmatch("[^;]+") do
        local name = part:match("^%s*([^=;%s]+)")
        if name and name ~= "srg_pow" then
            return true
        end
    end
    return false
end

function _M.presence(headers)
    local codes = {}
    for name, code in pairs(CODE) do
        if headers[name] ~= nil then
            codes[#codes + 1] = code
        end
    end
    table.sort(codes)
    return table.concat(codes)
end

-- Scratch for parse_raw and capture. Filled and consumed within one call;
-- nothing here yields, so one set per worker is enough.
local order_buf, seen_buf, fields_buf = {}, {}, {}

-- `raw` is the header block without the request line (raw_header(true)).
-- Walks it by index: no string per line, and a value is cut only for the
-- three headers the key reads. Header names are short and repeat, so their
-- sub() is usually an interned hit. `out` is filled if given.
function _M.parse_raw(raw, cap, out)
    cap = cap or _M.CAP
    raw = raw or ""
    local order, seen = order_buf, seen_buf
    clear(order)
    clear(seen)
    local ua, lang, cookie
    local n, pos, len = 0, 1, #raw
    while pos <= len do
        local eol = find(raw, "[\r\n]", pos) or len + 1
        if eol > pos then
            n = n + 1
            if n > cap then
                break
            end
            local colon = find(raw, ":", pos, true)
            if colon and colon > pos and colon < eol then
                local code = CODE[lower(sub(raw, pos, colon - 1))]
                if code then
                    if not seen[code] then
                        seen[code] = true
                        order[#order + 1] = code
                    end
                    if (code == "u" and not ua) or (code == "l" and not lang)
                        or (code == "c" and not cookie)
                    then
                        local vs = find(raw, "[^ \t\v\f]", colon + 1) or eol
                        if vs > eol then
                            vs = eol
                        end
                        local value = sub(raw, vs, eol - 1)
                        if code == "u" then
                            ua = value
                        elseif code == "l" then
                            lang = value
                        elseif _M.foreign_cookie(value) then
                            cookie = true
                        end
                    end
                end
            end
        end
        pos = eol + 1
    end
    out = out or {}
    out.ordered = true
    out.order = table.concat(order)
    out.ua = ua
    out.lang = lang
    out.cookie = cookie and true or false
    return out
end

function _M.short(key)
    return string.format("%08x", _M.crc32(key or ""))
end

function _M.build(fields)
    fields = fields or {}
    local method = (fields.method or "GET"):upper():gsub("[^A-Z]", "")
    if method == "" then
        method = "GET"
    end
    if #method > 7 then
        method = method:sub(1, 7)
    end
    local http = fields.http or "11"
    local seq = fields.ordered and (fields.order or "") or (fields.presence or "")
    local tag = fields.ordered and "1" or "2"
    local ja = ""
    if type(fields.ja4) == "string" and fields.ja4 ~= "" then
        ja = fields.ja4:lower():gsub("[^0-9a-z_]", "")
        if #ja > 48 then
            ja = ja:sub(1, 48)
        end
    end
    local key = tag .. method .. http .. seq .. hex8(_M.crc32(fields.ua or ""))
        .. first_lang(fields.lang) .. (fields.cookie and "1" or "0") .. ja
    return key
end

local function one(v)
    if type(v) == "table" then
        return v[1]
    end
    return v
end

-- Reads headers. Callers must not use this in normal mode.
function _M.capture()
    local ver = ngx.req.http_version() or 0
    local http = "09"
    if ver >= 3 then
        http = "30"
    elseif ver >= 2 then
        http = "20"
    elseif ver >= 1.1 then
        http = "11"
    elseif ver >= 1 then
        http = "10"
    end
    local fields
    if ver > 0 and ver < 2 then
        fields = fields_buf
        clear(fields)
        _M.parse_raw(ngx.req.raw_header(true), _M.CAP, fields)
    else
        local h = ngx.req.get_headers(_M.CAP) or {}
        fields = {
            ordered = false,
            presence = _M.presence(h),
            ua = one(h["user-agent"]),
            lang = one(h["accept-language"]),
            cookie = _M.foreign_cookie(h["cookie"]),
        }
    end
    fields.method = ngx.req.get_method()
    fields.http = http
    local ctx = ngx.ctx
    if ctx and type(ctx.ja4) == "string" then
        fields.ja4 = ctx.ja4
    end
    return _M.build(fields)
end

return _M
