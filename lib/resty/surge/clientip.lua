-- CIDR and path rules. Parsing happens at start(); the request path only
-- compares bytes. IPv4-mapped IPv6 (::ffff:0:0/96) is folded to 4 bytes so
-- one client is not two identities.

local bit = require "bit"
local band, lshift, rshift = bit.band, bit.lshift, bit.rshift
local byte = string.byte
local char = string.char
local sub = string.sub

local _M = {}

local function parse_ipv4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil, "bad ipv4"
    end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then
        return nil, "bad ipv4"
    end
    return char(a, b, c, d)
end

local function groups_of(part)
    if part == "" then
        return {}
    end
    local g = {}
    for h in part:gmatch("[^:]+") do
        if not h:match("^[0-9a-fA-F]+$") or #h > 4 then
            return nil
        end
        g[#g + 1] = tonumber(h, 16)
    end
    return g
end

local function parse_ipv6(addr)
    local first = addr:find("::", 1, true)
    if first and addr:find("::", first + 1, true) then
        return nil, "bad ipv6"
    end

    local left, right
    if first then
        left = sub(addr, 1, first - 1)
        right = sub(addr, first + 2)
    else
        left = addr
        right = nil
    end

    local lg = groups_of(left)
    if not lg then
        return nil, "bad ipv6"
    end
    local rg = {}
    if right ~= nil then
        rg = groups_of(right)
        if not rg then
            return nil, "bad ipv6"
        end
    end

    local total = #lg + #rg
    local missing
    if right ~= nil then
        if total > 7 then
            return nil, "bad ipv6"
        end
        missing = 8 - total
    else
        if total ~= 8 then
            return nil, "bad ipv6"
        end
        missing = 0
    end

    local words = {}
    for i = 1, #lg do
        words[#words + 1] = lg[i]
    end
    for _ = 1, missing do
        words[#words + 1] = 0
    end
    for i = 1, #rg do
        words[#words + 1] = rg[i]
    end

    local bytes = {}
    for i = 1, 8 do
        local v = words[i]
        bytes[#bytes + 1] = char(band(rshift(v, 8), 0xff), band(v, 0xff))
    end
    return table.concat(bytes)
end

function _M.parse_cidr(spec)
    local addr, bits = spec:match("^(.+)/(%d+)$")
    if addr then
        bits = tonumber(bits)
    else
        addr = spec
    end

    local bin, err, maxb
    if addr:find(":", 1, true) then
        bin, err = parse_ipv6(addr)
        maxb = 128
        bits = bits or 128
    else
        bin, err = parse_ipv4(addr)
        maxb = 32
        bits = bits or 32
    end
    if not bin then
        return nil, err
    end
    if bits < 0 or bits > maxb then
        return nil, "bad prefix length"
    end
    return { bin = bin, bits = bits, v6 = #bin == 16 }
end

function _M.matches(rule, bin)
    if #bin ~= #rule.bin then
        return false
    end
    local full = math.floor(rule.bits / 8)
    for i = 1, full do
        if byte(bin, i) ~= byte(rule.bin, i) then
            return false
        end
    end
    local rem = rule.bits % 8
    if rem == 0 then
        return true
    end
    local mask = band(lshift(0xff, 8 - rem), 0xff)
    local i = full + 1
    return band(byte(bin, i), mask) == band(byte(rule.bin, i), mask)
end

-- 4-byte string, 16-byte string, or nil for a unix socket path.
function _M.identity(bin)
    local n = #bin
    if n == 4 then
        return "v4", bin
    end
    if n ~= 16 then
        return nil, bin
    end
    for i = 1, 10 do
        if byte(bin, i) ~= 0 then
            return "v6", bin
        end
    end
    if byte(bin, 11) == 0xff and byte(bin, 12) == 0xff then
        return "v4", sub(bin, 13, 16)
    end
    return "v6", bin
end

function _M.peer_trusted(bin, rules)
    for i = 1, #rules do
        if _M.matches(rules[i], bin) then
            return true
        end
    end
    return false
end

-- One X-Forwarded-For token: "1.2.3.4", "1.2.3.4:443", or "[2001:db8::1]:443".
function _M.parse_ip(token)
    if type(token) ~= "string" then
        return nil
    end
    token = token:match("^%s*(.-)%s*$")
    if not token or token == "" then
        return nil
    end
    if token:sub(1, 1) == "[" then
        token = token:match("^%[([^%]]+)%]")
        if not token then
            return nil
        end
    else
        local v4 = token:match("^(%d+%.%d+%.%d+%.%d+):%d+$")
        if v4 then
            token = v4
        end
    end
    local rule = _M.parse_cidr(token)
    if not rule then
        return nil
    end
    return rule.v6 and "v6" or "v4", rule.bin
end

-- Rightmost address that is not itself a trusted proxy. Entries further
-- left are the client-supplied prefix and are ignored. Only the last
-- `limit` hops are examined.
function _M.client_from_xff(header, trusted, limit)
    if type(header) ~= "string" or header == "" then
        return nil
    end
    limit = limit or 8
    local parts = {}
    for token in header:gmatch("[^,]+") do
        parts[#parts + 1] = token
    end
    local start_at = 1
    if #parts > limit then
        start_at = #parts - limit + 1
    end
    local leftmost = nil
    for i = #parts, start_at, -1 do
        local fam, bin = _M.parse_ip(parts[i])
        if fam then
            leftmost = { fam, bin }
            if not _M.peer_trusted(bin, trusted) then
                return fam, bin
            end
        end
    end
    if leftmost then
        return leftmost[1], leftmost[2]
    end
    return nil
end

-- Peer address, unless that peer is a trusted proxy and nginx real_ip has
-- not already replaced it. opts.xff is ignored for every other request so
-- the header is not part of the normal path.
function _M.client_addr(peer_bin, opts)
    opts = opts or {}
    local family, bin = _M.identity(peer_bin)
    if not family then
        return nil
    end
    local trusted = opts.trusted
    if not trusted or #trusted == 0 or opts.realip_rewritten
        or not _M.peer_trusted(bin, trusted)
    then
        return family, bin
    end
    local fam, b2 = _M.client_from_xff(opts.xff, trusted, opts.limit or 8)
    if not fam then
        return family, bin
    end
    return fam, b2
end

-- Allow entries are CIDRs or path prefixes (leading /).
function _M.allow_rule(spec)
    if type(spec) ~= "string" or spec == "" then
        return nil, "allow entries must be strings"
    end
    if sub(spec, 1, 1) == "/" then
        return { path = spec }
    end
    return _M.parse_cidr(spec)
end

return _M
