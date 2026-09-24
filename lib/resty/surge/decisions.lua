-- Worker-local decision trie and the snapshot blob the leader publishes.
--
-- Lookup walks raw address bytes. No prefix string is built on the request.
-- A non-byte-aligned CIDR (/20) hangs off the last full byte and is checked
-- with a mask, because the host bits of that byte differ per client.
-- The trie is built in the timer and swapped in as one table, so a request
-- never sees a half-built tree.

local bit = require "bit"
local band, lshift, rshift = bit.band, bit.lshift, bit.rshift
local byte = string.byte
local char = string.char
local sub = string.sub

local _M = {}

local function node()
    return { kids = {} }
end

function _M.new_trie()
    return node()
end

local function add_partial(n, bits, key, dec)
    local full = math.floor(bits / 8)
    local rem = bits % 8
    local mask = band(lshift(0xff, 8 - rem), 0xff)
    local value = band(byte(key, full + 1), mask)
    local list = n.partial
    if not list then
        list = {}
        n.partial = list
    end
    list[#list + 1] = { mask = mask, value = value, bits = bits, dec = dec }
end

function _M.insert(root, key, bits, dec)
    if bits <= 0 then
        root.decision = dec
        root.bits = 0
        return
    end
    local full = math.floor(bits / 8)
    local n = root
    for i = 1, full do
        local b = byte(key, i)
        local child = n.kids[b]
        if not child then
            child = node()
            n.kids[b] = child
        end
        n = child
    end
    if bits % 8 == 0 then
        n.decision = dec
        n.bits = bits
    else
        add_partial(n, bits, key, dec)
    end
end

-- `accept(dec)` is false for a URI-scoped decision that does not apply.
-- A shorter unscoped match is kept when a longer scoped one does not apply.
function _M.lookup(root, bin, accept)
    local n = root
    local best, best_bits = nil, -1
    if n.decision and accept(n.decision) then
        best, best_bits = n.decision, n.bits or 0
    end
    for i = 1, #bin do
        local b = byte(bin, i)
        local parts = n.partial
        if parts then
            for p = 1, #parts do
                local rule = parts[p]
                if band(b, rule.mask) == rule.value
                    and rule.bits > best_bits
                    and accept(rule.dec)
                then
                    best = rule.dec
                    best_bits = rule.bits
                end
            end
        end
        local child = n.kids[b]
        if not child then
            return best
        end
        n = child
        if n.decision and n.bits > best_bits and accept(n.decision) then
            best = n.decision
            best_bits = n.bits
        end
    end
    return best
end

function _M.build(list)
    local v4 = node()
    local v6 = node()
    for i = 1, #list do
        local rec = list[i]
        if rec.family == "v4" or rec.family == "v6" then
            local root = rec.family == "v6" and v6 or v4
            _M.insert(root, rec.key, rec.bits, rec)
        end
    end
    return v4, v6
end

local function u16(n)
    return char(band(n, 0xff), band(rshift(n, 8), 0xff))
end

local function u32(n)
    if n < 0 then
        n = 0
    elseif n > 4294967295 then
        n = 4294967295
    end
    n = math.floor(n)
    return char(
        band(n, 0xff),
        band(rshift(n, 8), 0xff),
        band(rshift(n, 16), 0xff),
        band(rshift(n, 24), 0xff)
    )
end

local function wstr(s)
    s = s or ""
    return u16(#s) .. s
end

local function r16(s, i)
    local a, b = byte(s, i, i + 1)
    if not a or not b then
        return nil, i
    end
    return a + b * 256, i + 2
end

local function r32(s, i)
    local a, b, c, d = byte(s, i, i + 3)
    if not d then
        return nil, i
    end
    return a + b * 256 + c * 65536 + d * 16777216, i + 4
end

local function rstr(s, i)
    local n, j = r16(s, i)
    if not n then
        return nil, i
    end
    if j + n - 1 > #s then
        return nil, i
    end
    return sub(s, j, j + n - 1), j + n
end

local FAMILY = { [6] = "v6", [16] = "fp", [32] = "host" }

function _M.encode(snap)
    local list = snap.list or {}
    -- The count is u16. Past it, drop the tail here instead of letting the
    -- count wrap and the decoder drop records nobody chose.
    local n = #list
    if n > 65535 then
        n = 65535
    end
    local parts = { wstr(snap.mode or "normal"), u16(n) }
    for i = 1, n do
        local r = list[i]
        local fam = 4
        if r.family == "v6" then
            fam = 6
        elseif r.family == "fp" then
            fam = 16
        elseif r.family == "host" then
            fam = 32
        end
        parts[#parts + 1] = char(fam)
        parts[#parts + 1] = char(r.bits or 0)
        parts[#parts + 1] = wstr(r.key or "")
        parts[#parts + 1] = wstr(r.action or "block")
        parts[#parts + 1] = wstr(r.reason or "")
        parts[#parts + 1] = wstr(r.message or "")
        parts[#parts + 1] = wstr(r.uri or "")
        parts[#parts + 1] = char(r.close and 1 or 0)
        parts[#parts + 1] = u16(r.status or 403)
        parts[#parts + 1] = u32(r.ttl or 0)
        parts[#parts + 1] = wstr(r.incident or "")
        -- manual and until_ts have to cross workers and a leader restart.
        -- A block that lives only in worker 0's memory is gone on the next tick.
        parts[#parts + 1] = char(r.manual and 1 or 0)
        parts[#parts + 1] = u32(math.floor(r.until_ts or 0))
        -- Confidence has to cross workers. The export uses it, and a leader
        -- that only sees the snapshot would otherwise treat it as zero.
        local conf = math.floor((r.confidence or 0) * 10000)
        if conf < 0 then
            conf = 0
        elseif conf > 10000 then
            conf = 10000
        end
        parts[#parts + 1] = u16(conf)
        -- A host decision's site cap. Without it every worker but the leader
        -- falls back to limit_rps. Milli-rps, so a fractional cap survives.
        parts[#parts + 1] = u32((r.rate or 0) * 1000)
    end
    return table.concat(parts)
end

function _M.decode(blob)
    if type(blob) ~= "string" then
        return nil, "empty snapshot"
    end
    local mode, i = rstr(blob, 1)
    if not mode then
        return nil, "truncated mode"
    end
    local n, j = r16(blob, i)
    if not n then
        return nil, "truncated count"
    end
    i = j
    local list = {}
    for k = 1, n do
        local fam = byte(blob, i)
        local bits = byte(blob, i + 1)
        if not bits then
            return nil, "truncated record"
        end
        i = i + 2
        local key
        key, i = rstr(blob, i)
        if not key then
            return nil, "truncated key"
        end
        local action, reason, message, uri
        action, i = rstr(blob, i)
        reason, i = rstr(blob, i)
        message, i = rstr(blob, i)
        uri, i = rstr(blob, i)
        if not uri then
            return nil, "truncated fields"
        end
        local close = byte(blob, i)
        local status
        status, i = r16(blob, i + 1)
        local ttl
        ttl, i = r32(blob, i)
        local incident
        incident, i = rstr(blob, i)
        local flags = byte(blob, i)
        local until_ts
        until_ts, i = r32(blob, i + 1)
        local conf_i
        conf_i, i = r16(blob, i)
        local rate_m
        rate_m, i = r32(blob, i)
        if not incident or not ttl or not until_ts or not conf_i or not rate_m then
            return nil, "truncated tail"
        end
        list[k] = {
            family = FAMILY[fam] or "v4",
            bits = bits,
            key = key,
            action = action,
            reason = reason,
            message = message,
            uri = uri ~= "" and uri or nil,
            close = close == 1,
            status = status,
            ttl = ttl,
            incident = incident,
            manual = flags == 1,
            until_ts = until_ts ~= 0 and until_ts or nil,
            confidence = conf_i > 0 and (conf_i / 10000) or nil,
            rate = rate_m > 0 and (rate_m / 1000) or nil,
        }
    end
    return { mode = mode, list = list }
end

return _M
