-- Optional nftables feed. Only IP blocks are exported. The file is
-- replaced with an atomic rename. Lua never calls os.execute.

local bit = require "bit"

local _M = {}

local function ipv4(key)
    if #key == 0 or #key > 4 then
        return nil
    end
    if #key < 4 then
        key = key .. string.rep("\0", 4 - #key)
    end
    local a, b, c, d = key:byte(1, 4)
    return string.format("%d.%d.%d.%d", a, b, c, d)
end

local function ipv6(key)
    if #key == 0 or #key > 16 then
        return nil
    end
    if #key < 16 then
        key = key .. string.rep("\0", 16 - #key)
    end
    local parts = {}
    for i = 1, 16, 2 do
        parts[#parts + 1] = string.format("%02x%02x", key:byte(i, i + 1))
    end
    return table.concat(parts, ":")
end

-- The key padded to the family's length with the bits past `bits` cleared.
local function masked(key, bits, len)
    if #key > len then
        return nil
    end
    key = key .. string.rep("\0", len - #key)
    local full = math.floor(bits / 8)
    local rem = bits % 8
    if full >= len then
        return key
    end
    local head = key:sub(1, full)
    if rem > 0 then
        local keep = 256 - 2 ^ (8 - rem)
        head = head .. string.char(bit.band(key:byte(full + 1), keep))
        full = full + 1
    end
    return head .. string.rep("\0", len - full)
end

-- One line: family, prefix length, address, seconds of ttl, incident.
-- nft rejects a whole batch with "conflicting intervals" when one element
-- overlaps another, so a network inside one already listed is left out and
-- the same network twice keeps the longer ttl. The inner one is written
-- again once the outer one expires and the list is republished.
function _M.lines(list, now, min_confidence)
    local floor_c = min_confidence or 0.9
    local cand = {}
    for i = 1, #(list or {}) do
        local r = list[i]
        local ip = r.family == "v4" or r.family == "v6"
        if ip and r.action == "block" and not r.uri then
            local conf = r.confidence or (r.manual and 1 or 0)
            if r.manual or conf >= floor_c then
                local len = r.family == "v6" and 16 or 4
                local bits = r.bits or (#r.key * 8)
                local key = masked(r.key, bits, len)
                local ttl
                if r.until_ts and now then
                    -- A record past until_ts must not be given a fresh timeout.
                    ttl = math.floor(r.until_ts - now)
                else
                    ttl = r.ttl or 0
                end
                if key and ttl > 0 then
                    cand[#cand + 1] = { fam = r.family, bits = bits, key = key,
                        ttl = ttl, incident = r.incident or "-" }
                end
            end
        end
    end
    table.sort(cand, function(a, b)
        if a.bits ~= b.bits then
            return a.bits < b.bits
        end
        return a.ttl > b.ttl
    end)
    -- Kept networks by family and prefix length, as masked keys.
    local kept = { v4 = {}, v6 = {} }
    local lens = { v4 = {}, v6 = {} }
    local out = {}
    for i = 1, #cand do
        local c = cand[i]
        local len = c.fam == "v6" and 16 or 4
        local covered = false
        for _, b in ipairs(lens[c.fam]) do
            if kept[c.fam][b][masked(c.key, b, len)] then
                covered = true
                break
            end
        end
        if not covered then
            local by = kept[c.fam][c.bits]
            if not by then
                by = {}
                kept[c.fam][c.bits] = by
                local l = lens[c.fam]
                l[#l + 1] = c.bits
            end
            by[c.key] = true
            out[#out + 1] = string.format("%s %d %s %d %s", c.fam, c.bits,
                c.fam == "v6" and ipv6(c.key) or ipv4(c.key), c.ttl, c.incident)
        end
    end
    table.sort(out)
    return out
end

function _M.write(path, list, now, min_confidence)
    local lines = _M.lines(list, now, min_confidence)
    local body = table.concat(lines, "\n")
    if #lines > 0 then
        body = body .. "\n"
    end
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

return _M
