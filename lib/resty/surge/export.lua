-- Optional nftables feed. Only IP blocks are exported. The file is
-- replaced with an atomic rename. Lua never calls os.execute.

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

-- One line: family, prefix length, address, seconds of ttl, incident.
function _M.lines(list, now, min_confidence)
    local out = {}
    local floor_c = min_confidence or 0.9
    for i = 1, #(list or {}) do
        local r = list[i]
        if r.action == "block" and not r.uri then
            local conf = r.confidence or (r.manual and 1 or 0)
            if r.manual or conf >= floor_c then
                local addr = r.family == "v6" and ipv6(r.key) or ipv4(r.key)
                local ttl
                if r.until_ts and now then
                    -- A record past until_ts must not be given a fresh timeout.
                    ttl = math.floor(r.until_ts - now)
                else
                    ttl = r.ttl or 0
                end
                if addr and ttl > 0 then
                    out[#out + 1] = string.format("%s %d %s %d %s",
                        r.family == "v6" and "v6" or "v4",
                        r.bits or (#r.key * 8), addr, ttl, r.incident or "-")
                end
            end
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
