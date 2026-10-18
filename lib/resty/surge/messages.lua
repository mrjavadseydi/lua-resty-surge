-- One sentence per decision. Built when the decision is created, not per request.

local byte = string.byte

local _M = {}

-- RFC 5952: lowercase, no leading zeros, the longest run of two or more
-- zero groups as "::".
local function v6_text(key)
    key = key .. string.rep("\0", 16 - #key)
    local g = {}
    for i = 1, 8 do
        local hi, lo = byte(key, i * 2 - 1, i * 2)
        g[i] = hi * 256 + lo
    end
    local best, best_n, run, run_n = 0, 0, 0, 0
    for i = 1, 8 do
        if g[i] == 0 then
            if run_n == 0 then
                run = i
            end
            run_n = run_n + 1
            if run_n > best_n then
                best, best_n = run, run_n
            end
        else
            run_n = 0
        end
    end
    local function part(a, b)
        local o = {}
        for i = a, b do
            o[#o + 1] = string.format("%x", g[i])
        end
        return table.concat(o, ":")
    end
    if best_n < 2 then
        return part(1, 8)
    end
    return part(1, best - 1) .. "::" .. part(best + best_n, 8)
end

-- `v6` says the family; without it a key longer than 4 bytes is IPv6.
function _M.label(key, bits, v6)
    local n = #key
    if v6 == nil then
        v6 = n > 4
    end
    if v6 and n <= 16 then
        local s = v6_text(key)
        if bits and bits < 128 then
            return s .. "/" .. bits
        end
        return s
    end
    if n <= 4 then
        local o = {}
        for i = 1, n do
            o[i] = tostring(byte(key, i))
        end
        while #o < 4 do
            o[#o + 1] = "0"
        end
        local s = table.concat(o, ".")
        if bits and bits < 32 then
            return s .. "/" .. bits
        end
        return s
    end
    return key
end

function _M.line(action, label, share, base, rps, window)
    local verb = "Watching"
    if action == "block" then
        verb = "Blocked"
    elseif action == "limit" then
        verb = "Limited"
    elseif action == "challenge" then
        verb = "Challenging"
    end
    return string.format(
        "%s %s: %.1f%% of traffic in the last %.2fs (normal %.1f%%), %.0f rps.",
        verb, label, (share or 0) * 100, window or 0,
        (base or 0) * 100, rps or 0)
end

return _M
