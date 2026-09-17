-- One sentence per decision. Built when the decision is created, not per request.

local byte = string.byte

local _M = {}

function _M.label(key, bits)
    local n = #key
    if n > 0 and n <= 4 then
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
    if bits and n > 4 then
        local hex = {}
        for i = 1, n do
            hex[i] = string.format("%02x", byte(key, i))
        end
        return table.concat(hex) .. "/" .. bits
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
