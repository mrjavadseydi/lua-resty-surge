-- Prometheus text. Labels are result and reason only. Never an address.

local _M = {}

local function num(v)
    v = tonumber(v) or 0
    return string.format("%.0f", v)
end

function _M.prometheus(s)
    local lines = {
        "# HELP surge_mode 0 normal, 1 elevated, 2 attack",
        "# TYPE surge_mode gauge",
    }
    local mode = s.mode or "normal"
    local code = 0
    if mode == "elevated" then
        code = 1
    elseif mode == "attack" then
        code = 2
    end
    lines[#lines + 1] = "surge_mode " .. code
    lines[#lines + 1] = "# HELP surge_requests_total Requests by result."
    lines[#lines + 1] = "# TYPE surge_requests_total counter"
    local totals = s.totals or {}
    for _, result in ipairs({ "allowed", "limited", "challenged", "blocked" }) do
        lines[#lines + 1] = string.format(
            'surge_requests_total{result="%s"} %s', result, num(totals[result]))
    end
    lines[#lines + 1] = "# HELP surge_blocked_total Blocked requests by reason."
    lines[#lines + 1] = "# TYPE surge_blocked_total counter"
    local reasons = s.reasons or {}
    local names = {}
    for name in pairs(reasons) do
        names[#names + 1] = name
    end
    table.sort(names)
    for i = 1, #names do
        local name = names[i]
        local safe = name:gsub("[^%w_:]", "_")
        lines[#lines + 1] = string.format(
            'surge_blocked_total{reason="%s"} %s', safe, num(reasons[name]))
    end
    lines[#lines + 1] = "# HELP surge_decisions Active decisions."
    lines[#lines + 1] = "# TYPE surge_decisions gauge"
    lines[#lines + 1] = "surge_decisions " .. num(s.decisions)
    lines[#lines + 1] = "# HELP surge_feed_networks Networks loaded from a feed."
    lines[#lines + 1] = "# TYPE surge_feed_networks gauge"
    local feeds = s.feeds or {}
    for i = 1, #feeds do
        local f = feeds[i]
        local role = f.allow and "allow" or "block"
        local name = tostring(f.name or "feed"):gsub("[^%w_:]", "_")
        lines[#lines + 1] = string.format(
            'surge_feed_networks{feed="%s",role="%s"} %s',
            name, role, num(f.count))
    end
    return table.concat(lines, "\n") .. "\n"
end

return _M
