-- Deny bodies are built once, when a decision is published, and stored on
-- the record. The request path only prints the cached string.

local _M = {}

local function esc(s)
    s = s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("<", "&lt;"):gsub(">", "&gt;")
    return s
end

function _M.build(rec, expose)
    local incident = rec.incident or "srg-0"
    local reason = rec.reason or ""
    local message = rec.message or reason
    local show, hdr

    if expose == "id" then
        show = incident
        hdr = nil
    elseif expose == "full" then
        show = message
        hdr = message
    else
        show = incident .. " " .. reason
        hdr = reason
    end

    rec.reason_hdr = hdr
    rec.body_json = '{"incident":"' .. esc(incident)
        .. '","detail":"' .. esc(show) .. '"}'
    rec.body_html = "<!doctype html><meta charset=utf-8><title>"
        .. esc(incident) .. "</title><p>" .. esc(show) .. "</p>"
end

return _M
