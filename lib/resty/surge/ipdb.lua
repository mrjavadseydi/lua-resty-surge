-- Worker-local CIDR tries for reputation feeds.
--
-- Built in the timer (or at start) from the files on disk, then the table
-- reference is swapped. A request holds one reference for the lookup, so it
-- never walks a trie that is still being filled.
-- lua-resty-ipmatcher matches textual addresses. This trie matches the
-- binary address protect() already read, so the request path does not
-- format an IP. bench/radix.lua times both.

local clientip = require "resty.surge.clientip"
local decisions = require "resty.surge.decisions"
local respond = require "resty.surge.respond"

local _M = {}

local function always()
    return true
end

local function record(name, allow, expose)
    local reason = allow and ("allow:" .. name) or ("reputation:" .. name)
    local rec = {
        action = allow and "allow" or "block",
        reason = reason,
        message = allow
            and ("Allow feed " .. name)
            or ("Reputation feed " .. name .. " lists this address."),
        incident = "srg-feed-" .. name,
        status = 403,
        close = false,
        ttl = 0,
        feed = name,
    }
    if not allow then
        respond.build(rec, expose or "short")
    end
    return rec
end

-- groups: { { name, allow, cidrs = { "1.2.3.0/24", ... } }, ... }
function _M.compile(groups, expose)
    local block4, block6 = decisions.new_trie(), decisions.new_trie()
    local allow4, allow6 = decisions.new_trie(), decisions.new_trie()
    local report = {}
    local block_n, allow_n = 0, 0

    for g = 1, #groups do
        local group = groups[g]
        local rec = record(group.name, group.allow, expose)
        local n = 0
        local cidrs = group.cidrs or {}
        for i = 1, #cidrs do
            local rule = clientip.parse_cidr(cidrs[i])
            if rule then
                local trie
                if group.allow then
                    trie = rule.v6 and allow6 or allow4
                else
                    trie = rule.v6 and block6 or block4
                end
                decisions.insert(trie, rule.bin, rule.bits, rec)
                n = n + 1
            end
        end
        if group.allow then
            allow_n = allow_n + n
        else
            block_n = block_n + n
        end
        report[#report + 1] = {
            name = group.name,
            count = n,
            allow = group.allow and true or false,
            error = group.error,
        }
    end

    return {
        block4 = block_n > 0 and block4 or nil,
        block6 = block_n > 0 and block6 or nil,
        allow4 = allow_n > 0 and allow4 or nil,
        allow6 = allow_n > 0 and allow6 or nil,
        report = report,
    }
end

function _M.hit(trie, bin)
    if not trie then
        return nil
    end
    return decisions.lookup(trie, bin, always)
end

return _M
