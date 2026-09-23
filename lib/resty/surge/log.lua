-- One line per key per second. The request path does not call this.

local _M = {}
local last = {}
local n = 0

function _M.limited(key, level, msg)
    local now = ngx.now()
    local prev = last[key]
    if prev and now - prev < 1 then
        return
    end
    if not prev then
        n = n + 1
        -- ponytail: keys are incident ids; wipe instead of LRU. Worst case is
        -- one extra line per key after a wipe.
        if n > 1024 then
            last, n = {}, 1
        end
    end
    last[key] = now
    ngx.log(level, msg)
end

return _M
