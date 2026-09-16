-- One line per key per second. The request path does not call this.

local _M = {}
local last = {}

function _M.limited(key, level, msg)
    local now = ngx.now()
    local prev = last[key]
    if prev and now - prev < 1 then
        return
    end
    last[key] = now
    ngx.log(level, msg)
end

return _M
