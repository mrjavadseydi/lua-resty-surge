-- Generic Cell Rate Algorithm. One theoretical arrival time per key.
--
-- interval = 1/rate, tau = (burst-1)/rate.
-- Allow when now >= tat - tau, then tat = max(now, tat) + interval.
-- burst=1 allows no two requests closer than `interval`. burst=N allows N
-- requests at the same instant and then exactly `rate` per second.
--
-- shared() runs the same algorithm on a shared dict, so the limit is the
-- node's and not each worker's. Keys that are not in the limit stage never
-- call it.

local _M = {}

function _M.params(rate, burst)
    if not rate or rate <= 0 then
        error("gcra: rate must be > 0")
    end
    if not burst or burst < 1 then
        error("gcra: burst must be >= 1")
    end
    local interval = 1 / rate
    return interval, (burst - 1) * interval
end

-- Returns allow, new_tat. On reject, new_tat is the previous tat.
function _M.check(tat, now, interval, tau)
    if tat == nil then
        return true, now + interval
    end
    if now < tat - tau then
        return false, tat
    end
    if now > tat then
        return true, now + interval
    end
    return true, tat + interval
end

-- Do not yield while holding the lock: protect() uses worker-local scratch.
-- Contention rejects this request without adding debt. A full dict fails open.
function _M.shared(dict, key, now, interval, tau, ttl)
    local lock = key .. ":lock"
    local locked, err = dict:safe_add(lock, true, 1)
    if not locked then
        return err ~= "exists"
    end
    local allow, tat = _M.check(dict:get(key), now, interval, tau)
    if allow then
        dict:safe_set(key, tat, ttl)
    end
    dict:delete(lock)
    return allow
end

return _M
