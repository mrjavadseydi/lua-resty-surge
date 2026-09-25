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

-- GCRA on a shared dict with incr only: no lock, one incr per allowed
-- request, two per denied one. The dict holds tat in absolute seconds, so
-- a rate that changes between ticks does not corrupt it. Two workers that
-- both see a stale tat both move it forward; that denies a little early,
-- never late. A full dict fails open.
function _M.shared(dict, key, now, interval, tau, ttl)
    local v = dict:incr(key, interval, now, ttl)
    if not v then
        return true
    end
    local tat = v - interval
    if tat < now then
        dict:incr(key, now - tat)
        return true
    end
    if tat - tau > now then
        dict:incr(key, -interval)
        return false
    end
    return true
end

return _M
