-- Generic Cell Rate Algorithm. One theoretical arrival time per key.
--
-- interval = 1/rate, tau = (burst-1)/rate.
-- Allow when now >= tat - tau, then tat = max(now, tat) + interval.
-- burst=1 allows no two requests closer than `interval`. burst=N allows N
-- requests at the same instant and then exactly `rate` per second.
--
-- Callers that enforce per worker pass rate/n_workers as the rate. The
-- burst is not divided: each worker allows a full burst, so a client that
-- lands on every worker can burst about n_workers times the configured
-- burst. That is the trade for not touching the shared dict on the request
-- that is merely being limited. Keys that are not in the limit stage never
-- call this.

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

-- Per-worker rate. Burst stays as configured; see the note above.
function _M.worker_params(global_rate, burst, n_workers)
    if not n_workers or n_workers < 1 then
        n_workers = 1
    end
    return _M.params(global_rate / n_workers, burst)
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

return _M
