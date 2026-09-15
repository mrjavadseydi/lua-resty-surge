-- Normalized Shannon entropy over a merged histogram.
--
-- H = -Σ p_i log2(p_i), H_norm = H / log2(n). n counts buckets with a
-- positive count, including the "other" bucket when the caller put it in
-- the list. A single bucket has H_norm 0 (log2(1) is 0, so the ratio is
-- defined as 0 rather than left undefined). Uniform over n is 1.
--
-- The tracker is an EWMA of H_norm. Pass frozen=true while the process is
-- in elevated or attack mode so the reference distribution does not learn
-- the attack.

local log = math.log
local exp = math.exp
local LOG2 = log(2)

local _M = {}

function _M.normalized(counts)
    local n = 0
    local total = 0
    for i = 1, #counts do
        local c = counts[i]
        if c > 0 then
            n = n + 1
            total = total + c
        end
    end
    if n <= 1 or total <= 0 then
        return 0
    end

    local h = 0
    for i = 1, #counts do
        local c = counts[i]
        if c > 0 then
            local p = c / total
            h = h - p * log(p)
        end
    end
    h = h / LOG2
    return h / (log(n) / LOG2)
end

function _M.new_tracker(half_life, tick)
    if half_life <= 0 or tick <= 0 then
        error("entropy: half_life and tick must be > 0")
    end
    local alpha = 1 - exp(-tick / half_life)
    local mean = nil

    local tracker = {}

    function tracker.update(_, h, frozen)
        if frozen then
            return mean
        end
        if mean == nil then
            mean = h
        else
            mean = mean + alpha * (h - mean)
        end
        return mean
    end

    function tracker.mean()
        return mean
    end

    return tracker
end

return _M
