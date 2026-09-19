-- EWMA mean and variance of the global request rate.
--
-- α = 1 - exp(-tick / half_life)
-- diff = r - mean; incr = α * diff
-- mean = mean + incr
-- var  = (1 - α) * (var + diff * incr)
--
-- The sample is compared to the baseline from *before* the update. An attack
-- tick must not be folded into the average it is being judged against.
-- While the mode is elevated or attack the average is frozen, otherwise a
-- long flood slowly becomes "normal".
--
-- In normal mode a positive step is clamped to
-- mean * max_growth_per_hour * tick/3600. A ramp of a couple of percent a
-- minute then cannot hide inside the average. Organic growth still crosses
-- into elevated; that mode only counts more, it does not block anyone.
-- The first sample sets the mean with no clamp, so a cold process is not
-- stuck at zero.

local exp = math.exp
local sqrt = math.sqrt
local max = math.max

local _M = {}

local function sigma_of(var)
    if var > 0 then
        return sqrt(var)
    end
    return 0
end

function _M.new(opts)
    if opts.tick <= 0 or opts.half_life <= 0 then
        error("baseline: tick and half_life must be > 0")
    end
    return {
        tick = opts.tick,
        half_life = opts.half_life,
        alpha = 1 - exp(-opts.tick / opts.half_life),
        k_elev = opts.k_elev,
        k_attack = opts.k_attack,
        min_rps = opts.min_rps or 0,
        cooldown = opts.cooldown or 0,
        warmup = opts.warmup or 0,
        max_growth_per_hour = opts.max_growth_per_hour or 1e9,
        mean = 0,
        var = 0,
        mode = "normal",
        started_at = nil,
        below_since = nil,
        updated_at = nil,
        seeded = false,
        warming = true,
    }
end

local function apply_ewma(b, r)
    if not b.seeded then
        b.mean = r
        b.var = 0
        b.seeded = true
        return
    end

    local diff = r - b.mean
    local incr = b.alpha * diff
    if incr > 0 and b.mean > 0 then
        local cap = b.mean * b.max_growth_per_hour * (b.tick / 3600)
        if incr > cap then
            incr = cap
        end
    end
    b.mean = b.mean + incr
    local var = (1 - b.alpha) * (b.var + diff * incr)
    if var < 0 then
        var = 0
    end
    b.var = var
end

function _M.lines(b)
    local sigma = sigma_of(b.var)
    local elev = max(b.mean + b.k_elev * sigma, b.min_rps)
    local attack = max(b.mean + b.k_attack * sigma, b.min_rps * 2)
    return elev, attack, sigma
end

function _M.update(b, rps, now, entropy_attack)
    if b.started_at == nil then
        b.started_at = now
    end

    local warming = (now - b.started_at) < b.warmup
    b.warming = warming

    -- No decision until one sample has landed and warmup is over.
    -- With mean=var=0 the attack line is 0, so the first request would
    -- otherwise freeze the baseline before it exists.
    local ready = b.seeded and not warming
    local elev_line, atk_line, sigma = _M.lines(b)
    -- A handful of sampled requests makes entropy swing on its own.
    -- Ignore that signal until the rate clears the same floor as a real spike.
    local entropy_ok = entropy_attack == true and rps >= b.min_rps
    local want_attack = ready and (entropy_ok or rps > atk_line)
    local want_elev = ready and (rps > elev_line)

    local mode = b.mode
    if not ready then
        mode = "normal"
        b.below_since = nil
    elseif want_attack then
        mode = "attack"
        b.below_since = nil
    elseif mode == "attack" then
        -- Leave attack only after the entry condition has stayed false
        -- for the whole cooldown. One quiet tick is not an exit.
        if b.below_since == nil then
            b.below_since = now
        elseif now - b.below_since >= b.cooldown then
            if want_elev then
                mode = "elevated"
            else
                mode = "normal"
            end
            b.below_since = nil
        end
    elseif want_elev then
        mode = "elevated"
        b.below_since = nil
    elseif mode == "elevated" then
        if b.below_since == nil then
            b.below_since = now
        elseif now - b.below_since >= b.cooldown then
            mode = "normal"
            b.below_since = nil
        end
    else
        mode = "normal"
        b.below_since = nil
    end

    b.mode = mode
    if mode == "normal" then
        apply_ewma(b, rps)
    end
    b.updated_at = now

    return mode, {
        mean = b.mean,
        sigma = sigma,
        elev = elev_line,
        attack = atk_line,
        warming = warming,
        frozen = mode ~= "normal",
    }
end

function _M.export(b)
    local s = _M.snapshot(b)
    local function field(v)
        if v == nil then
            return "-"
        end
        return tostring(v)
    end
    return table.concat({
        field(s.mean), field(s.var), s.mode or "normal",
        field(s.started_at), field(s.below_since), field(s.updated_at),
        s.seeded and "1" or "0",
    }, "\n")
end

function _M.import(text)
    if type(text) ~= "string" then
        return nil
    end
    local mean, var, mode, started, below, updated, seeded =
        text:match("([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)\n([^\n]*)")
    if not mean then
        return nil
    end
    local function num(v)
        if not v or v == "-" or v == "" then
            return nil
        end
        return tonumber(v)
    end
    return {
        mean = tonumber(mean) or 0,
        var = tonumber(var) or 0,
        mode = mode,
        started_at = num(started),
        below_since = num(below),
        updated_at = num(updated),
        seeded = seeded == "1",
    }
end

function _M.snapshot(b)
    return {
        mean = b.mean,
        var = b.var,
        mode = b.mode,
        started_at = b.started_at,
        below_since = b.below_since,
        updated_at = b.updated_at,
        seeded = b.seeded,
    }
end

-- A baseline older than one half-life is kept as the seed, but warmup runs
-- again. A reload inside the half-life continues with the saved clock.
function _M.restore(b, snap, now)
    b.mean = snap.mean or 0
    b.var = snap.var or 0
    b.seeded = snap.seeded
    if b.seeded == nil then
        b.seeded = (b.mean ~= 0) or (b.var ~= 0)
    end
    b.updated_at = snap.updated_at

    local stale = snap.updated_at ~= nil and now ~= nil
        and (now - snap.updated_at) > b.half_life
    if stale then
        b.started_at = now
        b.mode = "normal"
        b.below_since = nil
        b.warming = true
        return
    end

    b.mode = snap.mode or "normal"
    b.started_at = snap.started_at
    b.below_since = snap.below_since
end

return _M
