local baseline = require "resty.surge.baseline"

local function new_b(over)
    local opts = {
        tick = 1,
        half_life = 10,
        k_elev = 3,
        k_attack = 5,
        min_rps = 0,
        cooldown = 5,
        warmup = 0,
        max_growth_per_hour = 1e9,
    }
    for k, v in pairs(over or {}) do
        opts[k] = v
    end
    return baseline.new(opts)
end

describe("ewma baseline", function()
    it("converges on a constant rate", function()
        -- min_rps sits above the signal so this stays in normal mode and the
        -- recurrence is what moves the mean, not the attack freeze.
        local b = new_b({ min_rps = 10000 })
        baseline.restore(b, {
            mean = 0, var = 0, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        for i = 1, 200 do
            assert(baseline.update(b, 50, i, false) == "normal")
        end
        assert(math.abs(b.mean - 50) < 0.5, "mean " .. b.mean)
    end)

    it("does not move the baseline while frozen in attack", function()
        local b = new_b({ half_life = 1000, min_rps = 0 })
        baseline.restore(b, {
            mean = 100, var = 25, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        local mode = baseline.update(b, 400, 1, false)
        assert(mode == "attack", mode)
        local mean = b.mean
        local var = b.var
        baseline.update(b, 100000, 2, false)
        assert(b.mode == "attack")
        assert(b.mean == mean, "mean moved to " .. b.mean)
        assert(b.var == var)
    end)

    it("does not flap when the rate oscillates around the line", function()
        local b = new_b({ half_life = 100000, cooldown = 5, min_rps = 0 })
        baseline.restore(b, {
            mean = 100, var = 25, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        -- σ = 5, attack line = 100 + 25 = 125. 130 enters, 90 does not,
        -- and 90 never lasts for the cooldown.
        local entered = 0
        local left = 0
        local prev = "normal"
        for i = 1, 30 do
            local r = (i % 2 == 1) and 130 or 90
            local mode = baseline.update(b, r, i, false)
            if prev ~= "attack" and mode == "attack" then
                entered = entered + 1
            end
            if prev == "attack" and mode ~= "attack" then
                left = left + 1
            end
            prev = mode
        end
        assert(entered == 1, "entered " .. entered)
        assert(left == 0, "left " .. left)
        assert(b.mode == "attack")
    end)

    it("leaves attack only after the cooldown", function()
        local b = new_b({ half_life = 100000, cooldown = 5 })
        baseline.restore(b, {
            mean = 100, var = 25, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        assert(baseline.update(b, 400, 10, false) == "attack")
        -- below_since is stamped on the first quiet tick (t=11).
        -- Exit when now - below_since >= 5, which is t=16.
        for t = 11, 15 do
            assert(baseline.update(b, 0, t, false) == "attack", "left early at " .. t)
        end
        assert(baseline.update(b, 0, 16, false) == "normal")
    end)

    it("uses the min_rps floor", function()
        local b = new_b({ half_life = 100000, min_rps = 100, k_elev = 3, k_attack = 5 })
        baseline.restore(b, {
            mean = 50, var = 0, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        assert(baseline.update(b, 80, 1, false) == "normal")
        -- mean is now ~50 still (half life is huge, but normal mode does update).
        -- Re-seed so the floor is the thing under test, not the EWMA step.
        baseline.restore(b, {
            mean = 50, var = 0, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        assert(baseline.update(b, 150, 1, false) == "elevated", b.mode)
        baseline.restore(b, {
            mean = 50, var = 0, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        assert(baseline.update(b, 250, 1, false) == "attack", b.mode)
    end)

    it("stays in normal during warmup", function()
        local b = new_b({ warmup = 100, half_life = 100000 })
        local mode = baseline.update(b, 1e9, 10, true)
        assert(mode == "normal", mode)
        assert(b.warming == true)
    end)

    it("ignores an entropy signal below min_rps", function()
        local b = new_b({ half_life = 100000, min_rps = 1000 })
        baseline.restore(b, {
            mean = 100, var = 0, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        assert(baseline.update(b, 10, 1, true) == "normal")
    end)

    it("enters attack on entropy once the rate clears min_rps", function()
        -- Attack line is max(mean, min_rps * 2) = 200. 150 is not a rate
        -- spike, but it is enough traffic for the entropy signal to count.
        local b = new_b({ half_life = 100000, min_rps = 100 })
        baseline.restore(b, {
            mean = 100, var = 0, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        assert(baseline.update(b, 150, 1, true) == "attack")
        assert(b.mean == 100)
    end)

    it("round-trips a baseline so a reload keeps the warmup clock", function()
        local b = new_b({ warmup = 100, half_life = 1000 })
        assert(baseline.update(b, 40, 10, false) == "normal")
        for i = 1, 5 do
            baseline.update(b, 40, 10 + i, false)
        end
        local text = baseline.export(b)
        local b2 = new_b({ warmup = 100, half_life = 1000 })
        local snap = baseline.import(text)
        assert(snap)
        baseline.restore(b2, snap, 20)
        assert(b2.started_at == 10)
        assert(b2.seeded == true)
        assert(math.abs(b2.mean - b.mean) < 1e-6)
        baseline.update(b2, 40, 20, false)
        assert(b2.warming == true)
        assert(b2.started_at == 10)
        baseline.update(b2, 40, 120, false)
        assert(b2.warming == false)
    end)

    it("caps how fast the mean can grow while still under the line", function()
        -- σ = 100, elevated line = 400. r = 350 stays in normal.
        -- α ≈ 1, so an uncapped step would jump the mean to 350.
        -- The hourly cap allows +100%.
        local b = new_b({
            tick = 3600,
            half_life = 1,
            max_growth_per_hour = 1,
            min_rps = 0,
            k_elev = 3,
            k_attack = 5,
        })
        baseline.restore(b, {
            mean = 100, var = 10000, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        local mode = baseline.update(b, 350, 1, false)
        assert(mode == "normal", mode)
        assert(math.abs(b.mean - 200) < 1e-6, "mean " .. b.mean)
    end)

    it("rewarmups a baseline older than one half-life and keeps the seed", function()
        local b = new_b({ half_life = 60, warmup = 30 })
        baseline.restore(b, {
            mean = 80, var = 4, mode = "attack", seeded = true,
            started_at = 0, updated_at = 0, below_since = 0,
        }, 1000)
        assert(b.mean == 80)
        assert(b.mode == "normal")
        assert(b.started_at == 1000)
        local mode = baseline.update(b, 1e9, 1010, false)
        assert(mode == "normal", mode)
    end)
end)
