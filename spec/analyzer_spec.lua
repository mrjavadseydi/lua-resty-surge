local analyzer = require "resty.surge.analyzer"

local function params()
    return {
        tick = 0.25,
        half_life = 20,
        k_elev = 3,
        k_attack = 5,
        min_rps = 20,
        abs_share = 0.05,
        multiplier = 10,
        consecutive = 2,
        ttl_base = 60,
        ttl_max = 600,
        cooldown = 30,
        warmup = 0,
        max_growth_per_hour = 5,
        min_key_rps = 5,
        limit_rps = 80,
        entropy_drop = 0.2,
        entropy_rise = 0.2,
        confidence_skip = 0.99,
        challenge_ready = true,
    }
end

local attacker = "\10\0\0\9"
local nat = "\10\1\2\3"

local function quiet()
    return {
        i4 = {
            [attacker] = { key = attacker, count = 1, error = 0 },
            [nat] = { key = nat, count = 30, error = 0 },
        },
        i6 = {}, s4 = {}, s6 = {},
        u = { ["/"] = { key = "/", count = 100, error = 0 } },
        _totals = { i4 = 100, i6 = 0, s4 = 0, s6 = 0, u = 100 },
    }
end

local function flood()
    return {
        i4 = {
            [attacker] = { key = attacker, count = 8000, error = 0 },
            [nat] = { key = nat, count = 30, error = 0 },
        },
        i6 = {}, s4 = {}, s6 = {},
        u = { ["/login"] = { key = "/login", count = 8030, error = 0 } },
        _totals = { i4 = 10000, i6 = 0, s4 = 0, s6 = 0, u = 8030 },
    }
end

local function find(list, key, action)
    for i = 1, #list do
        if list[i].key == key and (not action or list[i].action == action) then
            return list[i]
        end
    end
end

describe("analyzer", function()
    it("blocks a flood and leaves a steady NAT alone", function()
        local ctx = analyzer.new(params())
        local now = 0
        for _ = 1, 80 do
            now = now + 0.25
            analyzer.run(ctx, quiet(), now, nil)
        end
        assert(ctx.baseline.mode == "normal")

        local stages = {}
        for _ = 1, 6 do
            now = now + 0.25
            local snap = analyzer.run(ctx, flood(), now, nil)
            local rec = find(snap.list, attacker)
            stages[#stages + 1] = rec and rec.action or "none"
            assert(find(snap.list, nat, "block") == nil)
            assert(find(snap.list, nat, "limit") == nil)
            assert(snap.mode == "attack")
            if rec then
                assert(rec.uri == "/login")
                assert(rec.reason == "heavy_hitter")
                assert(rec.message:find("10.0.0.9", 1, true))
            end
        end
        local joined = table.concat(stages, ",")
        assert(joined:find("limit", 1, true), "stages " .. joined)
        assert(joined:find("block", 1, true), "stages " .. joined)
    end)

    it("does not turn a URI into a decision by itself", function()
        local ctx = analyzer.new(params())
        local now = 0
        for _ = 1, 40 do
            now = now + 0.25
            local snap = analyzer.run(ctx, quiet(), now, nil)
            for i = 1, #snap.list do
                assert(snap.list[i].key ~= "/")
            end
        end
    end)
end)
