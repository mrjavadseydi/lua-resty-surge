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

local function absent()
    return {
        i4 = { [nat] = { key = nat, count = 30, error = 0 } },
        i6 = {}, s4 = {}, s6 = {},
        u = { ["/"] = { key = "/", count = 100, error = 0 } },
        _totals = { i4 = 100, i6 = 0, s4 = 0, s6 = 0, u = 100 },
    }
end

local function empty()
    return {
        i4 = {}, i6 = {}, s4 = {}, s6 = {}, u = {},
        _totals = { i4 = 0, i6 = 0, s4 = 0, s6 = 0, u = 0 },
    }
end

local function find(list, key, action)
    for i = 1, #list do
        if list[i].key == key and (not action or list[i].action == action) then
            return list[i]
        end
    end
end

local function reach_block(ctx, now)
    for _ = 1, 40 do
        now = now + 0.25
        analyzer.run(ctx, quiet(), now, nil)
    end
    local snap
    for _ = 1, 8 do
        now = now + 0.25
        snap = analyzer.run(ctx, flood(), now, nil)
        if find(snap.list, attacker, "block") then
            return snap, now
        end
    end
    return snap, now
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

    it("keeps a block for its ttl after the ip leaves the top-k", function()
        local ctx = analyzer.new(params())
        local snap, now = reach_block(ctx, 0)
        local held = find(snap.list, attacker, "block")
        assert(held, "flood did not reach block")
        assert(held.until_ts)
        local quiet_snap = analyzer.run(ctx, absent(), now + 1, snap.list)
        local still = find(quiet_snap.list, attacker, "block")
        assert(still, "block dropped while ttl remained")
        assert(still.incident == held.incident)

        local fresh = analyzer.new(params())
        local adopted = analyzer.run(fresh, absent(), now + 1, snap.list)
        assert(find(adopted.list, attacker, "block"),
            "a new leader dropped the published block")
    end)

    it("does not put a block back after the snapshot drops it", function()
        local ctx = analyzer.new(params())
        local snap, now = reach_block(ctx, 0)
        assert(find(snap.list, attacker, "block"))
        local gone = analyzer.run(ctx, absent(), now + 1, {})
        assert(find(gone.list, attacker, "block") == nil)
        local later = analyzer.run(ctx, absent(), now + 2, {})
        assert(find(later.list, attacker) == nil)
    end)

    it("keeps a manual block that arrived in the snapshot", function()
        local ctx = analyzer.new(params())
        local manual = {
            family = "v4",
            bits = 32,
            key = attacker,
            action = "block",
            reason = "manual",
            message = "operator",
            ttl = 600,
            until_ts = 5000,
            manual = true,
            incident = "srg-manual",
        }
        local snap = analyzer.run(ctx, flood(), 100, { manual })
        local rec = find(snap.list, attacker, "block")
        assert(rec)
        assert(rec.manual == true)
        assert(rec.incident == "srg-manual")
        assert(rec.reason == "manual")
        local later = analyzer.run(ctx, absent(), 200, snap.list)
        rec = find(later.list, attacker, "block")
        assert(rec and rec.manual == true)
    end)

    it("requires consecutive ticks again after a block expires", function()
        local ctx = analyzer.new(params())
        local snap, _ = reach_block(ctx, 0)
        local held = find(snap.list, attacker, "block")
        assert(held and held.until_ts)
        local again = analyzer.run(ctx, flood(), held.until_ts + 1, snap.list)
        local rec = find(again.list, attacker)
        assert(rec, "expected the first returning tick to be recorded")
        assert(rec.action == "observe", "returned as " .. tostring(rec.action))
    end)

    it("limits a single hot ipv4 during warmup", function()
        local p = params()
        p.warmup = 500
        p.hard_ip_rps = 1000
        local ctx = analyzer.new(p)
        local window = flood()
        window.s4 = { ["\10\0\0"] = { key = "\10\0\0", count = 8000, error = 0 } }
        window._totals.s4 = 8000
        local snap = analyzer.run(ctx, window, 10, nil)
        assert(ctx.baseline.warming == true)
        local rec = find(snap.list, attacker)
        assert(rec and rec.action == "limit", rec and rec.action)
        assert(rec.reason == "hard_ip")
        assert(find(snap.list, nat) == nil)
        assert(find(snap.list, "\10\0\0") == nil)
        snap = analyzer.run(ctx, window, 10.25, nil)
        rec = find(snap.list, attacker)
        assert(rec.action == "limit")

        local mild = analyzer.new(p)
        local quiet_snap = analyzer.run(mild, quiet(), 10, nil)
        assert(mild.baseline.warming == true)
        assert(#quiet_snap.list == 0)
    end)

    it("drops idle share and state entries after one half-life", function()
        local ctx = analyzer.new(params())
        local now = 100
        local merged = empty()
        merged._totals.i4 = 100
        for i = 1, 40 do
            local key = string.char(10, 0, i, 1)
            merged.i4[key] = { key = key, count = 1, error = 0 }
        end
        analyzer.run(ctx, merged, now, nil)
        local shares = 0
        for _ in pairs(ctx.shares) do
            shares = shares + 1
        end
        assert(shares == 40)
        analyzer.run(ctx, empty(), now + 21, nil)
        shares = 0
        for _ in pairs(ctx.shares) do
            shares = shares + 1
        end
        assert(shares == 0, "shares left " .. shares)
        local states = 0
        for _ in pairs(ctx.states) do
            states = states + 1
        end
        assert(states == 0)

        local live = analyzer.new(params())
        local snap
        snap, now = reach_block(live, now)
        assert(find(snap.list, attacker, "block"))
        analyzer.run(live, absent(), now + 21, snap.list)
        local kept = false
        for _, st in pairs(live.states) do
            if st.stage == "block" then
                kept = true
            end
        end
        assert(kept, "an unexpired block was discarded")
    end)
end)
