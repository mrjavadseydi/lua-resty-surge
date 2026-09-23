local analyzer = require "resty.surge.analyzer"
local baseline = require "resty.surge.baseline"

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

-- Twenty sites share the node. victim.io is 1% of normal traffic.
local function sites(victim_count)
    local h = {}
    local total = 0
    for i = 1, 19 do
        local name = "site" .. i .. ".io"
        local n = i == 1 and 400 or 30
        h[name] = { key = name, count = n, error = 0 }
        total = total + n
    end
    h["victim.io"] = { key = "victim.io", count = victim_count, error = 0 }
    total = total + victim_count
    -- A spread botnet: no ip or subnet is heavy, so i4 carries only the total.
    return {
        i4 = { [nat] = { key = nat, count = 30, error = 0 } },
        i6 = {}, s4 = {}, s6 = {},
        u = { ["/"] = { key = "/", count = total, error = 0 } },
        h = h,
        _totals = { i4 = total, i6 = 0, s4 = 0, s6 = 0, u = total, h = total },
    }
end

describe("analyzer", function()
    it("challenges the flooded site, never blocks it, and leaves the others", function()
        local ctx = analyzer.new(params())
        local now = 0
        for _ = 1, 80 do
            now = now + 0.25
            local snap = analyzer.run(ctx, sites(10), now, nil)
            assert(#snap.list == 0)
        end
        local seen = {}
        local snap
        for _ = 1, 12 do
            now = now + 0.25
            snap = analyzer.run(ctx, sites(8000), now, snap and snap.list)
            assert(snap.mode ~= "normal")
            local rec = find(snap.list, "victim.io")
            if rec then
                seen[rec.action] = true
                assert(rec.family == "host")
                assert(rec.reason == "host_surge")
                assert(rec.uri == nil)
                assert(rec.message:find("victim.io", 1, true))
                assert(rec.rate >= 20)
            end
            assert(find(snap.list, "site1.io") == nil)
            assert(find(snap.list, "site2.io") == nil)
        end
        assert(seen.limit, "no limit stage")
        assert(seen.challenge, "no challenge stage")
        assert(not seen.block, "a whole site was blocked")
    end)

    it("keeps a host decision at observe in dry run", function()
        local ctx = analyzer.new(params())
        ctx.dry_run = true
        local now = 0
        for _ = 1, 80 do
            now = now + 0.25
            analyzer.run(ctx, sites(10), now, nil)
        end
        for _ = 1, 8 do
            now = now + 0.25
            local snap = analyzer.run(ctx, sites(8000), now, nil)
            local rec = find(snap.list, "victim.io")
            assert(not rec or rec.action == "observe")
        end
    end)

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

    it("can block a fingerprint and skip challenge on an api path", function()
        local p = params()
        p.api_prefixes = { "/api/" }
        local ctx = analyzer.new(p)
        local fp = "2GET20au00000000en1"
        local function window(heavy)
            local n = heavy and 900 or 1
            local other = heavy and 10 or 99
            return {
                i4 = { [nat] = { key = nat, count = 20, error = 0 } },
                i6 = {}, s4 = {}, s6 = {},
                f = {
                    [fp] = { key = fp, count = n, error = 0 },
                    ["2GET20x"] = { key = "2GET20x", count = other, error = 0 },
                },
                u = { ["/api/login"] = { key = "/api/login", count = n, error = 0 } },
                _totals = {
                    i4 = 100, i6 = 0, s4 = 0, s6 = 0,
                    f = n + other, u = n,
                },
            }
        end
        local now = 0
        for _ = 1, 6 do
            now = now + 0.25
            analyzer.run(ctx, window(false), now, nil)
        end
        local saw_block = false
        for _ = 1, 8 do
            now = now + 0.25
            local snap = analyzer.run(ctx, window(true), now, nil)
            for i = 1, #snap.list do
                local rec = snap.list[i]
                assert(rec.key ~= "/api/login")
                if rec.key == fp and rec.family == "fp" then
                    assert(rec.action ~= "challenge")
                    if rec.action == "block" then
                        saw_block = true
                    end
                end
            end
        end
        assert(saw_block, "fingerprint was not blocked")
    end)

    it("learns fingerprint entropy from elevated traffic and can leave attack", function()
        local p = params()
        p.min_rps = 0
        p.cooldown = 1
        p.entropy_drop = 0.2
        p.entropy_rise = 0.2
        local ctx = analyzer.new(p)
        -- sigma = 100, so 400 rps is normal, 800 is elevated, 900 is attack.
        baseline.restore(ctx.baseline, {
            mean = 400, var = 10000, mode = "normal", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        local chrome = "1GET11chrome"
        local function rates(ip_n, fps)
            local f, ftotal = {}, 0
            for k, n in pairs(fps) do
                f[k] = { key = k, count = n, error = 0 }
                ftotal = ftotal + n
            end
            return {
                i4 = { [nat] = { key = nat, count = ip_n, error = 0 } },
                i6 = {}, s4 = {}, s6 = {},
                f = f,
                u = { ["/"] = { key = "/", count = ip_n, error = 0 } },
                _totals = {
                    i4 = ip_n, i6 = 0, s4 = 0, s6 = 0, f = ftotal, u = ip_n,
                },
            }
        end
        local function mixed()
            return rates(200, {
                [chrome] = 40, otherb = 40, otherc = 40, otherd = 40, othere = 40,
            })
        end
        local now = 10
        for _ = 1, 4 do
            now = now + 0.25
            local snap = analyzer.run(ctx, rates(100, {}), now, nil)
            assert(snap.mode == "normal", snap.mode)
        end
        assert(ctx.entropy.f:mean() == nil)

        for _ = 1, 6 do
            now = now + 0.25
            local snap = analyzer.run(ctx, mixed(), now, nil)
            assert(snap.mode ~= "attack", snap.mode)
            assert(find(snap.list, chrome, "limit") == nil)
            assert(find(snap.list, chrome, "block") == nil)
            assert(find(snap.list, chrome, "challenge") == nil)
        end
        assert(ctx.entropy.f:mean() > 0.5, tostring(ctx.entropy.f:mean()))

        local entered = false
        for _ = 1, 6 do
            now = now + 0.25
            local snap = analyzer.run(ctx, rates(200, {
                [chrome] = 20, botkit = 180,
            }), now, nil)
            if snap.mode == "attack" then
                entered = true
            end
        end
        assert(entered, "fingerprint collapse did not enter attack")
        assert(ctx.entropy.f:mean() > 0.5)

        local left = false
        for _ = 1, 8 do
            now = now + 0.25
            local snap = analyzer.run(ctx, mixed(), now, nil)
            if snap.mode ~= "attack" then
                left = true
                break
            end
        end
        assert(left, "stuck in attack above min_rps")
    end)

    it("remembers a minority fingerprint first seen during attack", function()
        local p = params()
        p.min_rps = 0
        local ctx = analyzer.new(p)
        baseline.restore(ctx.baseline, {
            mean = 400, var = 10000, mode = "attack", seeded = true,
            started_at = 0, updated_at = 0,
        }, 0)
        local chrome = "1GET11chrome"
        local bot = "1GET11botkit"
        local function window()
            return {
                i4 = { [nat] = { key = nat, count = 10000, error = 0 } },
                i6 = {}, s4 = {}, s6 = {},
                f = {
                    [chrome] = { key = chrome, count = 20, error = 0 },
                    [bot] = { key = bot, count = 80, error = 0 },
                },
                u = { ["/"] = { key = "/", count = 10000, error = 0 } },
                _totals = { i4 = 10000, i6 = 0, s4 = 0, s6 = 0, f = 100, u = 10000 },
            }
        end
        local now = 100
        local bot_hit = false
        for _ = 1, 4 do
            now = now + 0.25
            local snap = analyzer.run(ctx, window(), now, nil)
            assert(snap.mode == "attack", snap.mode)
            assert(find(snap.list, chrome, "limit") == nil)
            assert(find(snap.list, chrome, "challenge") == nil)
            assert(find(snap.list, chrome, "block") == nil)
            local rec = find(snap.list, bot)
            if rec and rec.action ~= "observe" then
                bot_hit = true
            end
        end
        assert(bot_hit, "majority fingerprint was not escalated")
    end)

    it("keeps confidence when a block is adopted from the snapshot", function()
        local ctx = analyzer.new(params())
        local now = 50
        local prev = {
            {
                family = "v4", bits = 32, key = attacker,
                action = "block", reason = "heavy_hitter",
                message = "held", ttl = 60, until_ts = now + 30,
                confidence = 0.95, incident = "srg-keep",
            },
        }
        local snap = analyzer.run(ctx, absent(), now, prev)
        local rec = find(snap.list, attacker, "block")
        assert(rec, "adopted block missing")
        assert(math.abs((rec.confidence or 0) - 0.95) < 0.0001)
        snap = analyzer.run(ctx, flood(), now + 1, snap.list)
        rec = find(snap.list, attacker, "block")
        assert(rec, "block missing on the next tick")
        assert((rec.confidence or 0) > 0.5, tostring(rec.confidence))
    end)
end)
