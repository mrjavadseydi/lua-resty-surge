-- Leader-tick simulation of the seven scenarios in the spec.
--
-- Each tick builds the merged top-K the workers would have published and
-- runs analyzer.run. Fingerprints are omitted while the mode is normal,
-- matching protect(). Outcomes apply the decision list to that tick's
-- requests, including /24 scope and URI scope.
--
-- This is not a live nginx flood. Time is tick count times the preset tick.

local analyzer = require "resty.surge.analyzer"
local presets = require "resty.surge.presets"

local TICK = presets.balanced.tick

local function ip4(n)
    local a = math.floor(n / 65536) % 256
    local b = math.floor(n / 256) % 256
    local c = n % 256
    return string.char(10, a, b, c)
end

-- Attackers sit in 11.0.0.0/8 so a /24 block cannot land on the legit NAT.
local function attacker_ip(n)
    return string.char(11, math.floor(n / 256) % 256, n % 256, 9)
end

local function add(map, key, n)
    local e = map[key]
    if e then
        e.count = e.count + n
    else
        map[key] = { key = key, count = n, error = 0 }
    end
end

local function sum(map)
    local n = 0
    for _, e in pairs(map) do
        n = n + e.count
    end
    return n
end

-- Stable legit mix. The NAT is 12% of traffic: above abs_share, under its
-- own baseline once that baseline exists, and above min_key_rps.
local NAT = ip4(1)
local USERS = {}
for i = 1, 22 do
    USERS[i] = ip4(1000 + i)
end

local FP_CHROME = "1GET11aulchrome"
local FP_OTHER = {
    "1GET11aulfirefox",
    "1GET11aulsafari",
    "1GET11auledge",
}
local FP_BOT = "1GET11botkit000"

local URIS = { "/", "/app", "/search", "/img", "/help" }

local function legit_counts(total)
    local nat_n = math.floor(total * 0.12 + 0.5)
    if nat_n < 1 then
        nat_n = 1
    end
    local rest = total - nat_n
    local each = math.floor(rest / #USERS)
    local rem = rest - each * #USERS
    local ips = { [NAT] = nat_n }
    for i = 1, #USERS do
        ips[USERS[i]] = each + (i == 1 and rem or 0)
    end
    return ips
end

local function browser_fps(total)
    local chrome = math.floor(total * 0.45 + 0.5)
    local left = total - chrome
    local each = math.floor(left / #FP_OTHER)
    local fps = { [FP_CHROME] = chrome }
    local used = chrome
    for i = 1, #FP_OTHER do
        local n = (i == #FP_OTHER) and (total - used) or each
        fps[FP_OTHER[i]] = n
        used = used + n
    end
    return fps
end

local function zipf_uris(total)
    local weights = { 30, 18, 12, 8, 5 }
    local wsum = 0
    for i = 1, #weights do
        wsum = wsum + weights[i]
    end
    local uris, used = {}, 0
    for i = 1, #URIS do
        local n = math.floor(total * weights[i] / wsum)
        uris[URIS[i]] = n
        used = used + n
    end
    uris[URIS[1]] = uris[URIS[1]] + (total - used)
    return uris
end

local function merged(ips, fps, uris)
    local i4, s4 = {}, {}
    for ip, n in pairs(ips) do
        if n > 0 then
            add(i4, ip, n)
            add(s4, ip:sub(1, 3), n)
        end
    end
    local f = {}
    if fps then
        for k, n in pairs(fps) do
            if n > 0 then
                add(f, k, n)
            end
        end
    end
    local u = {}
    for k, n in pairs(uris) do
        if n > 0 then
            add(u, k, n)
        end
    end
    return {
        i4 = i4, i6 = {}, s4 = s4, s6 = {}, f = f, u = u,
        _totals = {
            i4 = sum(i4), i6 = 0, s4 = sum(s4), s6 = 0,
            f = sum(f), u = sum(u),
        },
    }
end

local function matches(rec, ip, uri, fp)
    if rec.uri and rec.uri ~= "" then
        if uri:sub(1, #rec.uri) ~= rec.uri then
            return false
        end
    end
    if rec.family == "fp" then
        return fp ~= nil and rec.key == fp
    end
    if rec.family ~= "v4" then
        return false
    end
    if rec.bits == 24 then
        return rec.key == ip:sub(1, 3)
    end
    return rec.key == ip
end

local function verdict(list, ip, uri, fp)
    local hit
    for i = 1, #list do
        local rec = list[i]
        local action = rec.action
        if (action == "block" or action == "challenge" or action == "limit")
            and matches(rec, ip, uri, fp)
        then
            -- A /32 outranks a /24. A fingerprint hit counts too.
            if not hit then
                hit = rec
            elseif rec.family == "fp" or (rec.bits or 0) > (hit.bits or 0) then
                hit = rec
            end
        end
    end
    return hit
end

local function new_world(params)
    return {
        ctx = analyzer.new(params),
        now = 0,
        prev = nil,
        mode = "normal",
        list = {},
    }
end

local function step(world, ips, uris, fps_or_nil)
    local fps = nil
    if world.mode ~= "normal" then
        fps = fps_or_nil
    end
    local snap = analyzer.run(world.ctx, merged(ips, fps, uris), world.now, world.prev)
    world.now = world.now + world.ctx.params.tick
    world.prev = snap.list
    world.mode = snap.mode
    world.list = snap.list
    world.last = snap
    return snap
end

local function warm(world, seconds, rps)
    local ticks = math.floor(seconds / world.ctx.params.tick)
    local total = math.floor(rps * world.ctx.params.tick + 0.5)
    if total < 20 then
        total = 20
    end
    for _ = 1, ticks do
        step(world, legit_counts(total), zipf_uris(total), browser_fps(total))
    end
end

local function find_action(list, key)
    for i = 1, #list do
        if list[i].key == key and list[i].action ~= "observe" then
            return list[i]
        end
    end
end

local function account(world, ips, uri_of, fp_of, acc, attackers)
    local list = world.list or {}
    for ip, n in pairs(ips) do
        if n > 0 then
            local uri = uri_of(ip)
            local fp = fp_of(ip)
            local hit = verdict(list, ip, uri, fp)
            local bad = attackers[ip]
            if bad then
                acc.attack = acc.attack + n
                if acc.detected and hit == nil then
                    acc.fn = acc.fn + n
                end
                if hit and (hit.action == "block" or hit.action == "challenge" or hit.action == "limit") then
                    acc.attack_hit = acc.attack_hit + n
                end
            else
                acc.legit = acc.legit + n
                if hit then
                    acc.fp = acc.fp + n
                    if hit.key ~= ip then
                        acc.collateral = acc.collateral + n
                    end
                end
            end
        end
    end
end

local function scenario(title, params, body)
    local world = new_world(params)
    warm(world, params.warmup + params.tick * 4, 200)
    local acc = {
        legit = 0, fp = 0, attack = 0, fn = 0, attack_hit = 0, collateral = 0,
        detected = false, detect_at = nil, block_at = nil,
        mode = world.mode,
    }
    local t0 = world.now
    local function mark(attacker_keys)
        if not acc.detected and world.mode ~= "normal" then
            acc.detected = true
            acc.detect_at = world.now - t0
        end
        if not acc.block_at then
            for i = 1, #attacker_keys do
                local rec = find_action(world.list, attacker_keys[i])
                if rec and rec.action == "block" then
                    acc.block_at = world.now - t0
                    acc.block_uri = rec.uri
                    acc.block_family = rec.family
                end
            end
        end
    end
    body(world, acc, mark)
    local fp_rate = 0
    if acc.legit > 0 then
        fp_rate = acc.fp / acc.legit
    end
    local fn_rate = 0
    if acc.attack > 0 and acc.detected then
        fn_rate = acc.fn / acc.attack
    end
    return {
        title = title,
        detect = acc.detect_at,
        block = acc.block_at,
        fp = fp_rate,
        fn = fn_rate,
        legit = acc.legit,
        attack = acc.attack,
        collateral = acc.collateral,
        fp_n = acc.fp,
        mode = world.mode,
        block_uri = acc.block_uri,
        block_family = acc.block_family,
        note = acc.note,
    }
end

local function fmt_t(t)
    if not t then
        return "none"
    end
    return string.format("%.2fs", t)
end

local function fmt_p(p)
    return string.format("%.4f%%", p * 100)
end

local function run_preset(name)
    local params = presets.copy(name)
    local base_rps = 200
    local rows = {}

    rows[1] = scenario("legit baseline", params, function(world, acc, mark)
        local total = math.floor(base_rps * TICK + 0.5)
        local ips = legit_counts(total)
        local attackers = {}
        for _ = 1, math.floor(30 / TICK) do
            step(world, ips, zipf_uris(total), browser_fps(total))
            mark({})
            account(world, ips, function() return "/" end,
                function() return FP_CHROME end, acc, attackers)
        end
        acc.note = "mode " .. world.mode
    end)

    rows[2] = scenario("legit spike x10", params, function(world, acc, mark)
        local total = math.floor(base_rps * 10 * TICK + 0.5)
        local ips = legit_counts(total)
        local attackers = {}
        for _ = 1, math.floor(30 / TICK) do
            step(world, ips, zipf_uris(total), browser_fps(total))
            mark({})
            account(world, ips, function() return "/" end,
                function() return FP_CHROME end, acc, attackers)
        end
        acc.note = "mode " .. world.mode
    end)

    rows[3] = scenario("single-source flood", params, function(world, acc, mark)
        local attacker = attacker_ip(9)
        local legit_n = math.floor(base_rps * TICK + 0.5)
        local attack_n = legit_n * 20
        local ips = legit_counts(legit_n)
        ips[attacker] = attack_n
        local attackers = { [attacker] = true }
        local keys = { attacker, attacker:sub(1, 3) }
        for _ = 1, math.floor(8 / TICK) do
            local uris = zipf_uris(legit_n + attack_n)
            step(world, ips, uris, browser_fps(legit_n + attack_n))
            mark(keys)
            account(world, ips, function(ip)
                return ip == attacker and "/login" or "/"
            end, function() return FP_CHROME end, acc, attackers)
        end
    end)

    rows[4] = scenario("botnet on /login", params, function(world, acc, mark)
        local legit_n = math.floor(base_rps * TICK + 0.5)
        local bot_ips_n = 5000
        local ips = legit_counts(legit_n)
        local attackers = {}
        -- Spread so no /24 is a heavy hitter. Top-K keeps a sample; the
        -- total still carries the botnet so each sampled IP stays tiny.
        local sample = 64
        local each = math.floor(bot_ips_n / sample)
        for i = 1, sample do
            local ip = ip4(200000 + i * 300)
            ips[ip] = each
            attackers[ip] = true
        end
        local uris = { ["/login"] = bot_ips_n, ["/"] = legit_n }
        local fps = { [FP_BOT] = bot_ips_n, [FP_CHROME] = legit_n }
        local keys = { FP_BOT }
        for _ = 1, math.floor(10 / TICK) do
            step(world, ips, uris, fps)
            mark(keys)
            account(world, ips, function(ip)
                return attackers[ip] and "/login" or "/"
            end, function(ip)
                return attackers[ip] and FP_BOT or FP_CHROME
            end, acc, attackers)
        end
    end)

    rows[5] = scenario("random-path cache bust", params, function(world, acc, mark)
        local legit_n = math.floor(base_rps * TICK + 0.5)
        local bust_n = legit_n * 15
        local ips = legit_counts(legit_n)
        local attackers = {}
        local subnet = ip4(400000):sub(1, 3)
        for i = 1, 40 do
            local ip = subnet .. string.char(i)
            ips[ip] = math.floor(bust_n / 40)
            attackers[ip] = true
        end
        local uris = zipf_uris(legit_n)
        for i = 1, 80 do
            uris["/r/" .. i] = math.floor(bust_n / 80)
        end
        local fps = browser_fps(legit_n)
        fps[FP_BOT] = bust_n
        for _ = 1, math.floor(10 / TICK) do
            step(world, ips, uris, fps)
            mark({ FP_BOT, subnet })
            account(world, ips, function(ip)
                return attackers[ip] and "/r/1" or "/"
            end, function(ip)
                return attackers[ip] and FP_BOT or FP_CHROME
            end, acc, attackers)
        end
    end)

    rows[6] = scenario("slow ramp 2%/min", params, function(world, acc, mark)
        local attacker = attacker_ip(77)
        local legit_n = math.floor(base_rps * TICK + 0.5)
        local attackers = { [attacker] = true }
        local elapsed = 0
        local multiple = 1
        -- Compound 2% per minute until 4x or 80 minutes, whichever first.
        while elapsed < 80 * 60 and multiple < 4 do
            elapsed = elapsed + TICK
            multiple = 1.02 ^ (elapsed / 60)
            local total = math.floor(legit_n * multiple + 0.5)
            local extra = total - legit_n
            local ips = legit_counts(legit_n)
            if extra > 0 then
                ips[attacker] = extra
            end
            step(world, ips, zipf_uris(total), browser_fps(total))
            if not acc.detected and world.mode ~= "normal" then
                acc.detected = true
                acc.detect_at = elapsed
                acc.detect_x = multiple
            end
            if not acc.block_at then
                local rec = find_action(world.list, attacker)
                if rec and rec.action == "block" then
                    acc.block_at = elapsed
                    acc.block_x = multiple
                    acc.block_uri = rec.uri
                    acc.block_family = rec.family
                end
            end
            account(world, ips, function() return "/" end,
                function() return FP_CHROME end, acc, attackers)
            if acc.block_at and elapsed > acc.block_at + 30 then
                break
            end
        end
        acc.note = string.format("detect at %.2fx, block at %s",
            acc.detect_x or 0, acc.block_x and string.format("%.2fx", acc.block_x) or "none")
    end)

    rows[7] = scenario("attack during legit spike", params, function(world, acc, mark)
        local attacker = attacker_ip(88)
        local legit_n = math.floor(base_rps * 10 * TICK + 0.5)
        local ips = legit_counts(legit_n)
        ips[attacker] = legit_n
        local attackers = { [attacker] = true }
        for _ = 1, math.floor(15 / TICK) do
            step(world, ips, zipf_uris(legit_n * 2), browser_fps(legit_n * 2))
            mark({ attacker })
            account(world, ips, function(ip)
                return ip == attacker and "/login" or "/"
            end, function() return FP_CHROME end, acc, attackers)
        end
        acc.note = "mode " .. world.mode
    end)

    return rows
end

local function line(row)
    return string.format(
        "%-28s detect %-8s block %-8s fp %s (%d/%d) fn %s collateral %d  %s%s",
        row.title, fmt_t(row.detect), fmt_t(row.block),
        fmt_p(row.fp), row.fp_n, row.legit, fmt_p(row.fn),
        row.collateral,
        (row.block_family and (row.block_family .. (row.block_uri and (" " .. row.block_uri) or "") .. " ") or ""),
        row.note or "")
end

local function main()
    local names = { "relaxed", "balanced", "strict" }
    local chunks = {}
    local fail = false
    for i = 1, #names do
        local name = names[i]
        local rows = run_preset(name)
        chunks[#chunks + 1] = "== " .. name .. " =="
        for r = 1, #rows do
            local text = line(rows[r])
            chunks[#chunks + 1] = text
            if name == "balanced" and rows[r].fp > 0.001 then
                fail = true
            end
            if name == "balanced" and rows[r].title == "single-source flood" then
                if not rows[r].block or rows[r].block > 2 then
                    fail = true
                end
            end
            if name == "balanced" and rows[r].title == "botnet on /login" then
                if not rows[r].block or rows[r].block > 5
                    or rows[r].block_uri ~= "/login"
                then
                    fail = true
                end
            end
            if name == "balanced" and rows[r].title == "slow ramp 2%/min" then
                local x = tonumber((rows[r].note or ""):match("detect at ([%d%.]+)x"))
                if not x or x >= 3 then
                    fail = true
                end
            end
            if name == "balanced" and rows[r].title == "legit spike x10" then
                if rows[r].fp_n > 0 then
                    fail = true
                end
            end
        end
        chunks[#chunks + 1] = ""
    end
    local report = table.concat(chunks, "\n")
    io.write(report)
    if fail then
        io.stderr:write("simulation missed a balanced target\n")
        os.exit(1)
    end
end

main()
