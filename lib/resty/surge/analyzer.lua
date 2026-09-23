-- Leader-only. Turns a merged top-K into a decision list.
--
-- A key offends when its share beats both the absolute floor and its own
-- baseline share times the multiplier, and its rate beats min_key_rps.
-- Share baselines freeze outside normal mode so a flood cannot become "normal".
-- The first time a key is seen, its share is recorded and it is not judged;
-- a one-tick spike of a brand new key does not escalate.
-- URIs are never decisions. When one URI is most of the window, IP and
-- subnet decisions are scoped to that path.
-- A host (site) offends when the mode is up and its share rose by
-- host_share_rise over its baseline. Host decisions stop at challenge.

local exp = math.exp
local baseline = require "resty.surge.baseline"
local entropy = require "resty.surge.entropy"
local escalation = require "resty.surge.escalation"
local fingerprint = require "resty.surge.fingerprint"
local messages = require "resty.surge.messages"

local _M = {}

local BLOCK_DIMS = {
    i4 = { family = "v4", bits = 32 },
    s4 = { family = "v4", bits = 24 },
    s6 = { family = "v6", bits = 64 },
    f = { family = "fp" },
    h = { family = "host" },
}

local function tracker(params)
    return entropy.new_tracker(params.half_life, params.tick)
end

function _M.new(params)
    return {
        params = params,
        baseline = baseline.new({
            tick = params.tick,
            half_life = params.half_life,
            k_elev = params.k_elev,
            k_attack = params.k_attack,
            min_rps = params.min_rps,
            cooldown = params.cooldown,
            warmup = params.warmup,
            max_growth_per_hour = params.max_growth_per_hour,
        }),
        entropy = {
            s4 = tracker(params),
            s6 = tracker(params),
            u = tracker(params),
            f = tracker(params),
        },
        shares = {},
        share_at = {},
        states = {},
        seq = 0,
        dry_run = false,
    }
end

local function histogram(map, total)
    local counts = {}
    local sum = 0
    for _, e in pairs(map or {}) do
        if e.count > 0 then
            counts[#counts + 1] = e.count
            sum = sum + e.count
        end
    end
    local other = (total or sum) - sum
    if other > 0 then
        counts[#counts + 1] = other
    end
    if #counts == 0 then
        counts[1] = 0
    end
    return counts
end

local function top_key(map)
    local best_k, best_c = nil, 0
    for k, e in pairs(map or {}) do
        if e.count > best_c then
            best_c = e.count
            best_k = k
        end
    end
    return best_k, best_c
end

local function confidence_of(share, threshold, streak)
    if threshold <= 0 then
        threshold = 0.000001
    end
    local ratio = share / threshold
    local c = ratio / (ratio + 1)
    if streak and streak > 1 then
        c = c + 0.05 * (streak - 1)
    end
    if c > 1 then
        c = 1
    end
    return c
end

function _M.run(ctx, merged, now, previous)
    local p = ctx.params
    local totals = merged._totals or {}
    local requests = (totals.i4 or 0) + (totals.i6 or 0)
    local rps = 0
    if p.tick > 0 then
        rps = requests / p.tick
    end

    local frozen_before = ctx.baseline.mode ~= "normal"
    local entropy_info = {}
    local entropy_bad = false
    for _, dim in ipairs({ "s4", "s6", "u", "f" }) do
        -- Fingerprints are not sampled in normal mode. An empty window is
        -- "no data", not entropy 0. Learning 0 makes the next real mix look
        -- like an attack, and attack then freezes that 0 forever.
        if dim == "f" and (totals[dim] or 0) <= 0 then
            entropy_info[dim] = {
                h = nil, base = ctx.entropy[dim]:mean(), delta = 0,
            }
        else
            local h = entropy.normalized(histogram(merged[dim], totals[dim]))
            local base = ctx.entropy[dim]:mean()
            local delta = 0
            if base then
                delta = h - base
                local drop = delta <= -p.entropy_drop
                -- A rise in fingerprint entropy is more kinds of clients.
                -- Only a drop (one toolkit) is an attack signal.
                local rise = dim ~= "f" and delta >= p.entropy_rise
                if drop or rise then
                    entropy_bad = true
                end
            end
            entropy_info[dim] = { h = h, base = base or h, delta = delta }
        end
    end

    local mode = baseline.update(ctx.baseline, rps, now, entropy_bad)
    local warming = ctx.baseline.warming
    local frozen = mode ~= "normal"
    for _, dim in ipairs({ "s4", "s6", "u", "f" }) do
        local h = entropy_info[dim].h
        if h ~= nil then
            local freeze = frozen or warming
            -- Elevated is when fingerprints are first visible. That mix is
            -- the reference. Freeze it only once the mode is attack.
            if dim == "f" and mode == "elevated" then
                freeze = false
            end
            ctx.entropy[dim]:update(h, freeze)
        end
    end

    local alpha = 1 - exp(-p.tick / p.half_life)
    local _, _, sigma = baseline.lines(ctx.baseline)

    local uri_scope = nil
    local uri_total = totals.u or 0
    local uri_key, uri_count = top_key(merged.u)
    if uri_key and uri_total > 0 and (uri_count / uri_total) >= 0.4 then
        local drop = entropy_info.u and entropy_info.u.delta or 0
        if drop <= -p.entropy_drop or (uri_count / uri_total) >= 0.5 then
            uri_scope = uri_key
        end
    end

    local api_only = false
    local prefs = p.api_prefixes
    if uri_scope and prefs then
        for i = 1, #prefs do
            local pre = prefs[i]
            if string.sub(uri_scope, 1, #pre) == pre then
                api_only = true
                break
            end
        end
    end

    local emitted = {}
    local manual_ids = {}
    local from_prev = {}

    local function dim_of(rec)
        if rec.family == "fp" then
            return "f"
        end
        if rec.family == "host" then
            return "h"
        end
        if rec.bits == 24 then
            return "s4"
        end
        if rec.bits == 64 or rec.family == "v6" then
            return "s6"
        end
        return "i4"
    end

    local function adopt(rec)
        local id = dim_of(rec) .. "\0" .. rec.key
        local st = ctx.states[id]
        local rec_until = rec.until_ts or 0
        if not st then
            st = escalation.new(rec.incident)
            ctx.states[id] = st
            st.stage = rec.action or st.stage
            st.ttl = rec.ttl or st.ttl
            st.until_ts = rec_until
            st.confidence = rec.confidence or 0
            st.last = rec
        elseif rec_until > (st.until_ts or 0) then
            -- A snapshot must not shorten a TTL this process already extended.
            st.until_ts = rec_until
            st.ttl = rec.ttl or st.ttl
            st.last = rec
            if rec.action and rec.action ~= "observe" then
                st.stage = rec.action
            end
        end
        if rec.confidence and rec.confidence > (st.confidence or 0) then
            st.confidence = rec.confidence
        end
        st.last_seen = st.last_seen or now
        return id, st
    end

    if previous then
        for i = 1, #previous do
            local rec = previous[i]
            local alive = not rec.until_ts or now < rec.until_ts
            if alive and (rec.manual or (rec.action and rec.action ~= "observe")) then
                -- Kept only while the published snapshot still carries it.
                -- An unblock removes the record; leader memory must not put it back.
                local id = adopt(rec)
                from_prev[id] = true
                if rec.manual then
                    manual_ids[id] = true
                    emitted[id] = rec
                end
            end
        end
    end

    local function emit(id, st, key, meta, share, base, rate, reason)
        local action = st.stage
        if action == "observe" and (st.streak or 0) == 0 then
            return
        end
        local is_host = meta.family == "host"
        local label = key
        if meta.family == "fp" then
            label = fingerprint.short(key)
        elseif not is_host then
            label = messages.label(key, meta.bits)
        end
        -- The limit stage caps a site at about twice its normal traffic,
        -- not at the per-client limit_rps.
        local limit = p.limit_rps
        if is_host then
            limit = math.max(p.min_rps, (base or 0) * (ctx.baseline.mean or 0) * 2)
        end
        local rec = {
            family = meta.family,
            key = key,
            bits = meta.bits,
            action = action,
            reason = reason,
            message = messages.line(action, label, share, base or 0, rate, p.tick),
            uri = not is_host and uri_scope or nil,
            close = false,
            status = (action == "limit" or action == "challenge") and 429 or 403,
            ttl = st.ttl > 0 and st.ttl or p.ttl_base,
            until_ts = st.until_ts,
            incident = st.incident,
            rate = limit,
            share = share,
            confidence = st.confidence,
        }
        st.last = rec
        emitted[id] = rec
    end

    local function hold(id, st)
        if st.stage ~= "observe" and st.last
            and (not st.until_ts or now < st.until_ts)
        then
            emitted[id] = st.last
        else
            emitted[id] = nil
            st.last = nil
        end
    end

    local touched = {}

    local function consider(dim, meta, hard_only)
        local map = merged[dim] or {}
        local total = totals[dim] or 0
        if total <= 0 then
            return
        end
        for key, e in pairs(map) do
            local id = dim .. "\0" .. key
            touched[id] = true
            local share = e.count / total
            local base = ctx.shares[id]
            local rate = 0
            if p.tick > 0 then
                rate = e.count / p.tick
            end
            ctx.share_at[id] = now
            local st = ctx.states[id]
            if st then
                st.last_seen = now
            end

            -- Judge against the baseline from before this tick. Seeding a
            -- brand-new key is not an offense. Fingerprints are only sampled
            -- once the mode has left normal, so elevated traffic is their
            -- baseline. Attack must not teach a bot's share as normal.
            local seeded_now = false
            local learn = not hard_only and not warming
            if dim == "f" then
                if mode == "attack" then
                    learn = false
                    -- First sight during the attack. Under half the window
                    -- is a browser, not one toolkit: remember the share and
                    -- do not punish it. A majority fingerprint is still judged.
                    if base == nil and share <= 0.5 then
                        ctx.shares[id] = share
                        seeded_now = true
                    end
                end
            elseif frozen then
                learn = false
            end
            if learn then
                if base == nil then
                    ctx.shares[id] = share
                    seeded_now = true
                else
                    ctx.shares[id] = base + alpha * (share - base)
                end
            end

            if manual_ids[id] then
                -- operator block wins over a fresh automatic one
            elseif dim == "h" then
                -- Absolute rise, not a multiple: 1% -> 30% and 40% -> 70% both
                -- count. A host first seen during a surge is judged against 0.
                local rise = p.host_share_rise or 0.25
                if not warming and mode ~= "normal" and rate > p.min_key_rps
                    and share - (base or 0) >= rise
                then
                    if not st then
                        ctx.seq = ctx.seq + 1
                        st = escalation.new(string.format("srg-%x", ctx.seq))
                        ctx.states[id] = st
                    end
                    if st.stage ~= "observe" and st.until_ts and now >= st.until_ts then
                        st.stage = "observe"
                        st.streak = 0
                        st.ttl = 0
                    end
                    -- Confidence is how much of the node this one site just
                    -- took over. Past confidence_skip each stage takes a tick.
                    local conf = math.min(1, share - (base or 0))
                    local cap = ctx.dry_run and "observe" or "challenge"
                    escalation.step(st, true, conf, p, now, cap)
                    emit(id, st, key, meta, share, base, rate, "host_surge")
                elseif st then
                    escalation.step(st, false, 0, p, now, nil)
                    hold(id, st)
                end
            elseif hard_only and dim == "i4" and p.hard_ip_rps
                and rate > p.hard_ip_rps
            then
                -- Warmup has no share baseline. Cap one IPv4 address, not a
                -- subnet total: a /24 over the same number is a busy NAT.
                if not st then
                    ctx.seq = ctx.seq + 1
                    st = escalation.new(string.format("srg-%x", ctx.seq))
                    ctx.states[id] = st
                end
                if st.stage == "observe" then
                    st.stage = "limit"
                    st.ttl = p.ttl_base
                    st.until_ts = now + st.ttl
                    st.streak = 0
                end
                st.last_seen = now
                emit(id, st, key, meta, share, base, rate, "hard_ip")
            elseif not hard_only and not seeded_now and not warming
                and rate > p.min_key_rps
            then
                local floor = math.max(p.abs_share, (base or 0) * p.multiplier)
                if share > floor then
                    if not st then
                        ctx.seq = ctx.seq + 1
                        st = escalation.new(string.format("srg-%x", ctx.seq))
                        ctx.states[id] = st
                    end
                    -- A decision that already expired must climb again.
                    if st.stage ~= "observe" and st.until_ts and now >= st.until_ts then
                        st.stage = "observe"
                        st.streak = 0
                        st.ttl = 0
                    end
                    local conf = confidence_of(share, floor, st.streak)
                    local cap = ctx.dry_run and "observe" or nil
                    escalation.step(st, true, conf, p, now, cap, api_only)
                    emit(id, st, key, meta, share, base, rate, "heavy_hitter")
                elseif st then
                    escalation.step(st, false, 0, p, now, nil)
                    hold(id, st)
                end
            elseif st then
                escalation.step(st, false, 0, p, now, nil)
                hold(id, st)
            end
        end
    end

    consider("i4", BLOCK_DIMS.i4, warming)
    consider("s4", BLOCK_DIMS.s4, warming)
    consider("s6", BLOCK_DIMS.s6, warming)
    consider("f", BLOCK_DIMS.f, warming)
    consider("h", BLOCK_DIMS.h, warming)

    -- Keys we blocked are absent from the top-K. Step them anyway so the
    -- TTL can expire them back to observe, and keep publishing until then.
    local idle_after = p.half_life or 600
    for id, st in pairs(ctx.states) do
        if not touched[id] then
            if from_prev[id] then
                escalation.step(st, false, 0, p, now, nil)
                hold(id, st)
            else
                ctx.states[id] = nil
                st = nil
            end
        end
        if st and st.stage == "observe"
            and st.last_seen and now - st.last_seen > idle_after
        then
            ctx.states[id] = nil
        end
    end
    for id, seen_at in pairs(ctx.share_at) do
        if now - seen_at > idle_after and not ctx.states[id] then
            ctx.shares[id] = nil
            ctx.share_at[id] = nil
        end
    end

    local list = {}
    for _, rec in pairs(emitted) do
        if rec then
            list[#list + 1] = rec
        end
    end

    return {
        mode = mode,
        list = list,
        rps = rps,
        mean = ctx.baseline.mean,
        sigma = sigma,
        entropy = entropy_info,
        warming = warming,
        frozen = frozen_before,
    }
end

return _M
