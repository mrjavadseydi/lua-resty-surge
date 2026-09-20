-- Preset parameters. Comments say what the value changes.
-- Starting points from the spec. Simulation in a later phase is what tunes them.

local function preset(t)
    return t
end

local M = {}

M.relaxed = preset({
    -- How often workers flush and the leader re-evaluates, in seconds.
    tick = 0.5,
    -- EWMA memory. Longer means a spike has to outrun a slower average.
    half_life = 15 * 60,
    -- Standard deviations above the mean required to enter each mode.
    k_elev = 4,
    k_attack = 6,
    -- Floor so a quiet site cannot enter attack by going from a handful of rps to a few dozen.
    min_rps = 200,
    -- A key must exceed this fraction of traffic, and this multiple of its own baseline share.
    abs_share = 0.10,
    multiplier = 20,
    -- Offending ticks required before observe → limit → challenge → block.
    consecutive = 8,
    -- First block lifetime, and the cap after repeated offenses double it.
    ttl_base = 5 * 60,
    ttl_max = 6 * 3600,
    -- Normal mode counts 1 in N requests. Elevated is 1 in 4, attack is every request.
    sample = 32,
    topk = 64,
    -- Leave elevated/attack only after the trigger has stayed false this long.
    cooldown = 90,
    -- No baseline blocks during this window. Reputation and the hard per-IP cap still apply.
    warmup = 180,
    -- Maximum relative rise of the baseline per hour while the mode is normal.
    max_growth_per_hour = 2,
    -- Sketch gate. Below this share of the window, a new key cannot enter top-K.
    admit_share = 0.01,
    -- Absolute change in normalized entropy that counts as a drop or a rise.
    entropy_drop = 0.25,
    entropy_rise = 0.25,
    -- Per-IP ceiling used before the baseline is warm.
    hard_ip_rps = 2000,
    -- A heavy key under this rate is not an offender, whatever its share.
    min_key_rps = 50,
    -- Global rate the limit stage enforces for one key. Each worker gets rate/workers.
    limit_rps = 200,
    -- At or above this confidence a stage change takes one tick.
    confidence_skip = 0.95,
    -- The challenge page exists. API paths still skip it and block.
    challenge_ready = true,
    -- Leading zero bits the browser must find. Higher is slower for bots.
    pow_bits = 12,
    -- How long a solved challenge cookie stays valid, in seconds.
    pow_ttl = 1800,
    -- Workers accept the previous HMAC secret for this long after rotation.
    secret_rotate = 86400,
    sketch_width = 2048,
    sketch_depth = 4,
    -- Extra requests the limit stage may pass at once, per worker.
    gcra_burst = 10,
    test_hooks = false,
    -- Seconds between worker re-reads of feed files. Remote updates also bump a shared version.
    feed_poll = 30,
})

M.balanced = preset({
    tick = 0.25,
    half_life = 10 * 60,
    k_elev = 3,
    k_attack = 5,
    min_rps = 100,
    abs_share = 0.05,
    multiplier = 10,
    consecutive = 4,
    ttl_base = 10 * 60,
    ttl_max = 24 * 3600,
    sample = 16,
    topk = 128,
    cooldown = 60,
    warmup = 120,
    max_growth_per_hour = 1,
    admit_share = 0.005,
    entropy_drop = 0.20,
    entropy_rise = 0.20,
    hard_ip_rps = 1000,
    min_key_rps = 20,
    limit_rps = 80,
    confidence_skip = 0.9,
    challenge_ready = true,
    pow_bits = 16,
    pow_ttl = 1200,
    secret_rotate = 86400,
    sketch_width = 2048,
    sketch_depth = 4,
    gcra_burst = 10,
    test_hooks = false,
    -- Seconds between worker re-reads of feed files. Remote updates also bump a shared version.
    feed_poll = 30,
})

M.strict = preset({
    tick = 0.25,
    half_life = 5 * 60,
    k_elev = 2.5,
    k_attack = 4,
    min_rps = 50,
    abs_share = 0.02,
    multiplier = 5,
    consecutive = 2,
    ttl_base = 30 * 60,
    ttl_max = 24 * 3600,
    sample = 8,
    topk = 256,
    cooldown = 45,
    warmup = 90,
    max_growth_per_hour = 0.5,
    admit_share = 0.002,
    entropy_drop = 0.15,
    entropy_rise = 0.15,
    hard_ip_rps = 500,
    min_key_rps = 10,
    limit_rps = 40,
    confidence_skip = 0.8,
    challenge_ready = true,
    pow_bits = 18,
    pow_ttl = 600,
    secret_rotate = 86400,
    sketch_width = 2048,
    sketch_depth = 4,
    gcra_burst = 10,
    test_hooks = false,
    -- Seconds between worker re-reads of feed files. Remote updates also bump a shared version.
    feed_poll = 30,
})

function M.copy(name)
    local src = M[name]
    if not src then
        return nil
    end
    local out = {}
    for k, v in pairs(src) do
        out[k] = v
    end
    return out
end

return M
