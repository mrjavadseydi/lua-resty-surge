-- Per-key stages: observe → limit → challenge → block.
--
-- `consecutive` offending ticks are required for each step. Confidence at or
-- above `confidence_skip` (default 0.9) takes the step on a single tick.
-- A repeat block doubles the TTL up to ttl_max.
-- In dry-run the caller passes cap "observe", so the stage never leaves the
-- log-only state. API keys pass api_only and skip challenge: there is no
-- page to run for a client that does not execute JavaScript.
-- Cap "challenge" stops a host decision there and keeps extending it.

local _M = {}

function _M.new(incident)
    return {
        stage = "observe",
        streak = 0,
        repeats = 0,
        ttl = 0,
        until_ts = 0,
        incident = incident,
        confidence = 0,
    }
end

function _M.step(st, offending, confidence, opts, now, cap, api_only)
    if cap == "observe" then
        st.stage = "observe"
        st.confidence = confidence or 0
        st.streak = 0
        return st
    end

    if not offending then
        st.streak = 0
        if st.stage ~= "observe" and now >= (st.until_ts or 0) then
            st.stage = "observe"
            st.ttl = 0
        end
        return st
    end

    -- A site-wide decision tops out at challenge. Blocking a host is the outage.
    if cap == "challenge" and st.stage == "challenge" then
        st.streak = 0
        st.confidence = confidence
        st.until_ts = now + (st.ttl > 0 and st.ttl or (opts.ttl_base or 60))
        return st
    end

    local need = opts.consecutive or 1
    local skip = opts.confidence_skip or 0.9
    if confidence >= skip then
        need = 1
    end
    st.streak = (st.streak or 0) + 1
    st.confidence = confidence
    if st.streak < need then
        return st
    end
    st.streak = 0

    local base = opts.ttl_base or 60
    local max_ttl = opts.ttl_max or base
    local function enter_block()
        -- One repeat per time we arrive at block, not per tick we stay there.
        st.stage = "block"
        st.repeats = (st.repeats or 0) + 1
        local ttl = base * (2 ^ (st.repeats - 1))
        if ttl > max_ttl then
            ttl = max_ttl
        end
        st.ttl = ttl
    end

    if st.stage == "observe" then
        st.stage = "limit"
        st.ttl = base
    elseif st.stage == "limit" then
        -- API paths cannot run the page. challenge_ready false skips it too.
        if cap ~= "challenge"
            and (api_only or opts.api_only or opts.challenge_ready == false)
        then
            enter_block()
        else
            st.stage = "challenge"
            st.ttl = base
        end
    elseif st.stage == "challenge" then
        enter_block()
    end
    st.until_ts = now + (st.ttl > 0 and st.ttl or base)
    return st
end

return _M
