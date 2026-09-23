local escalation = require "resty.surge.escalation"

local opts = {
    consecutive = 1,
    confidence_skip = 0.5,
    ttl_base = 60,
    ttl_max = 240,
    challenge_ready = true,
}

describe("escalation", function()
    it("walks observe, limit, challenge, block and doubles on a repeat", function()
        local st = escalation.new("srg-1")
        escalation.step(st, true, 1, opts, 0, nil)
        assert(st.stage == "limit")
        escalation.step(st, true, 1, opts, 1, nil)
        assert(st.stage == "challenge")
        escalation.step(st, true, 1, opts, 2, nil)
        assert(st.stage == "block")
        assert(st.ttl == 60)
        local ttl = st.ttl
        escalation.step(st, true, 1, opts, 3, nil)
        assert(st.stage == "block")
        assert(st.ttl == ttl)

        escalation.step(st, false, 0, opts, 3 + ttl, nil)
        assert(st.stage == "observe")

        escalation.step(st, true, 1, opts, 1000, nil)
        escalation.step(st, true, 1, opts, 1001, nil)
        escalation.step(st, true, 1, opts, 1002, nil)
        assert(st.stage == "block")
        assert(st.ttl == 120)
    end)

    it("stays at observe in dry-run and skips challenge for api clients", function()
        local st = escalation.new("srg-2")
        escalation.step(st, true, 1, opts, 0, "observe")
        assert(st.stage == "observe")

        local api = {
            consecutive = 1, confidence_skip = 0.5,
            ttl_base = 10, ttl_max = 40,
            api_only = true,
        }
        local s2 = escalation.new("srg-3")
        escalation.step(s2, true, 1, api, 0, nil)
        assert(s2.stage == "limit")
        escalation.step(s2, true, 1, api, 1, nil)
        assert(s2.stage == "block")
    end)

    it("stops a capped key at challenge, even for api or no page", function()
        local st = escalation.new("srg-5")
        local o = {
            consecutive = 1, confidence_skip = 0.5,
            ttl_base = 10, ttl_max = 40, challenge_ready = false,
        }
        escalation.step(st, true, 1, o, 0, "challenge", true)
        assert(st.stage == "limit")
        escalation.step(st, true, 1, o, 1, "challenge", true)
        assert(st.stage == "challenge")
        for t = 2, 6 do
            escalation.step(st, true, 1, o, t, "challenge", true)
            assert(st.stage == "challenge")
        end
        assert(st.until_ts == 16)
        escalation.step(st, false, 0, o, 17, nil)
        assert(st.stage == "observe")
    end)

    it("waits for consecutive ticks when confidence is low", function()
        local slow = {
            consecutive = 3, confidence_skip = 0.99,
            ttl_base = 10, ttl_max = 10, challenge_ready = true,
        }
        local st = escalation.new("srg-4")
        escalation.step(st, true, 0.2, slow, 0, nil)
        escalation.step(st, true, 0.2, slow, 1, nil)
        assert(st.stage == "observe")
        escalation.step(st, true, 0.2, slow, 2, nil)
        assert(st.stage == "limit")
    end)
end)
