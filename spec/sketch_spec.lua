local sketch = require "resty.surge.sketch"

describe("count-min sketch", function()
    it("matches the IEEE CRC of a known string", function()
        local h1 = sketch.hash_pair("123456789")
        -- First hash is CRC-32. 0xCBF43926.
        assert(h1 == 0xCBF43926, "crc " .. tostring(h1))
    end)

    it("forces the second hash odd", function()
        local _, h2 = sketch.hash_pair("123456789")
        assert(h2 % 2 == 1, "h2 " .. tostring(h2))
        local _, z = sketch.hash_pair("")
        assert(z % 2 == 1)
    end)

    it("never underestimates and stays inside the CMS bound", function()
        math.randomseed(1)
        local width, depth = 2048, 4
        local sk = sketch.new(width, depth)
        local n_keys = 500
        local n_events = 20000
        local true_count = {}
        for i = 1, n_keys do
            true_count[i] = 0
        end
        for _ = 1, n_events do
            local k = math.random(n_keys)
            local key = string.char(math.floor(k / 256), k % 256)
            true_count[k] = true_count[k] + 1
            sketch.add(sk, key, 1)
        end

        local eps = sketch.epsilon(width)
        local bound = eps * n_events
        local over = 0
        local seen = 0
        for k = 1, n_keys do
            local key = string.char(math.floor(k / 256), k % 256)
            local est = sketch.query(sk, key)
            local truth = true_count[k]
            assert(est >= truth, "underestimate key " .. k .. " est " .. est .. " truth " .. truth)
            if est - truth > bound then
                over = over + 1
            end
            seen = seen + 1
        end
        -- δ = e^-4 ≈ 0.018. A fixed seed should land well under 5%.
        local frac = over / seen
        assert(frac <= 0.05, "fraction over the εN bound: " .. frac)
    end)

    it("does not wrap a saturated counter", function()
        local sk = sketch.new(16, 4)
        sketch.add(sk, "x", 4294967295)
        assert(sketch.query(sk, "x") == 4294967295)
        sketch.add(sk, "x", 10)
        assert(sketch.query(sk, "x") == 4294967295, "wrapped")
    end)

    it("rotates by filling the spare buffer", function()
        local sk = sketch.new(16, 4)
        sketch.add(sk, "x", 5)
        assert(sketch.query(sk, "x") == 5)
        local before = sketch.total(sk)
        sketch.rotate(sk)
        assert(sketch.query(sk, "x") == 0)
        assert(sketch.total(sk) == 0)
        assert(sk.prev_total == before)
        sketch.add(sk, "x", 2)
        assert(sketch.query(sk, "x") == 2)
    end)

    it("allocates nothing on a repeated add after the trace is compiled", function()
        local sk = sketch.new()
        local key = "\1\2\3\4"
        -- One function, so every window shares a trace. The first call after a
        -- collection records that trace; the next call is the steady state.
        local function pump(n)
            for _ = 1, n do
                sketch.add(sk, key, 1)
            end
        end
        pump(20000)
        collectgarbage()
        collectgarbage()
        pump(20000)
        local before = collectgarbage("count")
        pump(200000)
        local bytes = (collectgarbage("count") - before) * 1024
        assert(bytes < 512, "allocated " .. bytes .. " bytes over 2e5 adds")
    end)
end)
