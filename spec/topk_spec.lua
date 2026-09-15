local topk = require "resty.surge.topk"
local sketch = require "resty.surge.sketch"

describe("space-saving", function()
    it("replaces the minimum and keeps the error bound", function()
        local tk = topk.new(2)
        local stream = { "a", "a", "a", "b", "b", "c" }
        for i = 1, #stream do
            topk.add(tk, stream[i], 1)
        end
        local ca, ea = topk.get(tk, "a")
        local cc, ec = topk.get(tk, "c")
        assert(ca == 3 and ea == 0, "a")
        assert(cc == 3 and ec == 2, "c count " .. tostring(cc) .. " err " .. tostring(ec))
        assert(topk.get(tk, "b") == nil)
        assert(cc - ec <= 1 and 1 <= cc)
    end)

    it("keeps a heavy key while uniques churn", function()
        local tk = topk.new(10)
        for _ = 1, 100 do
            topk.add(tk, "heavy", 1)
        end
        for i = 1, 50 do
            topk.add(tk, "u" .. i, 1)
        end
        local c = topk.get(tk, "heavy")
        assert(c == 100, "heavy count " .. tostring(c))
    end)

    it("recovers zipf keys with share >= 1% inside the error bound", function()
        math.randomseed(7)
        local universe = 100000
        local draws = 1000000
        local k = 128
        local s = 1.1

        local keys = {}
        for i = 1, universe do
            local n = i - 1
            keys[i] = string.char(math.floor(n / 65536), math.floor(n / 256) % 256, n % 256)
        end

        local cdf = {}
        local sum = 0
        for i = 1, universe do
            sum = sum + i ^ (-s)
            cdf[i] = sum
        end

        local function sample()
            local u = math.random() * sum
            local lo, hi = 1, universe
            while lo < hi do
                local mid = math.floor((lo + hi) / 2)
                if cdf[mid] < u then
                    lo = mid + 1
                else
                    hi = mid
                end
            end
            return lo
        end

        local tk = topk.new(k)
        local truth = {}
        for _ = 1, draws do
            local id = sample()
            local key = keys[id]
            truth[key] = (truth[key] or 0) + 1
            topk.add(tk, key, 1)
        end

        local heavy = 0
        for key, count in pairs(truth) do
            if count / draws >= 0.01 then
                heavy = heavy + 1
                local est, err = topk.get(tk, key)
                assert(est ~= nil, "missing heavy key with count " .. count)
                assert(count <= est, "overestimate violated")
                assert(est - err <= count, "error bound violated est " .. est .. " err " .. err .. " true " .. count)
            end
        end
        assert(heavy >= 1, "zipf produced no key at 1% share")

        for key, _ in pairs(tk.index) do
            local est, err = topk.get(tk, key)
            local count = truth[key] or 0
            assert(count <= est)
            assert(est - err <= count)
        end
    end)
end)

describe("sketch-gated admission", function()
    it("finds three heavy keys and does not thrash on a million uniques", function()
        local sk = sketch.new(2048, 4)
        local admit = 0.005
        local tk = topk.new(16, function(key)
            local total = sketch.total(sk)
            if total <= 0 then
                return true
            end
            return sketch.query(sk, key) >= admit * total
        end)

        local function observe(key, n)
            for _ = 1, n do
                sketch.add(sk, key, 1)
                topk.add(tk, key, 1)
            end
        end

        for i = 1, 1000000 do
            local n = i
            observe(string.char(
                math.floor(n / 16777216) % 256,
                math.floor(n / 65536) % 256,
                math.floor(n / 256) % 256,
                n % 256
            ), 1)
        end

        local heavies = { "\255\0\0\1", "\255\0\0\2", "\255\0\0\3" }
        for h = 1, #heavies do
            observe(heavies[h], 20000)
        end

        for h = 1, #heavies do
            assert(topk.get(tk, heavies[h]) ~= nil, "missing heavy " .. h)
        end
        assert(tk.replacements < 1000,
            "replacements " .. tk.replacements .. " (gate failed to stop churn)")
    end)
end)
