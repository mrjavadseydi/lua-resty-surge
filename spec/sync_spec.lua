local sync = require "resty.surge.sync"
local topk = require "resty.surge.topk"
local sketch = require "resty.surge.sketch"

describe("worker flush codec", function()
    it("round-trips keys and scales sampled counts", function()
        local tk = topk.new(4)
        topk.add(tk, "\10\0\0\1", 3)
        topk.add(tk, "\10\1\2", 1)
        local items = sync.decode_topk(sync.encode_topk(tk, 16))
        assert(#items == 2)
        local by = {}
        for i = 1, #items do
            by[items[i].key] = items[i].count
        end
        assert(by["\10\0\0\1"] == 48)
        assert(by["\10\1\2"] == 16)
    end)
end)

describe("prefix top-k", function()
    it("admits a /24 without a string until the gate opens", function()
        local sk = sketch.new(64, 4)
        local tk = topk.new(4)
        local full = "\10\1\2\9"
        local hashed = sketch.hash_pair(full, 3)
        sketch.add(sk, full, 1, 3)
        -- One hit is 100% of a tiny window, so the gate opens and the key is stored.
        local allow = sketch.query(sk, full, 3) >= 0.5 * sketch.total(sk)
        assert(allow)
        assert(topk.add_prefix(tk, full, 3, hashed, 1, allow))
        assert(topk.get(tk, "\10\1\2") == 1)

        -- A second address in the same /24 increments without needing a new key.
        local other = "\10\1\2\8"
        sketch.add(sk, other, 1, 3)
        local h2 = sketch.hash_pair(other, 3)
        assert(h2 == hashed)
        assert(topk.add_prefix(tk, other, 3, h2, 4, false))
        assert(topk.get(tk, "\10\1\2") == 5)
    end)

    it("hashes a prefix the same as the prefix string", function()
        local full = "\10\1\2\9"
        local a, b = sketch.hash_pair(full, 3)
        local c, d = sketch.hash_pair("\10\1\2")
        assert(a == c and b == d)
        local sk = sketch.new(32, 4)
        sketch.add(sk, full, 7, 3)
        assert(sketch.query(sk, "\10\1\2") == 7)
    end)
end)
