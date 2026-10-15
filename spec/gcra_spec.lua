local gcra = require "resty.surge.gcra"

local function dict()
    local d = { v = {} }
    function d:get(k) return self.v[k] end
    function d:safe_add(k, value)
        if self.v[k] ~= nil then return nil, "exists" end
        self.v[k] = value
        return true
    end
    function d:safe_set(k, value) self.v[k] = value; return true end
    function d:delete(k) self.v[k] = nil end
    function d:incr(k, by, init)
        local current = self.v[k]
        if current == nil then
            if init == nil then return nil, "not found" end
            current = init
        end
        self.v[k] = current + by
        return self.v[k]
    end
    return d
end

describe("gcra", function()
    it("allows one request per interval when burst is 1", function()
        local interval, tau = gcra.params(10, 1)
        assert(math.abs(interval - 0.1) < 1e-12)
        assert(tau == 0)

        local ok, tat = gcra.check(nil, 0, interval, tau)
        assert(ok == true)
        assert(math.abs(tat - 0.1) < 1e-12)

        ok, tat = gcra.check(tat, 0, interval, tau)
        assert(ok == false)

        ok, tat = gcra.check(tat, 0.1, interval, tau)
        assert(ok == true)
        assert(math.abs(tat - 0.2) < 1e-12)

        ok, tat = gcra.check(tat, 0.1, interval, tau)
        assert(ok == false)

        -- a long gap costs nothing extra
        ok, tat = gcra.check(tat, 100, interval, tau)
        assert(ok == true)
        assert(math.abs(tat - 100.1) < 1e-9)
    end)

    it("allows exactly the configured burst and then the rate", function()
        local interval, tau = gcra.params(10, 5)
        assert(math.abs(tau - 0.4) < 1e-12)

        local tat = nil
        local ok
        for i = 1, 5 do
            ok, tat = gcra.check(tat, 0, interval, tau)
            assert(ok == true, "burst request " .. i .. " rejected")
        end
        ok, tat = gcra.check(tat, 0, interval, tau)
        assert(ok == false, "6th burst request allowed")

        -- one cell frees every 0.1s
        for step = 1, 10 do
            local t = step * 0.1
            ok, tat = gcra.check(tat, t, interval, tau)
            assert(ok == true, "steady request at " .. t .. " rejected")
            ok, tat = gcra.check(tat, t, interval, tau)
            assert(ok == false, "extra request at " .. t .. " allowed")
        end
    end)

    it("runs the same limit on a shared dict", function()
        local d = dict()
        -- Rate 8: every tat below is exact in binary, so no boundary rounds.
        local interval, tau = gcra.params(8, 5)
        local ok_n = 0
        for _ = 1, 20 do
            if gcra.shared(d, "k", 100, interval, tau, 60) then
                ok_n = ok_n + 1
            end
        end
        -- The burst at one instant, as check() allows.
        assert(ok_n == 5)
        -- Denied requests gave their interval back: one more a cell later.
        assert(gcra.shared(d, "k", 100.1875, interval, tau, 60) == true)
        assert(gcra.shared(d, "k", 100.1875, interval, tau, 60) == false)
        -- A long gap resets to now instead of banking credit.
        ok_n = 0
        for _ = 1, 20 do
            if gcra.shared(d, "k", 500, interval, tau, 60) then
                ok_n = ok_n + 1
            end
        end
        assert(ok_n == 5)
    end)

    it("does not add idle-time debt when workers race on a stale clock", function()
        local d = dict()
        d.v.k = 100
        local get, incr = d.get, d.incr
        local pause = true
        function d:get(k)
            local value = get(self, k)
            if pause then coroutine.yield() end
            return value
        end
        function d:incr(...)
            local value = incr(self, ...)
            if pause then coroutine.yield() end
            return value
        end
        local interval, tau = gcra.params(80, 10)
        local first, second
        local worker = coroutine.create(function()
            first = gcra.shared(d, "k", 200, interval, tau, 600)
        end)
        local other = coroutine.create(function()
            second = gcra.shared(d, "k", 200, interval, tau, 600)
        end)
        assert(coroutine.resume(worker))
        assert(coroutine.resume(other))
        pause = false
        assert(coroutine.resume(worker))
        if coroutine.status(other) == "suspended" then
            assert(coroutine.resume(other))
        end
        assert(first and not second)
        assert(gcra.shared(d, "k", 200, interval, tau, 600))
        assert(math.abs(d.v.k - 200 - 2 * interval) < 1e-9)
        assert(d.v["k:lock"] == nil)
    end)

    it("fails open on no memory and releases the lock after a failed write", function()
        local d = dict()
        d.safe_add = function() return nil, "no memory" end
        assert(gcra.shared(d, "k", 200, 1, 0, 60))
        d = dict()
        d.safe_set = function() return nil, "no memory" end
        assert(gcra.shared(d, "k", 200, 1, 0, 60))
        assert(d.v["k:lock"] == nil)
    end)
end)
