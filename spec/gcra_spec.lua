local gcra = require "resty.surge.gcra"

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

    it("divides only the rate across workers", function()
        local interval, tau = gcra.worker_params(100, 4, 4)
        local one, _ = gcra.params(25, 4)
        assert(math.abs(interval - one) < 1e-12)
        assert(math.abs(tau - 3 / 25) < 1e-12)
    end)
end)
