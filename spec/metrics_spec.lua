local metrics = require "resty.surge.metrics"
local export = require "resty.surge.export"

describe("prometheus", function()
    it("counts results and reasons without an address label", function()
        local text = metrics.prometheus({
            mode = "attack",
            decisions = 2,
            totals = { allowed = 10, limited = 1, challenged = 0, blocked = 4 },
            reasons = { heavy_hitter = 3, ["reputation:spamhaus_drop"] = 1 },
            feeds = { { name = "goodbots", count = 8, allow = true } },
        })
        assert(text:find("surge_mode 2", 1, true))
        assert(text:find('surge_requests_total{result="blocked"} 4', 1, true))
        assert(text:find('reason="reputation:spamhaus_drop"', 1, true)
            or text:find('reason="reputation_spamhaus_drop"', 1, true))
        assert(text:find('surge_feed_networks{feed="goodbots",role="allow"} 8', 1, true))
        assert(not text:find("10.1.2.3", 1, true))
        assert(not text:find("ip=", 1, true))
    end)
end)

describe("kernel export", function()
    it("writes blocked addresses and skips a scoped decision", function()
        local lines = export.lines({
            {
                family = "v4", bits = 32, key = string.char(10, 1, 2, 3),
                action = "block", manual = true, ttl = 60, incident = "srg-1",
            },
            {
                family = "v4", bits = 32, key = string.char(10, 9, 9, 9),
                action = "block", uri = "/login", confidence = 1,
                ttl = 60, incident = "srg-2",
            },
        }, 1000, 0.9)
        assert(#lines == 1)
        assert(lines[1]:find("10.1.2.3", 1, true))
        local path = "/tmp/surge-export-spec.txt"
        assert(export.write(path, {
            {
                family = "v4", bits = 24, key = string.char(10, 1, 2),
                action = "block", confidence = 0.95, ttl = 30,
                incident = "srg-3",
            },
        }, 1000, 0.9))
        local f = assert(io.open(path, "rb"))
        local body = f:read("*a")
        f:close()
        os.remove(path)
        assert(body:find("10.1.2.0", 1, true) or body:find("10.1.2", 1, true))
    end)
end)
