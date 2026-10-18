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

    it("leaves out a network inside another so nft gets no overlap", function()
        local function rec(fam, bits, key, ttl, id)
            return { family = fam, bits = bits, key = key, action = "block",
                manual = true, ttl = ttl, incident = id }
        end
        local lines = export.lines({
            rec("v4", 24, string.char(10, 1, 2), 600, "net"),
            rec("v4", 32, string.char(10, 1, 2, 3), 900, "inside"),
            rec("v4", 32, string.char(10, 9, 9, 9), 60, "short"),
            rec("v4", 32, string.char(10, 9, 9, 9), 600, "long"),
            -- Host bits set: written as the network.
            rec("v4", 16, string.char(10, 7, 8, 9), 600, "hostbits"),
            rec("v6", 64, string.char(0xfd, 0, 0, 1, 0, 0, 0, 0), 600, "v6net"),
            rec("v6", 128, string.char(0xfd, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5),
                600, "v6inside"),
        }, nil, 0.9)
        local body = table.concat(lines, "\n")
        assert(#lines == 4, body)
        assert(body:find("v4 24 10.1.2.0 600 net", 1, true), body)
        assert(not body:find("inside", 1, true), body)
        assert(body:find("v4 32 10.9.9.9 600 long", 1, true), body)
        assert(body:find("v4 16 10.7.0.0 600 hostbits", 1, true), body)
        assert(body:find("v6 64 fd00:0001:0000:0000:0000:0000:0000:0000 600 v6net", 1, true), body)
    end)

    it("drops an expired block and a low-confidence automatic one", function()
        local lines = export.lines({
            {
                family = "v4", bits = 32, key = string.char(10, 1, 2, 3),
                action = "block", confidence = 0.95, ttl = 600,
                until_ts = 1000, incident = "gone",
            },
            {
                family = "v4", bits = 32, key = string.char(10, 4, 5, 6),
                action = "block", confidence = 0.5, ttl = 600,
                until_ts = 5000, incident = "low",
            },
            {
                family = "v4", bits = 32, key = string.char(10, 7, 8, 9),
                action = "block", confidence = 0.95, ttl = 600,
                until_ts = 1900, incident = "stay",
            },
        }, 1500, 0.9)
        assert(#lines == 1)
        assert(lines[1]:find("10.7.8.9", 1, true))
        assert(lines[1]:find(" 400 ", 1, true))
    end)

    it("does not treat one reason name as a prefix of another", function()
        local blob = "reputation:firehol_level1\nmanual_x\n"
        assert(metrics.has_line(blob, "reputation:firehol_level1"))
        assert(not metrics.has_line(blob, "reputation:firehol_level"))
        assert(not metrics.has_line(blob, "manual"))
        assert(metrics.has_line(blob, "manual_x"))
    end)
end)

describe("decision labels", function()
    local messages = require "resty.surge.messages"
    it("prints IPv6 as text, compressed, for any prefix", function()
        assert(messages.label(string.char(0xfd, 0, 0, 1, 0, 0, 0, 0), 64, true) == "fd00:1::/64")
        assert(messages.label(string.rep("\0", 16), 0, true) == "::/0")
        assert(messages.label(string.char(0x20, 1, 0x0d, 0xb8) .. string.rep("\0", 11) .. "\1",
            128, true) == "2001:db8::1")
        assert(messages.label(string.char(10, 1, 2), 24) == "10.1.2.0/24")
        assert(messages.label(string.char(10, 1, 2, 3), 32) == "10.1.2.3")
    end)
end)
