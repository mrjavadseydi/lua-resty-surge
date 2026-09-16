local ip = require "resty.surge.clientip"

local function v4(a, b, c, d)
    return string.char(a, b, c, d)
end

describe("client address", function()
    it("matches a byte-aligned CIDR and rejects the neighbour", function()
        local rule = ip.parse_cidr("10.0.0.0/8")
        assert(ip.matches(rule, v4(10, 1, 2, 3)))
        assert(not ip.matches(rule, v4(11, 0, 0, 1)))
    end)

    it("matches a /20 using the partial byte", function()
        local rule = ip.parse_cidr("10.1.16.0/20")
        assert(ip.matches(rule, v4(10, 1, 20, 5)))
        assert(ip.matches(rule, v4(10, 1, 31, 255)))
        assert(not ip.matches(rule, v4(10, 1, 32, 1)))
        assert(not ip.matches(rule, v4(10, 2, 20, 1)))
    end)

    it("parses compressed ipv6 and a /32", function()
        local rule = ip.parse_cidr("2001:db8::/32")
        local inside = ip.parse_cidr("2001:db8:1::1")
        local outside = ip.parse_cidr("2001:db9::1")
        assert(ip.matches(rule, inside.bin))
        assert(not ip.matches(rule, outside.bin))
    end)

    it("folds an ipv4-mapped address to 4 bytes", function()
        local mapped = string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 10, 1, 2, 3)
        local family, bin = ip.identity(mapped)
        assert(family == "v4")
        assert(bin == v4(10, 1, 2, 3))
        local v6 = ip.parse_cidr("2001:db8::1").bin
        assert(ip.identity(v6) == "v6")
    end)

    it("treats a leading slash as a path", function()
        local rule = ip.allow_rule("/health")
        assert(rule.path == "/health")
    end)
end)
