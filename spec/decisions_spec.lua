local decisions = require "resty.surge.decisions"
local clientip = require "resty.surge.clientip"

local function yes()
    return true
end

local function v4(a, b, c, d)
    return string.char(a, b, c, d)
end

describe("decision trie", function()
    it("prefers the longest byte-aligned match", function()
        local root = decisions.new_trie()
        local wide = { name = "wide" }
        local exact = { name = "exact" }
        decisions.insert(root, v4(10, 0, 0, 0), 24, wide)
        decisions.insert(root, v4(10, 0, 0, 5), 32, exact)
        assert(decisions.lookup(root, v4(10, 0, 0, 5), yes) == exact)
        assert(decisions.lookup(root, v4(10, 0, 0, 6), yes) == wide)
        assert(decisions.lookup(root, v4(11, 0, 0, 1), yes) == nil)
    end)

    it("matches a /20 and keeps a shorter hit when a scope rejects", function()
        local root = decisions.new_trie()
        local net = { name = "net", uri = nil }
        local host = { name = "host", uri = "/login" }
        decisions.insert(root, v4(10, 1, 16, 0), 20, net)
        decisions.insert(root, v4(10, 1, 20, 5), 32, host)
        local function accept(dec)
            return dec.uri == nil
        end
        assert(decisions.lookup(root, v4(10, 1, 20, 5), accept) == net)
        assert(decisions.lookup(root, v4(10, 1, 31, 1), yes) == net)
        assert(decisions.lookup(root, v4(10, 1, 32, 1), yes) == nil)
    end)

    it("enforces manual blocks over more specific automatic decisions", function()
        local cases = {
            { "0.0.0.0/0", "10.1.20.5" },
            { "10.1.16.0/20", "10.1.20.5" },
            { "10.1.20.0/24", "10.1.20.5" },
            { "2001:db8::/64", "2001:db8::5" },
            { "2001:db8:8000::/33", "2001:db8:9000::5" },
        }
        for _, case in ipairs(cases) do
            local net = assert(clientip.parse_cidr(case[1]))
            local ip = assert(clientip.parse_cidr(case[2]))
            for _, action in ipairs({ "observe", "limit", "challenge", "block" }) do
                local manual = { family = net.v6 and "v6" or "v4", key = net.bin,
                    bits = net.bits, action = "block", manual = true }
                local auto = { family = ip.v6 and "v6" or "v4", key = ip.bin,
                    bits = ip.bits, action = action }
                local t4, t6 = decisions.build({ manual, auto })
                assert(decisions.lookup(ip.v6 and t6 or t4, ip.bin, yes) == manual,
                    case[1] .. " was hidden by " .. action)
            end
        end
    end)

    it("keeps a scoped manual block and an automatic rule at the same prefix", function()
        for _, bits in ipairs({ 0, 20, 24 }) do
            for _, manual_first in ipairs({ false, true }) do
                local root = decisions.new_trie()
                local manual = { action = "block", manual = true, uri = "/login" }
                local auto = { action = "limit" }
                local first, second = manual, auto
                if not manual_first then first, second = auto, manual end
                decisions.insert(root, v4(10, 1, 16, 0), bits, first)
                decisions.insert(root, v4(10, 1, 16, 0), bits, second)
                assert(decisions.lookup(root, v4(10, 1, 16, 5), yes) == manual)
                assert(decisions.lookup(root, v4(10, 1, 16, 5), function(d)
                    return not d.uri
                end) == auto, "rejected scope lost the automatic fallback")
            end
        end
    end)

    it("keeps the longest applicable manual block and honors scope rejection", function()
        local root = decisions.new_trie()
        local wide = { action = "block", manual = true }
        local scoped = { action = "block", manual = true, uri = "/login" }
        local auto = { action = "limit" }
        decisions.insert(root, v4(10, 1, 16, 0), 20, wide)
        decisions.insert(root, v4(10, 1, 20, 0), 24, scoped)
        decisions.insert(root, v4(10, 1, 20, 5), 32, auto)
        assert(decisions.lookup(root, v4(10, 1, 20, 5), yes) == scoped)
        assert(decisions.lookup(root, v4(10, 1, 20, 5), function(d)
            return not d.uri
        end) == wide)
    end)

    it("prioritizes a manual close without prioritizing other manual actions", function()
        for _, close in ipairs({ false, true }) do
            local root = decisions.new_trie()
            local manual = { action = "challenge", manual = true, close = close }
            local auto = { action = "limit" }
            decisions.insert(root, v4(10, 1, 20, 0), 24, manual)
            decisions.insert(root, v4(10, 1, 20, 5), 32, auto)
            local hit = decisions.lookup(root, v4(10, 1, 20, 5), yes)
            assert(hit == (close and manual or auto))
        end
    end)
end)

describe("decision snapshot", function()
    it("round-trips binary keys and a uri scope", function()
        local snap = {
            mode = "attack",
            list = {
                {
                    family = "v4",
                    bits = 32,
                    key = "\127\0\0\1",
                    action = "block",
                    reason = "manual",
                    message = "blocked on purpose",
                    uri = "/login",
                    close = false,
                    status = 403,
                    ttl = 600,
                    incident = "srg-1",
                },
            },
        }
        local back = decisions.decode(decisions.encode(snap))
        assert(back.mode == "attack")
        assert(#back.list == 1)
        local r = back.list[1]
        assert(r.key == "\127\0\0\1")
        assert(r.uri == "/login")
        assert(r.reason == "manual")
        assert(r.message == "blocked on purpose")
        assert(r.ttl == 600)
        assert(r.status == 403)
        assert(r.close == false)
        assert(r.incident == "srg-1")
        assert(r.manual == false)
        assert(r.until_ts == nil)
        assert(r.confidence == nil)
    end)

    it("keeps a manual block and its expiry across a snapshot", function()
        local snap = {
            mode = "normal",
            list = {
                {
                    family = "v4",
                    bits = 32,
                    key = "\10\0\0\9",
                    action = "block",
                    reason = "manual",
                    message = "operator",
                    close = false,
                    status = 403,
                    ttl = 600,
                    until_ts = 1700000000,
                    manual = true,
                    incident = "srg-manual",
                },
            },
        }
        local r = decisions.decode(decisions.encode(snap)).list[1]
        assert(r.manual == true)
        assert(r.until_ts == 1700000000)
        local auto = {
            mode = "attack",
            list = {
                {
                    family = "v4", bits = 32, key = "\10\0\0\9",
                    action = "block", reason = "heavy_hitter",
                    message = "auto", close = false, status = 403,
                    ttl = 60, until_ts = 1700000060, confidence = 0.95,
                    incident = "srg-auto",
                },
            },
        }
        local kept = decisions.decode(decisions.encode(auto)).list[1]
        assert(math.abs(kept.confidence - 0.95) < 0.0001)
        assert(kept.until_ts == 1700000060)
        local fp = decisions.decode(decisions.encode({
            mode = "attack",
            list = {
                {
                    family = "fp", bits = 0, key = "2GET20au",
                    action = "challenge", reason = "heavy_hitter",
                    message = "fp", close = false, status = 403,
                    ttl = 30, incident = "srg-fp",
                },
            },
        })).list[1]
        assert(fp.family == "fp")
        assert(fp.key == "2GET20au")
        assert(fp.action == "challenge")
        assert(r.action == "block")
        assert(r.incident == "srg-manual")
    end)

    it("round-trips a host decision and keeps it out of the ip trie", function()
        local snap = {
            mode = "attack",
            list = {
                {
                    family = "host", bits = 0, key = "a.io",
                    action = "challenge", reason = "host_surge",
                    message = "site", close = false, status = 429,
                    ttl = 60, incident = "srg-h", rate = 2000.5,
                },
            },
        }
        local back = decisions.decode(decisions.encode(snap)).list
        assert(back[1].family == "host")
        assert(back[1].key == "a.io")
        assert(back[1].reason == "host_surge")
        -- The site cap crosses workers; limit_rps is not the fallback.
        assert(back[1].rate == 2000.5)
        -- "a.io" is four bytes. It must not become the ipv4 97.46.105.111.
        local t4 = decisions.build(back)
        assert(decisions.lookup(t4, "a.io", yes) == nil)
    end)

    it("rejects a blob from another format instead of misreading it", function()
        local blob = decisions.encode({ mode = "attack", list = {} })
        assert(decisions.decode(blob).mode == "attack")
        -- The pre-header layout started with the mode's u16 length.
        local snap, err = decisions.decode(blob:sub(3))
        assert(snap == nil and err == "format")
        snap, err = decisions.decode("S\255" .. blob:sub(3))
        assert(snap == nil and err == "format")
    end)
end)
