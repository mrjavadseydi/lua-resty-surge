local decisions = require "resty.surge.decisions"

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
end)
