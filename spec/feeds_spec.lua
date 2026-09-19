local feeds = require "resty.surge.feeds"
local ipdb = require "resty.surge.ipdb"

local dir = "/tmp/surge-feeds-spec"

local function cidr_n(n, prefix)
    local out = {}
    for i = 1, n do
        out[i] = string.format("%s%d.%d.0/24", prefix or "10.", math.floor((i - 1) / 256), (i - 1) % 256)
    end
    return out
end

describe("feed parsing and validation", function()
    it("parses spamhaus text and ignores semicolon comments", function()
        local parsed = feeds.parse(
            "; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n\n; eof\n",
            "spamhaus")
        assert(#parsed.cidrs == 1)
        assert(parsed.errors == 0)
        assert(feeds.validate(parsed, nil))
    end)

    it("rejects an empty list", function()
        local parsed = feeds.parse("; merged into drop.txt\n; EOF\n", "spamhaus")
        local ok, err = feeds.validate(parsed, nil)
        assert(not ok)
        assert(err == "empty")
    end)

    it("rejects a garbled list", function()
        local lines = {}
        for _ = 1, 20 do
            lines[#lines + 1] = "not-a-network"
        end
        lines[#lines + 1] = "1.2.3.0/24"
        local parsed = feeds.parse(table.concat(lines, "\n"), "cidr")
        local ok, err = feeds.validate(parsed, nil)
        assert(not ok)
        assert(err:find("parse errors", 1, true))
    end)

    it("rejects a list that shrank by 90% and keeps the previous file", function()
        local old = cidr_n(100)
        assert(feeds.write_list(dir, "drop", old))
        local have = feeds.read_list(feeds.list_path(dir, "drop"))
        assert(#have == 100)
        local body = table.concat(cidr_n(10), "\n") .. "\n"
        local ok, err = feeds.apply_body(dir, "drop", body, "cidr", #have)
        assert(not ok)
        assert(err:find("size changed by 90%", 1, true))
        have = feeds.read_list(feeds.list_path(dir, "drop"))
        assert(#have == 100)
        assert(feeds.read_note(dir, "drop"):find("size changed", 1, true))
    end)

    it("activates a valid update", function()
        local body = table.concat(cidr_n(100), "\n") .. "\n"
        local ok, n = feeds.apply_body(dir, "fresh", body, "cidr", 80)
        assert(ok == "updated")
        assert(n == 100)
        local have = feeds.read_list(feeds.list_path(dir, "fresh"))
        assert(#have == 100)
        assert(feeds.read_note(dir, "fresh") == nil)
    end)

    it("parses a goodbots JSON prefix list", function()
        local parsed = feeds.parse([[{
            "prefixes": [
                {"ipv4Prefix": "8.8.8.0/24"},
                {"ipv6Prefix": "2001:db8::/32"}
            ]
        }]], "goodbots")
        assert(#parsed.cidrs == 2)
        assert(feeds.validate(parsed, nil))
    end)

    it("reads a saved list back as plain cidr lines regardless of format", function()
        assert(feeds.write_list(dir, "saved-goodbots", { "8.8.8.0/24", "2001:db8::/32" }))
        local cidrs = feeds.read_list(feeds.list_path(dir, "saved-goodbots"), "cidr")
        assert(#cidrs == 2)
        assert(cidrs[1] == "8.8.8.0/24")
        local as_json = feeds.read_list(feeds.list_path(dir, "saved-goodbots"), "goodbots")
        assert(#as_json == 0)
    end)

    it("fingerprints a same-length swap of one network for another", function()
        assert(feeds.write_list(dir, "fp-a", { "10.0.0.0/24" }))
        assert(feeds.write_list(dir, "fp-b", { "10.0.1.0/24" }))
        local _, sum_a = feeds.read_list(feeds.list_path(dir, "fp-a"))
        local _, sum_b = feeds.read_list(feeds.list_path(dir, "fp-b"))
        assert(sum_a ~= sum_b)
        local _, sum_a2 = feeds.read_list(feeds.list_path(dir, "fp-a"))
        assert(sum_a == sum_a2)
    end)

    it("notices a one-byte edit in a file under 4KB", function()
        local function dump(name, body)
            local f = assert(io.open(feeds.list_path(dir, name), "wb"))
            f:write(body)
            f:close()
        end
        local prefix = "# surge\n" .. string.rep("10.0.0.0/8\n", 30)
        assert(#prefix < 4096)
        dump("small-a", prefix .. "10.1.0.0/32\n")
        dump("small-b", prefix .. "10.1.0.1/32\n")
        local _, sum_a = feeds.read_list(feeds.list_path(dir, "small-a"))
        local _, sum_b = feeds.read_list(feeds.list_path(dir, "small-b"))
        assert(sum_a ~= sum_b)
    end)

    it("creates a relative feed_dir under the working directory", function()
        local ffi = require "ffi"
        pcall(ffi.cdef, "int rmdir(const char *pathname);")
        local name = "surge-rel-spec"
        local function cleanup()
            os.remove(name .. "/nested/probe")
            ffi.C.rmdir(name .. "/nested")
            ffi.C.rmdir(name)
        end
        cleanup()
        local acc = feeds.ensure_dir(name .. "/nested")
        local ok, err = pcall(function()
            assert(acc == name .. "/nested")
            local f = assert(io.open(name .. "/nested/probe", "wb"))
            f:write("ok")
            f:close()
            local rooted = io.open("/" .. name .. "/nested/probe", "rb")
            if rooted then
                rooted:close()
            end
            assert(rooted == nil)
        end)
        cleanup()
        if not ok then
            error(err, 0)
        end
    end)
end)

describe("reputation trie", function()
    it("returns the feed name for the longest match and not for a miss", function()
        local db = ipdb.compile({
            { name = "spamhaus_drop", cidrs = { "1.10.16.0/20", "2001:db8::/32" } },
            { name = "goodbots", allow = true, cidrs = { "8.8.8.0/24" } },
        }, "short")
        local hit = ipdb.hit(db.block4, string.char(1, 10, 20, 5))
        assert(hit.reason == "reputation:spamhaus_drop")
        assert(hit.reason_hdr == "reputation:spamhaus_drop")
        assert(hit.incident == "srg-feed-spamhaus_drop")
        assert(ipdb.hit(db.block4, string.char(1, 10, 32, 1)) == nil)
        local v6 = require("resty.surge.clientip").parse_cidr("2001:db8:1::1")
        assert(ipdb.hit(db.block6, v6.bin).reason == "reputation:spamhaus_drop")
        assert(ipdb.hit(db.allow4, string.char(8, 8, 8, 8)).feed == "goodbots")
    end)

    it("hides the reason when expose_reason is id", function()
        local db = ipdb.compile({
            { name = "office", cidrs = { "127.0.0.1" } },
        }, "id")
        local hit = ipdb.hit(db.block4, string.char(127, 0, 0, 1))
        assert(hit.reason_hdr == nil)
        assert(hit.body_html:find("srg-feed-office", 1, true))
    end)
end)

describe("feed fetch", function()
    it("returns the body, and not-modified when the etag matches", function()
        local fake = {
            new = function()
                return {
                    set_timeout = function() end,
                    request_uri = function(_, _, req)
                        if req.headers["If-None-Match"] == '"abc"' then
                            return { status = 304, headers = {}, body = "" }
                        end
                        return {
                            status = 200,
                            headers = { etag = '"abc"' },
                            body = "10.0.0.0/8\n",
                        }
                    end,
                }
            end,
        }
        local body, err = feeds.fetch("http://feeds.example/list", nil, fake)
        assert(err == nil)
        assert(body == "10.0.0.0/8\n")
        local _, err2 = feeds.fetch("http://feeds.example/list", { etag = '"abc"' }, fake)
        assert(err2 == "not modified")
    end)

    it("stores an etag only after the list write succeeds", function()
        local bag = {}
        local res = { headers = { etag = '"abc"' } }
        assert(feeds.remember_etag(bag, "drop", res, false) == false)
        assert(bag.drop == nil)
        assert(feeds.remember_etag(bag, "drop", { headers = {} }, true) == false)
        assert(bag.drop == nil)
        assert(feeds.remember_etag(bag, "drop", res, true) == true)
        assert(bag.drop == '"abc"')
    end)
end)
