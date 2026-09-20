local fp = require "resty.surge.fingerprint"

local RAW = table.concat({
    "accept: text/html",
    "accept-language: en-US,en;q=0.9",
    "user-agent: Demo/1",
    "cookie: session=abc",
    "accept-encoding: gzip",
}, "\r\n")

describe("http fingerprint", function()
    it("keeps http/1 header order and ignores the cookie value", function()
        local a = fp.parse_raw(RAW, 32)
        local b = fp.parse_raw(RAW:gsub("session=abc", "session=zzz"), 32)
        assert(a.order == "aluce")
        assert(a.cookie == true)
        local k1 = fp.build({
            ordered = true, order = a.order, method = "GET", http = "11",
            ua = a.ua, lang = a.lang, cookie = a.cookie,
        })
        local k2 = fp.build({
            ordered = true, order = b.order, method = "GET", http = "11",
            ua = b.ua, lang = b.lang, cookie = b.cookie,
        })
        assert(k1 == k2)
        assert(k1:sub(1, 1) == "1")
        assert(fp.crc32("hello") == 907060870)
    end)

    it("omits order for http/2 and still records which headers exist", function()
        local headers = {
            accept = "text/html",
            ["user-agent"] = "Demo/1",
            cookie = "nope",
        }
        local key = fp.build({
            ordered = false,
            presence = fp.presence(headers),
            method = "POST",
            http = "20",
            ua = "Demo/1",
            lang = "en-US,en",
            cookie = true,
        })
        assert(key:sub(1, 1) == "2")
        assert(key:find("acu", 1, true))
        local other = fp.build({
            ordered = false,
            presence = fp.presence(headers),
            method = "POST",
            http = "20",
            ua = "Demo/1",
            lang = "en-US,en",
            cookie = false,
        })
        assert(key ~= other)
    end)

    it("stops reading after the cap", function()
        local lines = {}
        for i = 1, 40 do
            lines[i] = "x-h" .. i .. ": z"
        end
        lines[#lines + 1] = "accept: text/html"
        local parsed = fp.parse_raw(table.concat(lines, "\n"), 32)
        assert(parsed.order == "")
    end)
end)
