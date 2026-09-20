local ja4 = require "resty.surge.ja4"

local function ids(list)
    local out = {}
    for hex in list:gmatch("[^,]+") do
        out[#out + 1] = tonumber(hex, 16)
    end
    return out
end

describe("ja4", function()
    it("matches the worked example from the JA4 spec", function()
        local fp = ja4.fingerprint({
            version = "13",
            sni = true,
            alpn = "h2",
            ciphers = ids("1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035"),
            extensions = ids("001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015"),
            sigalgs = ids("0403,0804,0401,0503,0805,0501,0806,0601"),
        })
        assert(fp == "t13d1516h2_8daaf6152771_e5627efa2ab1", fp)
    end)

    it("ignores grease and uses 00 when alpn is absent", function()
        local fp = ja4.fingerprint({
            version = "12",
            sni = false,
            ciphers = { 0x0a0a, 0x0035 },
            extensions = { 0x0000 },
        })
        -- 0x0000 counts as SNI and is omitted from the extension hash.
        assert(fp == "t12d010100_692296a295db_000000000000", fp)
    end)
end)
