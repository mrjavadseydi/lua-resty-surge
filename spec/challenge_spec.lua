local challenge = require "resty.surge.challenge"
local sha = require "resty.surge.sha256"

local function v4(a, b, c, d)
    return string.char(a, b, c, d)
end

describe("sha256", function()
    it("matches the empty, abc, and hmac vectors", function()
        assert(sha.hex(sha.pure("")) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert(sha.hex(sha.pure("abc")) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        assert(sha.hex(sha.pure_hmac("key",
            "The quick brown fox jumps over the lazy dog")) ==
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        assert(sha.equal("ab", "ab"))
        assert(not sha.equal("ab", "ac"))
        assert(not sha.equal("ab", "abc"))
    end)
end)

describe("proof of work cookie", function()
    it("binds the cookie to a /24 and the secret version", function()
        local bin = v4(10, 1, 2, 9)
        local neighbor = v4(10, 1, 2, 8)
        local other = v4(10, 1, 3, 9)
        assert(challenge.prefix_hash(bin) == challenge.prefix_hash(neighbor))
        assert(challenge.prefix_hash(bin) ~= challenge.prefix_hash(other))

        local token = challenge.token(bin, 1000, 60, 8)
        local nonce
        for i = 0, 8000 do
            local n = tostring(i)
            if challenge.proof_ok(token, n, 8, 1000, bin, 60) then
                nonce = n
                break
            end
        end
        assert(nonce, "no nonce")
        assert(not challenge.proof_ok(token, nonce, 8, 1000, other, 60))
        assert(not challenge.proof_ok(token, nonce, 8, 1066, bin, 60))
        assert(challenge.proof_ok(token, nonce, 8, 1000, neighbor, 60))

        local value = challenge.issue(bin, 1000, 60, 8, 3, "secret")
        local header = "other=1; srg_pow=" .. value
        assert(challenge.valid(header, bin, 1010, "secret", nil, 3, 0))
        assert(challenge.valid(header, neighbor, 1010, "nope", "secret", 4, 3))
        assert(not challenge.valid(header, other, 1010, "secret", nil, 3, 0))
        assert(not challenge.valid(header, bin, 2000, "secret", nil, 3, 0))
        local flipped = value:sub(1, -2) .. (value:sub(-1) == "0" and "1" or "0")
        assert(not challenge.valid("srg_pow=" .. flipped, bin, 1010, "secret", nil, 3, 0))
    end)

    it("puts the token and the original request in the page", function()
        assert(challenge.safe_target("/search?q=a%20b") == "/search?q=a%20b")
        assert(challenge.safe_target("//evil.example/x") == "/")
        assert(challenge.safe_target("https://evil.example") == "/")
        local html = challenge.page("v1.10.aabbccdd.8", 8, "/search?q=a%20b", "POST")
        assert(html:find("v1.10.aabbccdd.8", 1, true))
        assert(html:find("/search?q=a%20b", 1, true))
        assert(html:find("POST", 1, true))
        assert(html:find("location.reload", 1, true))
        assert(not challenge.page('v1."bad', 8))
    end)
end)
