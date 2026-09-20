-- SHA-256 and HMAC-SHA256.
--
-- lua-resty-openssl is used when it loads. The pure implementation is the
-- fallback for OpenResty builds that do not ship it, and it is what the
-- unit tests check against known digests.

local bit = require "bit"
local band, bxor, bor, rshift, lshift =
    bit.band, bit.bxor, bit.bor, bit.rshift, bit.lshift
local char = string.char
local byte = string.byte
local format = string.format
local rep = string.rep

local _M = {}

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function add(a, b)
    return band(a + b, 0xffffffff)
end

local function rotr(x, n)
    return bor(rshift(x, n), lshift(x, 32 - n))
end

local function u32be(n)
    return char(
        band(rshift(n, 24), 0xff),
        band(rshift(n, 16), 0xff),
        band(rshift(n, 8), 0xff),
        band(n, 0xff)
    )
end

local function load32(s, i)
    local a, b, c, d = byte(s, i, i + 3)
    return bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
end

local function pure_sha256(msg)
    local len = #msg
    local bits = len * 8
    msg = msg .. "\128" .. rep("\0", (56 - (len + 1) % 64) % 64)
    local hi = math.floor(bits / 4294967296)
    msg = msg .. u32be(hi) .. u32be(bits % 4294967296)

    local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    local w = {}

    for off = 1, #msg, 64 do
        for i = 1, 16 do
            w[i] = load32(msg, off + (i - 1) * 4)
        end
        for i = 17, 64 do
            local x = w[i - 15]
            local y = w[i - 2]
            local s0 = bxor(rotr(x, 7), rotr(x, 18), rshift(x, 3))
            local s1 = bxor(rotr(y, 17), rotr(y, 19), rshift(y, 10))
            w[i] = add(add(w[i - 16], s0), add(w[i - 7], s1))
        end
        local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for i = 1, 64 do
            local S1 = bxor(rotr(e, 6), rotr(e, 11), rotr(e, 25))
            local ch = bxor(band(e, f), band(bxor(e, 0xffffffff), g))
            local t1 = add(add(add(h, S1), add(ch, K[i])), w[i])
            local S0 = bxor(rotr(a, 2), rotr(a, 13), rotr(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local t2 = add(S0, maj)
            h = g
            g = f
            f = e
            e = add(d, t1)
            d = c
            c = b
            b = a
            a = add(t1, t2)
        end
        h0, h1, h2, h3 = add(h0, a), add(h1, b), add(h2, c), add(h3, d)
        h4, h5, h6, h7 = add(h4, e), add(h5, f), add(h6, g), add(h7, h)
    end
    return u32be(h0) .. u32be(h1) .. u32be(h2) .. u32be(h3)
        .. u32be(h4) .. u32be(h5) .. u32be(h6) .. u32be(h7)
end

local function pure_hmac(key, msg)
    if #key > 64 then
        key = pure_sha256(key)
    end
    if #key < 64 then
        key = key .. rep("\0", 64 - #key)
    end
    local ip, op = {}, {}
    for i = 1, 64 do
        local b = byte(key, i)
        ip[i] = char(bxor(b, 0x36))
        op[i] = char(bxor(b, 0x5c))
    end
    return pure_sha256(table.concat(op) .. pure_sha256(table.concat(ip) .. msg))
end

local openssl_digest, openssl_hmac
local ok_d, digest_mod = pcall(require, "resty.openssl.digest")
if ok_d then
    openssl_digest = digest_mod
end
local ok_h, hmac_mod = pcall(require, "resty.openssl.hmac")
if ok_h then
    openssl_hmac = hmac_mod
end

function _M.pure(msg)
    return pure_sha256(msg)
end

function _M.pure_hmac(key, msg)
    return pure_hmac(key, msg)
end

function _M.sha256(msg)
    if openssl_digest then
        local d = openssl_digest.new("sha256")
        if d then
            d:update(msg)
            return d:final()
        end
    end
    return pure_sha256(msg)
end

function _M.hmac(key, msg)
    if openssl_hmac then
        local h = openssl_hmac.new(key, "sha256")
        if h then
            h:update(msg)
            return h:final()
        end
    end
    return pure_hmac(key, msg)
end

function _M.hex(bin)
    local parts = {}
    for i = 1, #bin do
        parts[i] = format("%02x", byte(bin, i))
    end
    return table.concat(parts)
end

-- Leading zero bits of a raw digest. Used by the proof-of-work check.
function _M.leading_zeros(bin)
    local n = 0
    for i = 1, #bin do
        local b = byte(bin, i)
        if b == 0 then
            n = n + 8
        else
            local mask = 128
            while mask > 0 and band(b, mask) == 0 do
                n = n + 1
                mask = rshift(mask, 1)
            end
            return n
        end
    end
    return n
end

-- Byte-wise compare. Length is not secret; the MAC bytes are.
function _M.equal(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = bor(diff, bxor(byte(a, i), byte(b, i)))
    end
    return diff == 0
end

return _M
