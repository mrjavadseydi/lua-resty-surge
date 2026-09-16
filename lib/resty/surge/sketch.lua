-- Count-Min Sketch with conservative update.
--
-- width=2048, depth=4 → ε ≈ e/width ≈ 0.001327, δ ≈ e^-depth ≈ 0.0183.
-- Depth is unrolled: a variable-depth loop is what blows the LuaJIT trace,
-- and every preset uses 4. Width is a power of two so the bucket is a mask,
-- not a division.
--
-- Two 32-bit CRCs walk the key bytes with string.byte. ffi.cast of a Lua
-- string allocates a cdata pointer per call, which the normal-mode budget
-- does not allow. h2 is an independent message (each byte xored with 0x5a)
-- and is forced odd so the Kirsch–Mitzenmacher step is coprime with the width.
-- ngx.crc32_short is faster for a single hash, but a second independent
-- digest would need another string or a second C call. One pass here wins
-- on short keys; bench/microbench.lua is the comparison.

local ffi = require "ffi"
local bit = require "bit"

local band, bxor, rshift, bor = bit.band, bit.bxor, bit.rshift, bit.bor
local byte = string.byte
local exp = math.exp

local U32_MAX = 4294967295

local crc_table = {}
for i = 0, 255 do
    local c = i
    for _ = 1, 8 do
        if band(c, 1) == 1 then
            c = bxor(rshift(c, 1), 0xEDB88320)
        else
            c = rshift(c, 1)
        end
    end
    crc_table[i + 1] = c
end

local function u32(x)
    if x < 0 then
        return x + 4294967296
    end
    return x
end

-- nbytes hashes a prefix of s (a /24 is the first 3 bytes) without
-- allocating the prefix string.
local function hash_pair(s, nbytes)
    local h1, h2 = 0xffffffff, 0xffffffff
    local n = #s
    if nbytes and nbytes < n then
        n = nbytes
    end
    for i = 1, n do
        local b = byte(s, i)
        local i1 = band(bxor(h1, b), 0xff) + 1
        h1 = bxor(rshift(h1, 8), crc_table[i1])
        local i2 = band(bxor(h2, bxor(b, 0x5a)), 0xff) + 1
        h2 = bxor(rshift(h2, 8), crc_table[i2])
    end
    h1 = u32(bxor(h1, 0xffffffff))
    h2 = u32(bor(bxor(h2, 0xffffffff), 1))
    return h1, h2
end

local _M = {}

_M.DEFAULT_WIDTH = 2048
_M.DEFAULT_DEPTH = 4
_M.hash_pair = hash_pair

function _M.epsilon(width)
    return exp(1) / (width or _M.DEFAULT_WIDTH)
end

function _M.delta(depth)
    return exp(-(depth or _M.DEFAULT_DEPTH))
end

local function new_counters(n)
    return ffi.new("uint32_t[?]", n)
end

function _M.new(width, depth)
    width = width or _M.DEFAULT_WIDTH
    depth = depth or _M.DEFAULT_DEPTH
    if depth ~= 4 then
        error("sketch: depth is fixed at 4")
    end
    if width < 4 or band(width, width - 1) ~= 0 then
        error("sketch: width must be a power of two >= 4")
    end

    local n = width * depth
    return {
        width = width,
        mask = width - 1,
        w1 = width,
        w2 = width * 2,
        w3 = width * 3,
        nbytes = n * 4,
        cur = new_counters(n),
        prev = new_counters(n),
        total = 0,
        prev_total = 0,
    }
end

local function buckets(sk, h1, h2)
    local mask = sk.mask
    return band(h1, mask),
           sk.w1 + band(h1 + h2, mask),
           sk.w2 + band(h1 + h2 * 2, mask),
           sk.w3 + band(h1 + h2 * 3, mask)
end

local function min4(data, i0, i1, i2, i3)
    local m = data[i0]
    local v = data[i1]
    if v < m then m = v end
    v = data[i2]
    if v < m then m = v end
    v = data[i3]
    if v < m then m = v end
    return m
end

-- Raise every row that is below the new minimum. Rows already above it
-- stay put: that is the conservative update, and it is what keeps a
-- colliding key from inflating this one. Saturating at 2^32-1; a wrapped
-- counter would look like a tiny count and break the "no underestimate" bound.
local function raise(data, idx, limit)
    if data[idx] < limit then
        data[idx] = limit
    end
end

function _M.add(sk, key, weight, nbytes)
    weight = weight or 1
    if weight <= 0 then
        return
    end

    local h1, h2 = hash_pair(key, nbytes)
    local i0, i1, i2, i3 = buckets(sk, h1, h2)
    local data = sk.cur
    local est = min4(data, i0, i1, i2, i3)
    local limit = est + weight
    if limit > U32_MAX then
        limit = U32_MAX
    end
    raise(data, i0, limit)
    raise(data, i1, limit)
    raise(data, i2, limit)
    raise(data, i3, limit)
    sk.total = sk.total + weight
end

function _M.query(sk, key, nbytes)
    local h1, h2 = hash_pair(key, nbytes)
    local i0, i1, i2, i3 = buckets(sk, h1, h2)
    return min4(sk.cur, i0, i1, i2, i3)
end

function _M.total(sk)
    return sk.total
end

-- Current window becomes the previous one. The buffer that was previous
-- is wiped and reused, so a rotate does not allocate.
function _M.rotate(sk)
    sk.cur, sk.prev = sk.prev, sk.cur
    ffi.fill(sk.cur, sk.nbytes, 0)
    sk.prev_total = sk.total
    sk.total = 0
end

return _M
