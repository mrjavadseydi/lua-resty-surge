#!/usr/bin/env luajit

-- Compare the bundled binary trie with lua-resty-ipmatcher when that
-- module is installed. The request path uses the trie: ipmatcher matches
-- a textual address, and protect() already holds the binary one.

package.path = (arg[0] or ""):match("^(.*)/bench/radix%.lua$")
    and ((arg[0]:match("^(.*)/bench/radix%.lua$")) .. "/lib/?.lua;" .. package.path)
    or ("lib/?.lua;" .. package.path)

local ipdb = require "resty.surge.ipdb"
local char = string.char

local N = 4000
local LOOKUPS = 200000
local cidrs, groups_cidrs = {}, {}
for i = 1, N do
    local a = i % 223 + 1
    local b = math.floor(i / 223) % 256
    cidrs[i] = string.format("%d.%d.0.0/16", a, b)
    groups_cidrs[i] = cidrs[i]
end

local db = ipdb.compile({ { name = "bench", cidrs = groups_cidrs } }, "short")
local keys = {}
for i = 1, 1024 do
    local a = i % 223 + 1
    local b = math.floor(i / 223) % 256
    keys[i] = char(a, b, i % 250, 7)
end

local function bench(name, fn)
    fn()
    local t0 = os.clock()
    fn()
    local ns = (os.clock() - t0) / LOOKUPS * 1e9
    return string.format("%-28s %8.1f ns/lookup", name, ns)
end

local lines = {}
local function report(s)
    lines[#lines + 1] = s
    io.write(s, "\n")
end

report("lua-resty-surge phase 5 radix bench")
report("networks " .. N .. "  lookups " .. LOOKUPS)
if ngx then
    report("runtime: openresty")
else
    report("runtime: plain luajit")
end

report(bench("binary trie", function()
    local hit = 0
    for i = 1, LOOKUPS do
        if ipdb.hit(db.block4, keys[(i % 1024) + 1]) then
            hit = hit + 1
        end
    end
    if hit == 0 then
        error("trie matched nothing")
    end
end))

local ok_matcher, ipmatcher = pcall(require, "resty.ipmatcher")
if ok_matcher then
    local matcher = ipmatcher.new(cidrs)
    local texts = {}
    for i = 1, 1024 do
        local raw = keys[i]
        texts[i] = string.format("%d.%d.%d.%d", raw:byte(1, 4))
    end
    report(bench("lua-resty-ipmatcher", function()
        local hit = 0
        for i = 1, LOOKUPS do
            if matcher:match(texts[(i % 1024) + 1]) then
                hit = hit + 1
            end
        end
        if hit == 0 then
            error("ipmatcher matched nothing")
        end
    end))
else
    report("lua-resty-ipmatcher not installed")
end

local root = (arg[0] or ""):match("^(.*)/bench/radix%.lua$") or "."
local f = io.open(root .. "/bench/results/phase5.txt", "w")
if f then
    f:write(table.concat(lines, "\n"), "\n")
    f:close()
    io.write("wrote ", root, "/bench/results/phase5.txt\n")
end
