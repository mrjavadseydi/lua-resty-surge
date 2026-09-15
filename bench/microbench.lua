#!/usr/bin/env luajit

-- Phase 2 micro-benchmark. Numbers in bench/results are whatever this
-- script printed on the machine that ran it.
--   luajit bench/microbench.lua
--   luajit bench/microbench.lua --jit     # trace aborts on stderr

local script = arg[0] or "bench/microbench.lua"
local root = script:match("^(.*)/bench/microbench%.lua$") or "."
package.path = root .. "/lib/?.lua;" .. package.path

if arg[1] == "--jit" then
    require("jit.v").on()
end

local sketch = require "resty.surge.sketch"
local topk = require "resty.surge.topk"
local gcra = require "resty.surge.gcra"

local function bench(name, n, fn)
    fn()
    collectgarbage()
    collectgarbage()
    local before = collectgarbage("count")
    local t0 = os.clock()
    fn()
    local dt = os.clock() - t0
    local after = collectgarbage("count")
    local ns = dt / n * 1e9
    local bytes = (after - before) * 1024 / n
    return string.format("%-28s %10.1f ns/op   %8.3f bytes/op", name, ns, bytes)
end

local lines = {}
local function report(s)
    lines[#lines + 1] = s
    io.write(s, "\n")
end

report("lua-resty-surge phase 2 microbench")
report("luajit " .. (jit and jit.version or "?"))
if ngx then
    report("runtime: openresty (ngx present)")
else
    report("runtime: plain luajit")
end
local uname = io.popen("uname -sm")
if uname then
    report((uname:read("*l")))
    uname:close()
end
local cpu = io.popen("sysctl -n machdep.cpu.brand_string 2>/dev/null")
if cpu then
    local line = cpu:read("*l")
    cpu:close()
    if line then
        report(line)
    end
end
report("")

local key4 = "\10\0\0\1"
local key16 = "\1\2\3\4\5\6\7\8\9\10\11\12\13\14\15\16"

local sk = sketch.new()
report(bench("sketch add 4-byte", 1000000, function()
    for _ = 1, 1000000 do
        sketch.add(sk, key4, 1)
    end
end))

local sk16 = sketch.new()
report(bench("sketch add 16-byte", 1000000, function()
    for _ = 1, 1000000 do
        sketch.add(sk16, key16, 1)
    end
end))

report(bench("sketch query 4-byte", 1000000, function()
    for _ = 1, 1000000 do
        sketch.query(sk, key4)
    end
end))

local tk = topk.new(128)
report(bench("topk hit (key resident)", 1000000, function()
    for _ = 1, 1000000 do
        topk.add(tk, key4, 1)
    end
end))

local interval, tau = gcra.params(100, 4)
local tat = nil
report(bench("gcra check", 1000000, function()
    local t = 0
    for _ = 1, 1000000 do
        local ok, next_tat = gcra.check(tat, t, interval, tau)
        if ok then
            tat = next_tat
        end
        t = t + 0.01
    end
end))

if ngx and ngx.crc32_short then
    report(bench("ngx.crc32_short 4-byte", 1000000, function()
        for _ = 1, 1000000 do
            ngx.crc32_short(key4)
        end
    end))
    report(bench("ngx.crc32_short 16-byte", 1000000, function()
        for _ = 1, 1000000 do
            ngx.crc32_short(key16)
        end
    end))
else
    report("ngx.crc32_short not available in this interpreter; hash is the pure Lua CRC")
end

report("")
report("sketch ε " .. string.format("%.6f", sketch.epsilon())
    .. "  δ " .. string.format("%.6f", sketch.delta()))

local out = root .. "/bench/results/phase2.txt"
local f = io.open(out, "w")
if f then
    f:write(table.concat(lines, "\n"), "\n")
    f:close()
    io.write("wrote ", out, "\n")
end
