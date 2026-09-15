-- Loop the phase-2 hot functions so `luajit -jv bench/jit_hot.lua` shows
-- whether the traces compile. Trace output goes to stderr.

package.path = (arg[0] or ""):match("^(.*)/bench/jit_hot%.lua$")
    and ((arg[0]:match("^(.*)/bench/jit_hot%.lua$")) .. "/lib/?.lua;" .. package.path)
    or ("lib/?.lua;" .. package.path)

local sketch = require "resty.surge.sketch"
local topk = require "resty.surge.topk"
local gcra = require "resty.surge.gcra"

local sk = sketch.new()
local tk = topk.new(128)
local key = "\1\2\3\4"
local interval, tau = gcra.params(100, 4)
local tat = 0

for _ = 1, 200000 do
    sketch.add(sk, key, 1)
    topk.add(tk, key, 1)
    local ok, next_tat = gcra.check(tat, tat, interval, tau)
    if ok then
        tat = next_tat
    end
end

io.write("jit hot loop done\n")
