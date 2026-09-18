#!/usr/bin/env luajit

-- Tiny runner so the specs do not need busted installed.
-- The same files run under busted: they only call describe/it/assert.
--   luajit spec/run.lua
--   resty spec/run.lua
--   busted spec

local script = arg[0] or "spec/run.lua"
local root = script:match("^(.*)/spec/run%.lua$") or "."

package.path = root .. "/lib/?.lua;" .. root .. "/spec/?.lua;" .. package.path

local passed, failed = 0, 0
local suite = ""

-- rawset skips OpenResty's _G write guard when this file is loaded by resty.
local function describe(name, fn)
    suite = name
    fn()
end

local function it(name, fn)
    local ok, err = xpcall(fn, debug.traceback)
    if ok then
        passed = passed + 1
        io.write("ok   ", suite, " — ", name, "\n")
    else
        failed = failed + 1
        io.write("FAIL ", suite, " — ", name, "\n", err, "\n")
    end
end

rawset(_G, "describe", describe)
rawset(_G, "it", it)

local files = {
    "spec/sketch_spec.lua",
    "spec/topk_spec.lua",
    "spec/baseline_spec.lua",
    "spec/entropy_spec.lua",
    "spec/gcra_spec.lua",
    "spec/clientip_spec.lua",
    "spec/decisions_spec.lua",
    "spec/config_spec.lua",
    "spec/sync_spec.lua",
    "spec/escalation_spec.lua",
    "spec/analyzer_spec.lua",
    "spec/feeds_spec.lua",
}

for i = 1, #files do
    local path = root .. "/" .. files[i]
    local chunk, err = loadfile(path)
    if not chunk then
        failed = failed + 1
        io.write("FAIL load ", path, "\n", err, "\n")
    else
        local ok, run_err = xpcall(chunk, debug.traceback)
        if not ok then
            failed = failed + 1
            io.write("FAIL ", path, "\n", run_err, "\n")
        end
    end
end

io.write(string.format("\n%d passed, %d failed\n", passed, failed))
os.exit(failed == 0 and 0 or 1)
