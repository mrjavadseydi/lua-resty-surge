-- Per-worker flush and the leader's merge.
-- Runs from a timer, never from a request. The hot path does not touch
-- the shared dict; this is the only place that does, once per tick.
--
-- Worker 0 takes a shared-dict lease (pid, TTL of a few ticks). During a
-- reload two processes both have id 0; add() keeps a single owner, and the
-- new worker 0 picks the lease up on the tick after the old pid expires.

local bit = require "bit"
local band, rshift = bit.band, bit.rshift
local byte = string.byte
local char = string.char
local sub = string.sub
local decisions = require "resty.surge.decisions"

local _M = {}

local LEASE = "leader"

local function u16(n)
    n = math.floor(n)
    if n < 0 then n = 0 elseif n > 65535 then n = 65535 end
    return char(band(n, 0xff), band(rshift(n, 8), 0xff))
end

local function u32(n)
    if n < 0 then
        n = 0
    elseif n > 4294967295 then
        n = 4294967295
    end
    n = math.floor(n)
    return char(
        band(n, 0xff),
        band(rshift(n, 8), 0xff),
        band(rshift(n, 16), 0xff),
        band(rshift(n, 24), 0xff)
    )
end

local function r16(s, i)
    local a, b = byte(s, i, i + 1)
    if not b then
        return nil, i
    end
    return a + b * 256, i + 2
end

local function r32(s, i)
    local a, b, c, d = byte(s, i, i + 3)
    if not d then
        return nil, i
    end
    return a + b * 256 + c * 65536 + d * 16777216, i + 4
end

function _M.encode_topk(tk, scale)
    scale = scale or 1
    local parts = { u16(scale), u16(tk.used) }
    local slots = tk.slots
    for i = 1, tk.used do
        local e = slots[i]
        local key = e.key or ""
        parts[#parts + 1] = u16(#key)
        parts[#parts + 1] = key
        parts[#parts + 1] = u32(e.count)
        parts[#parts + 1] = u32(e.error)
    end
    return table.concat(parts)
end

function _M.decode_topk(blob)
    if type(blob) ~= "string" or #blob < 4 then
        return nil
    end
    local scale, i = r16(blob, 1)
    local n
    n, i = r16(blob, i)
    if not n then
        return nil
    end
    local items = {}
    for k = 1, n do
        local klen
        klen, i = r16(blob, i)
        if not klen or i + klen - 1 > #blob then
            return nil
        end
        local key = sub(blob, i, i + klen - 1)
        i = i + klen
        local count, errn
        count, i = r32(blob, i)
        errn, i = r32(blob, i)
        if not errn then
            return nil
        end
        items[k] = { key = key, count = count * scale, error = errn * scale }
    end
    return items, scale
end

local function flush_one(dict, key, tk, scale)
    local blob = _M.encode_topk(tk, scale)
    -- safe_set does not evict someone else's decision to make room.
    local ok, err = dict:safe_set(key, blob)
    if not ok then
        return err
    end
    return nil
end

local function pull(state)
    local dict = state.dict
    local ver = dict:get("v:dec") or 0
    if ver == state.box.ver then
        return
    end
    local blob = dict:get("dec")
    if not blob then
        state.box.ver = ver
        return
    end
    local snap, err = decisions.decode(blob)
    if not snap then
        ngx.log(ngx.ERR, "surge: bad decision snapshot: ", err or "")
        state.box.ver = ver
        return
    end
    state.install(snap)
    state.box.ver = ver
end

local function lead(dict, pid, ttl)
    local cur = dict:get(LEASE)
    if cur == pid then
        dict:set(LEASE, pid, ttl)
        return true
    end
    if cur == nil then
        local ok = dict:add(LEASE, pid, ttl)
        if ok then
            return true
        end
        return dict:get(LEASE) == pid
    end
    return false
end

local function merge_dim(dict, nworkers, suffix, into)
    for id = 0, nworkers - 1 do
        local blob = dict:get("w" .. id .. ":" .. suffix)
        if blob then
            local items = _M.decode_topk(blob)
            if items then
                for i = 1, #items do
                    local it = items[i]
                    local prev = into[it.key]
                    if prev then
                        prev.count = prev.count + it.count
                        if it.error > prev.error then
                            prev.error = it.error
                        end
                    else
                        into[it.key] = {
                            key = it.key,
                            count = it.count,
                            error = it.error,
                        }
                    end
                end
            end
        end
    end
end

function _M.tick(state)
    local dict = state.dict
    local scale = state.box.sample or 1
    local dims = state.dims
    for i = 1, #dims do
        local d = dims[i]
        local err = flush_one(dict, d.slot, d.topk, scale)
        if err then
            ngx.log(ngx.ERR, "surge: flush ", d.slot, " failed: ", err)
        end
        d.topk_reset(d.topk)
        if d.sketch then
            d.sketch_rotate(d.sketch)
        end
    end

    pull(state)

    if state.id ~= 0 then
        return
    end
    local ttl = state.tick * 3
    if ttl < 0.05 then
        ttl = 0.05
    end
    if not lead(dict, state.pid, ttl) then
        return
    end

    local merged = {}
    for i = 1, #dims do
        local d = dims[i]
        local acc = {}
        merge_dim(dict, state.nworkers, d.suffix, acc)
        merged[d.suffix] = acc
    end
    state.merged = merged
end

return _M
