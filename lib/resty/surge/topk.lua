-- Space-Saving heavy hitters.
--
-- A key already in the table is incremented in place. A new key is admitted
-- only when `gate(key)` is true. The caller updates the Count-Min Sketch
-- first and the gate checks estimate >= admit_share * window_total, so a
-- cloud of one-off botnet keys never enters and the O(K) replacement stays rare.
--
-- On replacement the new entry gets count = min + weight and error = min.
-- The stored count is an upper bound: true frequency is in
-- [count - error, count], as long as every occurrence of the key was offered
-- to this table (the gate delays admission, so a gated count can sit below
-- the true frequency; the ungated bound is the one the tests lock).
--
-- The minimum slot is remembered. It is recomputed only when a key that
-- currently holds that minimum is incremented off it or replaced.

local byte = string.byte
local sub = string.sub

local ok_clear, table_clear = pcall(require, "table.clear")
if not ok_clear then
    function table_clear(t)
        for k in pairs(t) do
            t[k] = nil
        end
    end
end

local _M = {}

local function rescan(tk)
    local used = tk.used
    local slots = tk.slots
    if used == 0 then
        tk.min_i, tk.min_c, tk.min_ties = 1, 0, 0
        return
    end
    local min_i = 1
    local min_c = slots[1].count
    local ties = 1
    for i = 2, used do
        local c = slots[i].count
        if c < min_c then
            min_c = c
            min_i = i
            ties = 1
        elseif c == min_c then
            ties = ties + 1
        end
    end
    tk.min_i = min_i
    tk.min_c = min_c
    tk.min_ties = ties
end

local function retarget(tk)
    local mc = tk.min_c
    local slots = tk.slots
    for i = 1, tk.used do
        if slots[i].count == mc then
            tk.min_i = i
            return
        end
    end
    rescan(tk)
end

function _M.new(k, gate)
    if not k or k < 1 then
        error("topk: k must be >= 1")
    end
    local slots = {}
    for i = 1, k do
        slots[i] = { key = nil, count = 0, error = 0 }
    end
    return {
        k = k,
        slots = slots,
        index = {},
        used = 0,
        min_i = 1,
        min_c = 0,
        min_ties = 0,
        gate = gate,
        replacements = 0,
        -- hash -> slot, for prefix keys that must not be allocated to be found
        hashes = {},
    }
end

local function same_prefix(key, full, n)
    if #key ~= n then
        return false
    end
    for i = 1, n do
        if byte(key, i) ~= byte(full, i) then
            return false
        end
    end
    return true
end

-- Prefix observe. `hash` is hash_pair(full, nbytes). The prefix string is
-- created only when a new key is admitted; a hit compares bytes in place.
-- `allow_new` is the sketch gate, already decided by the caller, so this
-- table is constructed without its own gate.
function _M.add_prefix(tk, full, nbytes, hash, weight, allow_new)
    weight = weight or 1
    if weight <= 0 then
        return false
    end

    local hashes = tk.hashes
    local idx = hashes[hash]
    if idx then
        local e = tk.slots[idx]
        if e and same_prefix(e.key, full, nbytes) then
            return _M.add(tk, e.key, weight)
        end
    end

    local slots = tk.slots
    for i = 1, tk.used do
        local e = slots[i]
        if same_prefix(e.key, full, nbytes) then
            hashes[hash] = i
            return _M.add(tk, e.key, weight)
        end
    end

    if not allow_new then
        return false
    end

    local key = sub(full, 1, nbytes)
    local ok = _M.add(tk, key, weight, true)
    if ok then
        local slot = tk.index[key]
        if slot then
            hashes[hash] = slot
        end
    end
    return ok
end

-- `admit`, when given, is the caller's gate decision and replaces tk.gate.
function _M.add(tk, key, weight, admit)
    weight = weight or 1
    if weight <= 0 then
        return false
    end

    local index = tk.index
    local idx = index[key]
    if idx then
        local e = tk.slots[idx]
        local before = e.count
        e.count = before + weight
        if before == tk.min_c then
            tk.min_ties = tk.min_ties - 1
            if tk.min_ties <= 0 then
                rescan(tk)
            elseif idx == tk.min_i then
                retarget(tk)
            end
        end
        return true
    end

    if admit == nil then
        admit = not tk.gate or tk.gate(key)
    end
    if not admit then
        return false
    end

    local slots = tk.slots
    if tk.used < tk.k then
        tk.used = tk.used + 1
        local slot = tk.used
        local e = slots[slot]
        e.key = key
        e.count = weight
        e.error = 0
        index[key] = slot
        if tk.used == 1 or weight < tk.min_c then
            tk.min_i = slot
            tk.min_c = weight
            tk.min_ties = 1
        elseif weight == tk.min_c then
            tk.min_ties = tk.min_ties + 1
        end
        return true
    end

    local mi = tk.min_i
    local e = slots[mi]
    local min = e.count
    index[e.key] = nil
    e.key = key
    e.count = min + weight
    e.error = min
    index[key] = mi
    tk.replacements = tk.replacements + 1
    rescan(tk)
    return true
end

function _M.get(tk, key)
    local idx = tk.index[key]
    if not idx then
        return nil
    end
    local e = tk.slots[idx]
    return e.count, e.error
end

function _M.reset(tk)
    local slots = tk.slots
    for i = 1, tk.used do
        local e = slots[i]
        e.key = nil
        e.count = 0
        e.error = 0
    end
    table_clear(tk.index)
    table_clear(tk.hashes)
    tk.used = 0
    tk.min_i = 1
    tk.min_c = 0
    tk.min_ties = 0
end

return _M
