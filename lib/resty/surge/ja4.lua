-- JA4 (FoxIO) for a TLS ClientHello.
--
-- Computed only in ssl_client_hello, and only when ngx.ssl.clienthello is
-- present (OpenResty 1.29.2.1+). The value is stored on ngx.ctx; the HTTP
-- phase reads it. This build's harness confirmed that hand-off. QUIC is not
-- seen on this HTTP hook, so the protocol character is "t". If the supported
-- versions extension is missing, the version field is "00": the legacy
-- record version is not exposed by the getters.

local sha = require "resty.surge.sha256"

local _M = {}

local GREASE = {
    [0x0a0a] = true, [0x1a1a] = true, [0x2a2a] = true, [0x3a3a] = true,
    [0x4a4a] = true, [0x5a5a] = true, [0x6a6a] = true, [0x7a7a] = true,
    [0x8a8a] = true, [0x9a9a] = true, [0xaaaa] = true, [0xbaba] = true,
    [0xcaca] = true, [0xdada] = true, [0xeaea] = true, [0xfafa] = true,
}

local VER = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"] = "10",
    ["SSLv3"] = "s3",
    ["SSLv2"] = "s2",
}
local RANK = { ["13"] = 6, ["12"] = 5, ["11"] = 4, ["10"] = 3, ["s3"] = 2, ["s2"] = 1 }

local function hex4(n)
    return string.format("%04x", n)
end

local function count2(n)
    if n > 99 then
        n = 99
    end
    return string.format("%02d", n)
end

local function alnum(b)
    return (b >= 48 and b <= 57)
        or (b >= 65 and b <= 90)
        or (b >= 97 and b <= 122)
end

local function alpn_chars(alpn)
    if type(alpn) ~= "string" or alpn == "" then
        return "00"
    end
    local first = alpn:byte(1)
    local last = alpn:byte(#alpn)
    if alnum(first) and alnum(last) then
        local a = string.char(first)
        local b = string.char(last)
        return a .. b
    end
    local hf = string.format("%02x", first)
    local hl = string.format("%02x", last)
    return hf:sub(1, 1) .. hl:sub(2, 2)
end

local function best_version(list)
    local best, code = 0, "00"
    for i = 1, #(list or {}) do
        local c = VER[list[i]]
        local rank = c and RANK[c] or 0
        if rank > best then
            best = rank
            code = c
        end
    end
    return code
end

-- Extension bodies include the length prefix OpenSSL returns.
local function parse_alpn(data)
    if type(data) ~= "string" or #data < 3 then
        return ""
    end
    local i = 3
    local n = data:byte(i)
    if not n or i + n > #data then
        return ""
    end
    return data:sub(i + 1, i + n)
end

local function parse_sigalgs(data)
    local out = {}
    if type(data) ~= "string" or #data < 4 then
        return out
    end
    local n = data:byte(1) * 256 + data:byte(2)
    local last = math.min(#data, 2 + n)
    local i = 3
    while i + 1 <= last do
        local id = data:byte(i) * 256 + data:byte(i + 1)
        if not GREASE[id] then
            out[#out + 1] = id
        end
        i = i + 2
    end
    return out
end

function _M.fingerprint(parts)
    parts = parts or {}
    local ciphers = {}
    local raw_c = parts.ciphers or {}
    for i = 1, #raw_c do
        local c = raw_c[i]
        if not GREASE[c] then
            ciphers[#ciphers + 1] = hex4(c)
        end
    end
    table.sort(ciphers)

    local exts = {}
    local ext_count = 0
    local sni = parts.sni and true or false
    local raw_e = parts.extensions or {}
    for i = 1, #raw_e do
        local e = raw_e[i]
        if not GREASE[e] then
            ext_count = ext_count + 1
            if e == 0 then
                sni = true
            end
            if e ~= 0 and e ~= 0x0010 then
                exts[#exts + 1] = hex4(e)
            end
        end
    end
    table.sort(exts)

    local sigs = {}
    local raw_s = parts.sigalgs or {}
    for i = 1, #raw_s do
        local s = raw_s[i]
        if not GREASE[s] then
            sigs[#sigs + 1] = hex4(s)
        end
    end

    local b = "000000000000"
    if #ciphers > 0 then
        b = sha.hex(sha.sha256(table.concat(ciphers, ","))):sub(1, 12)
    end
    local c = "000000000000"
    if #exts > 0 then
        local body = table.concat(exts, ",")
        if #sigs > 0 then
            body = body .. "_" .. table.concat(sigs, ",")
        end
        c = sha.hex(sha.sha256(body)):sub(1, 12)
    end

    local ver = parts.version or "00"
    local a = "t" .. ver .. (sni and "d" or "i")
        .. count2(#ciphers) .. count2(ext_count) .. alpn_chars(parts.alpn)
    return a .. "_" .. b .. "_" .. c
end

function _M.available()
    local ok, ch = pcall(require, "ngx.ssl.clienthello")
    return ok and type(ch) == "table" and type(ch.get_client_hello_ciphers) == "function"
end

function _M.capture()
    local ch = require "ngx.ssl.clienthello"
    local ciphers = ch.get_client_hello_ciphers() or {}
    local exts = ch.get_client_hello_ext_present() or {}
    local sni = ch.get_client_hello_server_name()
    local vers = ch.get_supported_versions()
    local alpn = parse_alpn(ch.get_client_hello_ext(16))
    local sigs = parse_sigalgs(ch.get_client_hello_ext(13))
    return _M.fingerprint({
        ciphers = ciphers,
        extensions = exts,
        sigalgs = sigs,
        alpn = alpn,
        sni = type(sni) == "string" and sni ~= "",
        version = best_version(vers),
    })
end

return _M
