-- Proof-of-work challenge and the HMAC cookie that records a pass.
--
-- The page asks the browser for a nonce such that SHA-256(token || nonce)
-- has the configured number of leading zero bits. The cookie is
-- v1.<expiry>.<prefix>.<bits>.<secret_ver>.<hmac>. One HMAC is enough:
-- the version selects the current or the previous secret.
-- The prefix is a /24 or a /64, so a phone that changes address inside
-- the subnet stays verified. Manual blocks and reputation hits do not
-- honor the cookie.

local sha = require "resty.surge.sha256"
local fp = require "resty.surge.fingerprint"

local _M = {}

_M.NAME = "srg_pow"

function _M.prefix_hash(bin)
    if type(bin) ~= "string" then
        return nil
    end
    local n = #bin >= 16 and 8 or 3
    if #bin < n then
        return nil
    end
    return string.format("%08x", fp.crc32(bin:sub(1, n)))
end

function _M.token(bin, now, ttl, bits)
    local pfx = _M.prefix_hash(bin)
    if not pfx then
        return nil
    end
    local exp = math.floor(now + ttl)
    return string.format("v1.%d.%s.%d", exp, pfx, bits)
end

function _M.proof_ok(token, nonce, bits, now, bin, ttl)
    if type(token) ~= "string" or type(nonce) ~= "string" then
        return false
    end
    if #nonce == 0 or #nonce > 16 or not nonce:match("^%d+$") then
        return false
    end
    local exp_s, pfx, token_bits = token:match("^v1%.(%d+)%.(%x+)%.(%d+)$")
    local exp = tonumber(exp_s)
    local tb = tonumber(token_bits)
    if not exp or tb ~= bits then
        return false
    end
    if exp < now or exp > now + ttl + 5 then
        return false
    end
    if pfx ~= _M.prefix_hash(bin) then
        return false
    end
    return sha.leading_zeros(sha.sha256(token .. nonce)) >= bits
end

function _M.issue(bin, now, ttl, bits, ver, secret)
    if type(secret) ~= "string" or secret == "" then
        return nil
    end
    local pfx = _M.prefix_hash(bin)
    if not pfx then
        return nil
    end
    local exp = math.floor(now + ttl)
    local body = string.format("v1.%d.%s.%d.%d", exp, pfx, bits, ver)
    return body .. "." .. sha.hex(sha.hmac(secret, body))
end

local function unhex(s)
    if #s % 2 ~= 0 then
        return nil
    end
    local out = {}
    for i = 1, #s, 2 do
        local n = tonumber(s:sub(i, i + 1), 16)
        if not n then
            return nil
        end
        out[#out + 1] = string.char(n)
    end
    return table.concat(out)
end

function _M.find(header)
    if type(header) ~= "string" then
        return nil
    end
    local name = _M.NAME
    for part in header:gmatch("[^;]+") do
        local k, v = part:match("^%s*([^=%s]+)%s*=%s*(.-)%s*$")
        if k == name and v and v ~= "" then
            return v
        end
    end
    return nil
end

-- cur_ver selects cur. prev_ver selects prev. Any other version is rejected
-- without a second HMAC.
function _M.valid(header, bin, now, cur, prev, cur_ver, prev_ver)
    local value = _M.find(header)
    if not value then
        return false
    end
    local exp_s, pfx, _, ver_s, mac_hex =
        value:match("^v1%.(%d+)%.(%x+)%.(%d+)%.(%d+)%.(%x+)$")
    local exp = tonumber(exp_s)
    local ver = tonumber(ver_s)
    local mac = mac_hex and unhex(mac_hex)
    if not exp or not ver or not mac then
        return false
    end
    if exp < now then
        return false
    end
    if pfx ~= _M.prefix_hash(bin) then
        return false
    end
    local secret
    if ver == cur_ver then
        secret = cur
    elseif ver == prev_ver then
        secret = prev
    end
    if type(secret) ~= "string" or secret == "" then
        return false
    end
    local body = value:match("^(.*)%.%x+$")
    if not body then
        return false
    end
    return sha.equal(sha.hmac(secret, body), mac)
end

function _M.cookie_header(value, ttl, secure)
    local line = _M.NAME .. "=" .. value
        .. "; Path=/; Max-Age=" .. math.floor(ttl)
        .. "; HttpOnly; SameSite=Lax"
    if secure then
        line = line .. "; Secure"
    end
    return line
end

-- Inline SHA-256. No external script, and it matches the Lua digest on
-- ASCII (the token and the decimal nonce).
local PAGE = [[<!doctype html><meta charset=utf-8><title>Checking your browser</title>
<p>Checking your browser.</p>
<script>
(function(){
var ch=%q;
var bits=%d;
var ret=%q;
var method=%q;
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function rr(n,x){return (x>>>n)|(x<<(32-n));}
function add(a,b){return (a+b)>>>0;}
function sha256(msg){
  var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  var bytes=[];
  for(var i=0;i<msg.length;i++) bytes.push(msg.charCodeAt(i)&255);
  var bitLen=bytes.length*8;
  bytes.push(128);
  while((bytes.length%%64)!==56) bytes.push(0);
  var hi=Math.floor(bitLen/4294967296), lo=bitLen>>>0;
  bytes.push((hi>>>24)&255,(hi>>>16)&255,(hi>>>8)&255,hi&255,(lo>>>24)&255,(lo>>>16)&255,(lo>>>8)&255,lo&255);
  var w=new Array(64);
  for(var off=0; off<bytes.length; off+=64){
    for(var i=0;i<16;i++){var j=off+i*4; w[i]=((bytes[j]<<24)|(bytes[j+1]<<16)|(bytes[j+2]<<8)|bytes[j+3])>>>0;}
    for(var i=16;i<64;i++){
      var x=w[i-15], y=w[i-2];
      var s0=(rr(7,x)^rr(18,x)^(x>>>3))>>>0;
      var s1=(rr(17,y)^rr(19,y)^(y>>>10))>>>0;
      w[i]=add(add(w[i-16],s0),add(w[i-7],s1));
    }
    var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for(var i=0;i<64;i++){
      var S1=(rr(6,e)^rr(11,e)^rr(25,e))>>>0;
      var ch=((e&f)^((~e)&g))>>>0;
      var t1=add(add(add(h,S1),add(ch,K[i])),w[i]);
      var S0=(rr(2,a)^rr(13,a)^rr(22,a))>>>0;
      var maj=((a&b)^(a&c)^(b&c))>>>0;
      var t2=add(S0,maj);
      h=g;g=f;f=e;e=add(d,t1);d=c;c=b;b=a;a=add(t1,t2);
    }
    h0=add(h0,a);h1=add(h1,b);h2=add(h2,c);h3=add(h3,d);h4=add(h4,e);h5=add(h5,f);h6=add(h6,g);h7=add(h7,h);
  }
  function hex(n){var s=(n>>>0).toString(16);while(s.length<8)s="0"+s;return s;}
  return hex(h0)+hex(h1)+hex(h2)+hex(h3)+hex(h4)+hex(h5)+hex(h6)+hex(h7);
}
function zeros(hex){
  var n=0;
  for(var i=0;i<hex.length;i++){
    var v=parseInt(hex.charAt(i),16);
    if(v===0) n+=4;
    else { if(v<2)n+=3; else if(v<4)n+=2; else if(v<8)n+=1; break; }
  }
  return n;
}
var i=0;
function step(){
  var n=600;
  while(n--){
    var nonce=String(i++);
    if(zeros(sha256(ch+nonce))>=bits){
      var join=ret.indexOf("?")>=0?"&":"?";
      var proof=ret+join+"srg_pow="+nonce+"&srg_ch="+encodeURIComponent(ch);
      var done=function(){
        if(method==="POST"||method==="PUT"||method==="PATCH") location.reload();
        else location.replace(ret);
      };
      if(window.fetch){
        fetch(proof,{credentials:"same-origin",redirect:"manual"}).then(done,done);
      }else{
        location.replace(proof);
      }
      return;
    }
  }
  setTimeout(step,0);
}
step();
})();
</script>
]]

-- request_uri keeps the raw path and query. A value that is not a
-- same-origin path is replaced so the page cannot be an open redirect.
function _M.safe_target(uri)
    if type(uri) ~= "string" or uri:sub(1, 1) ~= "/" or uri:sub(1, 2) == "//" then
        return "/"
    end
    if uri:find("[\r\n\\]") or uri:find("://", 1, true) then
        return "/"
    end
    return uri
end

function _M.page(token, bits, target, method)
    if type(token) ~= "string" or token:find("[^%w%.]") then
        return nil
    end
    target = _M.safe_target(target)
    if type(method) ~= "string" then
        method = "GET"
    end
    method = method:upper():gsub("[^A-Z]", "")
    if method == "" then
        method = "GET"
    end
    return string.format(PAGE, token, bits, target, method)
end

return _M
