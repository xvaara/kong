local cache = require "kong.tools.database_cache"
local stringy = require "stringy"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"

local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"

local _M = {}


local function retrieve_hmac_fields(request, header_name, conf)
  local hmacId, hmakKey, signature, algorithm
  local authorization_header = request.get_headers()[header_name]

  if authorization_header then
    -- Authentication: hmac hmacKeyID:base64(hmac-sha1(VERB + "\n"  Content-md5 + "\n" + Content-Type + "\n" + Date))
    local iterator, iter_err = ngx.re.gmatch(authorization_header, "\\s*[Hh]mac\\s*(.+)")
    if not iterator then
      ngx.log(ngx.ERR, iter_err)
      return
    end

    local m, err = iterator()
    if err then
      ngx.log(ngx.ERR, err)
      return 
    end
    
    if m and table.getn(m) > 0 then
      local decoded_hmac_fields = ngx.decode_base64(m[1])
      if decoded_hmac_fields then
        local hmac_parts = stringy.split(decoded_basic, ":")
        hmacId = hmac_parts[1]
        signature = hmac_parts[2]
        algorithm = hmac_parts[3]
      end
    end
  end  
    
  if conf.hide_credentials then
    request.clear_header(header_name)
  end
  
  return hmacId, signature, algorithm
end


local function validate_signature(request, hmacKey, signature, algorithm, defaultClockSkew)
  -- create new digest using the key and validate against the signature
  -- hmac-sha1( VERB + "\n" + Content-md5 + "\n" + Content-Type + "\n" + Date, key)
  -- ignore algorithm, only supporting hmac-sha1
  
  local date = request.get_headers()["date"]
  
  -- validate clock skew
  local requestTime = ngx.parse_http_time(date);  
  if time == nil then
    responses.send_HTTP_UNAUTHORIZED("Date header missing, HMAC signature cannot be verified")  
  end
  
  local now = ngx.time;
  local skew = math.abs(now - requestTime)
  if skew > defaultClockSkew then
    responses.send_HTTP_UNAUTHORIZED("HMAC signature expired")
  end   
  
  -- validate signature
  local src = request.get_method() + "\n" + request.get_headers()["content-md5"] + "\n" + request.get_headers()["content-type"] + "\n" + date 
  local digest = ngx.hmac_sha1(hmacKey, src)
  if not digest == signature then
    return responses.send_HTTP_UNAUTHORIZED()
  end 
end

local function load_hmacKey(keyId)
  local hmacKey
  if keyId then
    hmacKey = cache.get_or_set(cache.hmacauth_key(keyId), function()
      local key, err = dao.hmacauth_credentials:find_by_keys { key_id = keyId }
      local result
      if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      elseif #hmacKey > 0 then
        result = hmacKey[1]
      end
      return result
    end)
  end
  return hmacKey
end

function _M.execute(conf)
  -- If both headers are missing, return 401
  if not (ngx.req.get_headers()[AUTHORIZATION] or ngx.req.get_headers()[PROXY_AUTHORIZATION]) then
    ngx.ctx.stop_phases = true
    return responses.send_HTTP_UNAUTHORIZED()
  end
  
  local  hmacId, signature, algorithm = retrieve_hmac_fields(ngx.req, PROXY_AUTHORIZATION, conf)
  
  -- Try with the authorization header
  if not hmacId then
    hmacId, signature, algorithm = retrieve_hmac_fields(ngx.req, AUTHORIZATION, conf)
  end
  
  local hmackey = load_hmacKey(hmacId)

  if not validate_signature(ngx.req, hmacKey, signature, algorithm, cong.clock_skew) then
    ngx.ctx.stop_phases = true -- interrupt other phases of this request
    return responses.send_HTTP_FORBIDDEN("HMAC signature does not match")
  end

end

return _M
