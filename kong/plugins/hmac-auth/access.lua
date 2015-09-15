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
    local iterator, iter_err = ngx.re.gmatch(authorization_header, "\\s*[Kk]ong\\s*(.+)")
    if not iterator then
      ngx.log(ngx.ERR, iter_err)
      return
    end

    local m, err = iterator()
    if err then
      ngx.log(ngx.ERR, err)
      return
    end

  end

  if conf.hide_credentials then
    request.clear_header(header_name)
  end

  return username, password
end


local function validate_signature(request, hmakKey, signature, algorithm)
  -- 
  
end

local function load_hmacKey(keyId)
  local credential
  if keyId then
    hmackey = cache.get_or_set(cache.basicauth_credential_key(username), function()
      local credentials, err = dao.basicauth_credentials:find_by_keys { key_id = keyId }
      local result
      if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      elseif #credentials > 0 then
        result = hmackey[1]
      end
      return result
    end)
  end

  return credential
end

function _M.execute(conf)
  -- If both headers are missing, return 401
  if not (ngx.req.get_headers()[AUTHORIZATION] or ngx.req.get_headers()[PROXY_AUTHORIZATION]) then
    ngx.ctx.stop_phases = true
    return responses.send_HTTP_UNAUTHORIZED()
  end

  local  hmacId, signature, algorithm = retrieve_hmac_fields(ngx.req, PROXY_AUTHORIZATION, conf)
  if hmackey then
    hmakKey = load_hmacKey(hmacId)
  end

  -- Try with the authorization header
  if not hmakKey then
    hmacId, signature, algorithm = retrieve_hmac_fields(ngx.req, AUTHORIZATION, conf)
    hmakKey = load_hmacKey(hmacId)
  end

  if not validate_signature(ngx.req, hmakKey, signature, algorithm) then
    ngx.ctx.stop_phases = true -- interrupt other phases of this request
    return responses.send_HTTP_FORBIDDEN("Invalid authentication credentials")
  end

 
end

return _M
