local spec_helper = require "spec.spec_helpers"
local http_client = require "kong.tools.http_client"
local cjson = require "cjson"

local PROXY_URL = spec_helper.PROXY_URL

describe("Authentication Plugin", function()

  setup(function()
    spec_helper.prepare_db()
    spec_helper.insert_fixtures {
      api = {
        {name = "tests hmac auth", inbound_dns = "hmacauth.com", upstream_url = "http://httpbin.org"}
      },
      consumer = {
        {username = "hmacauth_tests_consuser"}
      },
      plugin = {
        {name = "hmac-auth", config = {}, __api = 1}
      },
      hmacauth_credential = {
        {hmac_id = "123456", hmac_key = "1sskdfl;jdslkfjds", __consumer = 1}
      }
    }

    spec_helper.start_kong()
  end)

  teardown(function()
    spec_helper.stop_kong()
  end)

  describe("HMAC Authentication", function()

    it("should return invalid credentials when the credential is missing", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "basicauth.com"})
      local body = cjson.decode(response)
      assert.equal(401, status)
      assert.equal("Unauthorized", body.message)
    end)

    it("should return invalid credentials when the credential value is wrong", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "basicauth.com", authorization = "asd"})
      local body = cjson.decode(response)
      assert.equal(403, status)
      assert.equal("Invalid authentication credentials", body.message)
    end)


    it("should return invalid credentials when the credential value is wrong in proxy-authorization", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "basicauth.com", ["proxy-authorization"] = "asd"})
      local body = cjson.decode(response)
      assert.equal(403, status)
      assert.equal("Invalid authentication credentials", body.message)
    end)

   
  end)
end)
