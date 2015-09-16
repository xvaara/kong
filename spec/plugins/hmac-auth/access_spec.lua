local spec_helper = require "spec.spec_helpers"
local http_client = require "kong.tools.http_client"
local cjson = require "cjson"

local PROXY_URL = spec_helper.PROXY_URL

describe("Authentication Plugin", function()

  setup(function()
    spec_helper.prepare_db()
    spec_helper.insert_fixtures {
      api = {
        {name = "tests hmac auth", inbound_dns = "hmacauth.com", upstream_url = "http://mockbin.org"}
      },
      consumer = {
        {username = "hmacauth_tests_consuser"}
      },
      plugin = {
        {name = "hmac-auth", config = {}, __api = 1}
      },
      hmacauth_credential = {
        {username = "bob", secret = "secret", __consumer = 1}
      }
    }

    spec_helper.start_kong()
  end)

  teardown(function()
    spec_helper.stop_kong()
  end)

  describe("HMAC Authentication", function()

    it("should return invalid credentials when the credential is missing", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com"})
      local body = cjson.decode(response)
      assert.equal(401, status)
      assert.equal("Unauthorized", body.message)
    end)

    it("should return invalid credentials when the credential value is wrong", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com", authorization = "asd"})
      local body = cjson.decode(response)
      assert.equal(403, status)
      assert.equal("Invalid authentication credentials", body.message)
    end)


    it("should return invalid credentials when the credential value is wrong in proxy-authorization", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com", date = "Wed, 16 Sep 2015 00:00:00 GMT", ["proxy-authorization"] = "asd"})
      local body = cjson.decode(response)
      assert.equal(403, status)
      assert.equal("Invalid authentication credentials", body.message)
    end)

    it("should not pass when passing only the password", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", authorization = "hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA=="})
      local body = cjson.decode(response)
      assert.equal(403, status)
      assert.equal("Invalid authentication credentials", body.message)
    end)

    it("should not pass when passing only the username", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", authorization = "hmac bob"})
      local body = cjson.decode(response)
      assert.equal(403, status)
      assert.equal("Invalid authentication credentials", body.message)
    end)

    it("should reply 401 when authorization is missing", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", authorization123 = "hmac bob:dXNlcm5hbWU6cGFzc3dvcmQ="})
      local body = cjson.decode(response)
      assert.equal(401, status)
      assert.equal("Unauthorized", body.message)
    end)

    it("should pass with GET", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", authorization = "hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA=="})
      assert.equal(200, status)
      local parsed_response = cjson.decode(response)
      assert.equal("hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA==", parsed_response.headers.Authorization)
    end)

    it("should pass with GET and proxy-authorization", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", ["proxy-authorization"] = "hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA=="})
      assert.equal(200, status)
      local parsed_response = cjson.decode(response)
      assert.equal("hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA==", parsed_response.headers["Proxy-Authorization"])
    end)

    it("should pass with POST", function()
      local response, status = http_client.post(PROXY_URL.."/post", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", authorization = "hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA=="})
      assert.equal(200, status)
      local parsed_response = cjson.decode(response)
      assert.equal("hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA==", parsed_response.headers.Authorization)
    end)

    it("should pass with GET and valid authorization and wrong proxy-authorization", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", ["proxy-authorization"] = "hello", authorization = "hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA=="})
      assert.equal(200, status)
      local parsed_response = cjson.decode(response)
      assert.equal("hello", parsed_response.headers["Proxy-Authorization"])
      assert.equal("hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA==", parsed_response.headers.Authorization)
    end)

    it("should pass with GET and invalid authorization and valid proxy-authorization", function()
      local response, status = http_client.get(PROXY_URL.."/get", {}, {host = "hmacauth.com",  date = "Wed, 16 Sep 2015 00:00:00 GMT", authorization = "hello", ["proxy-authorization"] = "hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA=="})
      assert.equal(200, status)
      local parsed_response = cjson.decode(response)
      assert.equal("hmac bob:YjA0YjEzZDUxMjQ1OGJhNDY5MDUxNWFiNGIzMWJiYzc2YjEyODc3OA==", parsed_response.headers["Proxy-Authorization"])
    end)
  end)
end)
