local spec_helper = require "spec.spec_helpers"
local http_client = require "kong.tools.http_client"
local cjson = require "cjson"

local STUB_GET_URL = spec_helper.STUB_GET_URL

local function wait()
  -- Wait til the beginning of a new second before starting the test
  -- to avoid ending up in an edge case when the second is about to end
  local now = os.time()
  while os.time() < now + 1 do
    -- Nothing
  end
end

describe("RateLimiting Plugin", function()

  setup(function()
    spec_helper.prepare_db()
    spec_helper.insert_fixtures {
      api = {
        { name = "tests-rate-limiting1", request_host = "test3.com", upstream_url = "http://mockbin.com" },
        { name = "tests-rate-limiting2", request_host = "test4.com", upstream_url = "http://mockbin.com" },
        { name = "tests-rate-limiting3", request_host = "test5.com", upstream_url = "http://mockbin.com" },
        { name = "tests-rate-limiting4", request_host = "test6.com", upstream_url = "http://mockbin.com" }
      },
      consumer = {
        { custom_id = "provider_123" },
        { custom_id = "provider_124" }
      },
      plugin = {
        { name = "key-auth", config = {key_names = {"apikey"}, hide_credentials = true}, __api = 1 },
        { name = "rate-limiting", config = { minute = 6 }, __api = 1 },
        { name = "rate-limiting", config = { minute = 8 }, __api = 1, __consumer = 1 },
        { name = "rate-limiting", config = { minute = 6 }, __api = 2 },
        { name = "rate-limiting", config = { minute = 3, hour = 5 }, __api = 3 },
        { name = "rate-limiting", config = { minute = 33 }, __api = 4 }
      },
      keyauth_credential = {
        { key = "apikey122", __consumer = 1 },
        { key = "apikey123", __consumer = 2 }
      }
    }

    spec_helper.start_kong()
  end)

  teardown(function()
    spec_helper.stop_kong()
  end)

  describe("Without authentication (IP address)", function()

    it("should get blocked if exceeding limit", function()
      wait()

      -- Default rate-limiting plugin for this API says 6/minute
      local limit = 6

      for i = 1, limit do
        local _, status, headers = http_client.get(STUB_GET_URL, {}, {host = "test4.com"})
        assert.are.equal(200, status)
        assert.are.same(tostring(limit), headers["x-ratelimit-limit-minute"])
        assert.are.same(tostring(limit - i), headers["x-ratelimit-remaining-minute"])
      end

      -- Additonal request, while limit is 6/minute
      local response, status = http_client.get(STUB_GET_URL, {}, {host = "test4.com"})
      local body = cjson.decode(response)
      assert.are.equal(429, status)
      assert.are.equal("API rate limit exceeded", body.message)
    end)

    it("should handle multiple limits", function()
      local limits = {
        minute = 3,
        hour = 5
      }

      wait()

      for i = 1, 3 do
        local _, status, headers = http_client.get(STUB_GET_URL, {}, {host = "test5.com"})
        assert.are.equal(200, status)

        assert.are.same(tostring(limits.minute), headers["x-ratelimit-limit-minute"])
        assert.are.same(tostring(limits.minute - i), headers["x-ratelimit-remaining-minute"])
        assert.are.same(tostring(limits.hour), headers["x-ratelimit-limit-hour"])
        assert.are.same(tostring(limits.hour - i), headers["x-ratelimit-remaining-hour"])
      end

      local response, status, headers = http_client.get(STUB_GET_URL, {}, {host = "test5.com"})
      assert.are.equal("2", headers["x-ratelimit-remaining-hour"])
      assert.are.equal("0", headers["x-ratelimit-remaining-minute"])
      local body = cjson.decode(response)
      assert.are.equal(429, status)
      assert.are.equal("API rate limit exceeded", body.message)
    end)

  end)

  describe("With authentication", function()

    describe("Default plugin", function()

      it("should get blocked if exceeding limit", function()
        wait()

        -- Default rate-limiting plugin for this API says 6/minute
        local limit = 6

        for i = 1, limit do
          local _, status, headers = http_client.get(STUB_GET_URL, {apikey = "apikey123"}, {host = "test3.com"})
          assert.are.equal(200, status)
          assert.are.same(tostring(limit), headers["x-ratelimit-limit-minute"])
          assert.are.same(tostring(limit - i), headers["x-ratelimit-remaining-minute"])
        end

        -- Third query, while limit is 2/minute
        local response, status = http_client.get(STUB_GET_URL, {apikey = "apikey123"}, {host = "test3.com"})
        local body = cjson.decode(response)
        assert.are.equal(429, status)
        assert.are.equal("API rate limit exceeded", body.message)
      end)

    end)

    describe("Plugin customized for specific consumer", function()

      it("should get blocked if exceeding limit", function()
        wait()

        -- This plugin says this consumer can make 4 requests/minute, not 6 like the default
        local limit = 8

        for i = 1, limit do
          local _, status, headers = http_client.get(STUB_GET_URL, {apikey = "apikey122"}, {host = "test3.com"})
          assert.are.equal(200, status)
          assert.are.same(tostring(limit), headers["x-ratelimit-limit-minute"])
          assert.are.same(tostring(limit - i), headers["x-ratelimit-remaining-minute"])
        end

        local response, status = http_client.get(STUB_GET_URL, {apikey = "apikey122"}, {host = "test3.com"})
        local body = cjson.decode(response)
        assert.are.equal(429, status)
        assert.are.equal("API rate limit exceeded", body.message)
      end)

    end)
  end)
end)
