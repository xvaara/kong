local json = require "cjson"
local http_client = require "kong.tools.http_client"
local spec_helper = require "spec.spec_helpers"

describe("HMAC Auth Credentials API", function()
  local BASE_URL, credential, consumer

  setup(function()
    spec_helper.prepare_db()
    spec_helper.start_kong()
  end)

  teardown(function()
    spec_helper.stop_kong()
  end)

  describe("/consumers/:consumer/hmac-auth/", function()

    setup(function()
      local fixtures = spec_helper.insert_fixtures {
        consumer = {{ username = "bob" }}
      }
      consumer = fixtures.consumer[1]
      BASE_URL = spec_helper.API_URL.."/consumers/bob/hmac-auth/"
    end)

  end)
end)
