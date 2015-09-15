local BaseDao = require "kong.dao.cassandra.base_dao"

local SCHEMA = {
  primary_key = {"id"},
  fields = {
    id = { type = "id", dao_insert_value = true },
    created_at = { type = "timestamp", dao_insert_value = true },
    consumer_id = { type = "id", required = true, queryable = true, foreign = "consumers:id" },
    key_id = { type = "string", required = true, unique = true, queryable = true },
    key = { type = "string" }
  }
}

local HMACAuthCredentials = BaseDao:extend()

function HMACAuthCredentials:new(properties)
  self._table = "hmak_credentials"
  self._schema = SCHEMA

  HMACAuthCredentials.super.new(self, properties)
end

return { hmac_credentials = HMACAuthCredentials }
