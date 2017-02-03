# Standard Library Requirements

# External Requirements
require 'authify/core'
require 'rack'

# Internal Requirements
module Authify
  module Middleware
    CONFIG = Core::CONFIG.merge(
      {}
    )
  end
end

require 'authify/middleware/version'
require 'authify/middleware/jwt_auth'
