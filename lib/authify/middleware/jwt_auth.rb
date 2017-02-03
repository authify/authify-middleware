module Authify
  module Middleware
    # Auth Middleware
    class JWTAuth
      include Core::Helpers::JWTSSL

      def initialize(app)
        @app = app
      end

      # rubocop:disable Metrics/MethodLength
      def call(env)
        options = { algorithm: 'ES256', iss: CONFIG[:jwt][:issuer] }
        bearer = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
        payload, _header = JWT.decode bearer, public_key, true, options

        env[:scopes] = payload['scopes']
        env[:user] = payload['user']

        @app.call env
      rescue JWT::DecodeError
        [
          401,
          { 'Content-Type' => 'text/plain' },
          ['A token must be passed.']
        ]
      rescue JWT::ExpiredSignature
        [
          403,
          { 'Content-Type' => 'text/plain' },
          ['The token has expired.']
        ]
      rescue JWT::InvalidIssuerError
        [
          403,
          { 'Content-Type' => 'text/plain' },
          ['The token does not have a valid issuer.']
        ]
      rescue JWT::InvalidIatError
        [
          403,
          { 'Content-Type' => 'text/plain' },
          ['The token does not have a valid "issued at" time.']
        ]
      end
    end
  end
end
