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
        payload = process_token

        env[:scopes] = payload['scopes']
        env[:user] = payload['user']
        env[:authenticated] = true
      rescue JWT::DecodeError => e
        env[:authenticated] = false
        env[:authentication_errors] ||= []
        env[:authentication_errors] << e
      rescue JWT::ExpiredSignature => e
        env[:authenticated] = false
        env[:authentication_errors] ||= []
        env[:authentication_errors] << e
      rescue JWT::InvalidIssuerError => e
        env[:authenticated] = false
        env[:authentication_errors] ||= []
        env[:authentication_errors] << e
      rescue JWT::InvalidIatError => e
        env[:authenticated] = false
        env[:authentication_errors] ||= []
        env[:authentication_errors] << e
      ensure
        @app.call env
      end

      private

      def process_token
        options = {
          algorithm: 'ES256',
          verify_iss: true,
          verify_iat: true,
          iss: CONFIG[:jwt][:issuer]
        }

        bearer = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
        JWT.decode(bearer, public_key, true, options)[0]
      end
    end
  end
end
