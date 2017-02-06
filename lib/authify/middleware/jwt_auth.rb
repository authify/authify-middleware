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
        options = {
          algorithm: 'ES256',
          verify_iss: true,
          verify_iat: true,
          iss: CONFIG[:jwt][:issuer]
        }
        begin
          bearer = env.fetch('HTTP_AUTHORIZATION', '').slice(7..-1)
          payload, _header = JWT.decode bearer, public_key, true, options

          env[:scopes] = payload['scopes']
          env[:user] = payload['user']

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
      end
    end
  end
end
