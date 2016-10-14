require 'json'
require 'contracts'
require 'hashie'
require 'jwt_claims'

require 'rack/json_web_token_auth/resources'
require 'rack/json_web_token_auth/resource'
require 'custom_contracts'

module Rack
  # Rack Middleware for JSON Web Token Authentication
  class JsonWebTokenAuth
    include Contracts::Core
    C = Contracts

    ENV_KEY = 'jwt.claims'.freeze
    PATH_INFO_HEADER_KEY = 'PATH_INFO'.freeze

    Contract C::Any, Proc => C::Any
    def initialize(app, &block)
      @app = app
      # execute the block methods provided in the context of this class
      instance_eval(&block)
    end

    Contract Proc => C::ArrayOf[Resources]
    def secured(&block)
      resources = Resources.new(public_resource: false)
      # execute the methods in the 'secured' block in the context of
      # a new Resources object
      resources.instance_eval(&block)
      all_resources << resources
    end

    Contract Proc => C::ArrayOf[Resources]
    def unsecured(&block)
      resources = Resources.new(public_resource: true)
      # execute the methods in the 'unsecured' block in the context of
      # a new Resources object
      resources.instance_eval(&block)
      all_resources << resources
    end

    Contract Hash => C::RackResponse
    def call(env)
      begin
        resource = resource_for_path(env[PATH_INFO_HEADER_KEY])

        if resource.public_resource?
          # whitelisted as `unsecured`. skip all token authentication.
          @app.call(env)
        elsif resource.nil?
          # no matching `secured` or `unsecured` resource.
          # fail-safe with 401 unauthorized
          raise 'No resource for path defined. Deny by default.'
        else
          # a `secured` resource, validate the token to see if authenticated

          # Test that `env` has a well formed Authorization header
          unless Contract.valid?(env, C::RackRequestHttpAuth)
            raise 'malformed Authorization header or token'
          end

          # Extract the token from the 'Authorization: Bearer token' string
          token = C::BEARER_TOKEN_REGEX.match(env['HTTP_AUTHORIZATION'])[1]

          # Verify the token and its claims are valid
          jwt_opts = resource.opts[:jwt]
          jwt = ::JwtClaims.verify(token, jwt_opts)

          # JwtClaims.verify returns a JWT claims set hash, if the
          # JWT Message Authentication Code (MAC), or signature,
          # are verified and the registered claims are also verified.
          if Contract.valid?(jwt, C::HashOf[ok: C::HashOf[Symbol => C::Any]])
            # Authenticated! Pass all claims into the app env for app use
            # with the hash keys converted to strings to match Rack env.
            env[ENV_KEY] = Hashie.stringify_keys(jwt[:ok])
          elsif Contract.valid?(jwt, C::HashOf[error: C::ArrayOf[Symbol]])
            # a list of any registered claims that fail validation, if the JWT MAC is verified
            raise "invalid JWT claims : #{jwt[:error].sort.join(', ')}"
          elsif Contract.valid?(jwt, C::HashOf[error: 'invalid JWT'])
            # the JWT MAC is not verified
            raise 'invalid JWT'
          elsif Contract.valid?(jwt, C::HashOf[error: 'invalid input'])
            # otherwise
            raise 'invalid JWT input'
          else
            raise 'unhandled JWT error'
          end

          @app.call(env)
        end
      rescue StandardError => e
        body = e.message.nil? ? 'Unauthorized' : "Unauthorized : #{e.message}"
        headers = { 'WWW-Authenticate' => 'Bearer error="invalid_token"',
                    'Content-Type' => 'text/plain',
                    'Content-Length' => body.bytesize.to_s }
        [401, headers, [body]]
      end
    end

    Contract C::None => C::Or[C::ArrayOf[Resources], []]
    def all_resources
      @all_resources ||= []
    end

    Contract String => C::Maybe[Resource]
    def resource_for_path(path_info)
      all_resources.each do |r|
        if found = r.resource_for_path(path_info)
          return found
        end
      end
      nil
    end
  end
end