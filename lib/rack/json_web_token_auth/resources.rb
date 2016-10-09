require 'custom_contracts'
require 'rack/json_web_token_auth/resource'

module Rack
  class JsonWebTokenAuth
    class Resources
      include Contracts::Core
      C = Contracts

      Contract C::KeywordArgs[public_resource: C::Bool] => C::Any
      def initialize(public_resource: false)
        @resources = []
        @public_resource = public_resource
      end

      Contract C::None => C::Bool
      def public_resource?
        @public_resource
      end

      Contract String, C::Maybe[Hash] => C::ArrayOf[Resource]
      def resource(path, opts = {})
        @resources << Resource.new(public_resource?, path, opts)
      end

      Contract String => C::Maybe[Resource]
      def resource_for_path(path)
        # return first match
        @resources.detect { |r| r.matches_path?(path) }
      end
    end
  end
end
