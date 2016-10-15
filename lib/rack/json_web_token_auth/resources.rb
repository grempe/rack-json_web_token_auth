require 'rack/json_web_token_auth/resource'

module Rack
  class JsonWebTokenAuth
    class Resources
      include Contracts::Core
      include Contracts::Builtin

      Contract KeywordArgs[public_resource: Bool] => Any
      def initialize(public_resource: false)
        @resources = []
        @public_resource = public_resource
      end

      Contract None => Bool
      def public_resource?
        @public_resource
      end

      Contract String, Maybe[Hash] => ArrayOf[Resource]
      def resource(path, opts = {})
        @resources << Resource.new(public_resource?, path, opts)
      end

      Contract String => Maybe[Resource]
      def resource_for_path(path)
        # return first match
        @resources.detect { |r| r.matches_path?(path) }
      end
    end
  end
end
