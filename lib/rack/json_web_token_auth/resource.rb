module Rack
  class JsonWebTokenAuth
    class Resource
      include Contracts::Core
      include Contracts::Builtin

      attr_accessor :public_resource, :path, :pattern, :opts

      Contract Bool, String, Hash => Any
      def initialize(public_resource, path, opts = {})
        @public_resource = public_resource
        @path = path
        @pattern = compile(path)
        @opts = opts

        if public_resource
          # unsecured resources should not have any jwt options defined
          if @opts.key?(:jwt)
            raise 'unexpected jwt options provided for unsecured resource'
          end
        else
          # secured resources must have a :jwt hash with a :key
          unless Contract.valid?(@opts, ({ jwt: { key: nil, alg: 'none' } })) ||
                 Contract.valid?(@opts, ({ jwt: { key: Key } }))
            raise 'invalid or missing jwt options for secured resource'
          end
        end
      end

      Contract String => Maybe[Integer]
      def matches_path?(path)
        pattern =~ path
      end

      Contract None => Bool
      def public_resource?
        public_resource
      end

      protected

      Contract String => Regexp
      def compile(path)
        special_chars = %w{. + ( )}

        pattern = path.gsub(/([\*#{special_chars.join}])/) do |match|
          case match
          when '*'
            '(.*?)'
          when *special_chars
            Regexp.escape(match)
          else
            '([^/?&#]+)'
          end
        end

        /^#{pattern}$/
      end
    end
  end
end
