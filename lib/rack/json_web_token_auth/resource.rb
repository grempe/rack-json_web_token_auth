module Rack
  class JsonWebTokenAuth
    class Resource
      include Contracts::Core
      C = Contracts

      attr_accessor :public_resource, :path, :pattern, :opts

      Contract C::Bool, String, Hash => C::Any
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

      Contract String => C::Maybe[Fixnum]
      def matches_path?(path)
        pattern =~ path
      end

      Contract C::None => C::Bool
      def public_resource?
        public_resource
      end

      protected

      Contract String => Regexp
      def compile(path)
        if path.respond_to? :to_str
          special_chars = %w{. + ( )}
          pattern =
            path.to_str.gsub(/((:\w+)|[\*#{special_chars.join}])/) do |match|
              case match
              when "*"
                "(.*?)"
              when *special_chars
                Regexp.escape(match)
              else
                "([^/?&#]+)"
              end
            end
          /^#{pattern}$/
        elsif path.respond_to? :match
          path
        else
          raise TypeError, path
        end
      end
    end
  end
end
