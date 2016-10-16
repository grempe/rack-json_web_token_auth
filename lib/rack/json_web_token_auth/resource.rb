module Rack
  class JsonWebTokenAuth
    class Resource
      include Contracts::Core
      include Contracts::Builtin

      attr_reader :public_resource, :path, :pattern, :methods, :opts

      Contract Bool, String, ({ jwt: Maybe[Hash], methods: Maybe[ResourceHttpMethods] }) => Any
      def initialize(public_resource, path, opts = {})
        @public_resource = public_resource
        @path = path
        @pattern = compile(path)
        @opts = opts

        if public_resource
          # unsecured resources should not have a :jwt option defined
          if @opts.key?(:jwt)
            raise 'unexpected :jwt option provided for unsecured resource'
          end

          # unsecured resources should not have a :methods option defined
          if @opts.key?(:methods)
            raise 'unexpected :methods option provided for unsecured resource'
          end
        else
          # secured resources must have a :jwt hash with a :key
          unless Contract.valid?(@opts, ({ jwt: { key: nil, alg: 'none' } })) ||
                 Contract.valid?(@opts, ({ jwt: { key: Key } }))
            raise 'invalid or missing jwt options for secured resource'
          end

          # Don't allow providing other HTTP methods with :any
          if opts[:methods] && opts[:methods].include?(:any) && opts[:methods].size > 1
            raise 'unexpected additional methods provided with :any'
          end

          @methods = if opts[:methods].nil?
                       [:get]
                     elsif opts[:methods] == [:any]
                       [:get, :head, :post, :put, :patch, :delete, :options]
                     else
                       opts[:methods]
                     end.map { |e| e.to_s }
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

      Contract HttpMethods => Bool
      def invalid_http_method?(request_method)
        request_method.nil? || !methods.include?(request_method.downcase)
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
