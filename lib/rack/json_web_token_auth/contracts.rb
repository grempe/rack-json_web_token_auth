module Rack
  class JsonWebTokenAuth
    # Custom Contracts
    # See : https://egonschiele.github.io/contracts.ruby/

    # The last segment gets dropped for 'none' algorithm since there is no
    # signature so both of these patterns are valid. All character chunks
    # are base64url format and periods.
    #   Bearer abc123.abc123.abc123
    #   Bearer abc123.abc123.
    BEARER_TOKEN_REGEX = %r{
      ^Bearer\s{1}(       # starts with Bearer and a single space
      [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
      [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
      [a-zA-Z0-9\-\_]*    # 0 or more chars, no trailing chars
      )$
    }x

    class RackRequestHttpAuth
      def self.valid?(val)
        Contract.valid?(val, ({ 'HTTP_AUTHORIZATION' => BEARER_TOKEN_REGEX }))
      end

      def self.to_s
        'A Rack request with JWT auth header'
      end
    end

    class RackResponse
      def self.valid?(val)
        Contract.valid?(val, [Contracts::Int, Hash, Contracts::Any])
      end

      def self.to_s
        'A Rack response'
      end
    end

    class Key
      def self.valid?(val)
        return false if val.is_a?(String) && val.strip.empty?
        Contracts::Or[String, OpenSSL::PKey::RSA, OpenSSL::PKey::EC].valid?(val)
      end

      def self.to_s
        'A JWT secret string or signature key'
      end
    end
  end
end
