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

    class Algorithm
      def self.valid?(val)
        Contracts::Enum['none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'].valid?(val)
      end

      def self.to_s
        'A valid JWT token signature algorithm, or none'
      end
    end

    class DecodedToken
      def self.valid?(val)
        Contracts::ArrayOf[Hash].valid?(val) &&
          Contracts::DecodedTokenClaims.valid?(val[0]) &&
          Contracts::DecodedTokenHeader.valid?(val[1])
      end

      def self.to_s
        'A valid Array of decoded token claims and header Hashes'
      end
    end

    class DecodedTokenClaims
      def self.valid?(val)
        Contracts::HashOf[Contracts::Or[String, Symbol] => Contracts::Maybe[Contracts::Or[String, Contracts::Num, Contracts::Bool, Contracts::ArrayOf[Contracts::Any], Hash]]].valid?(val)
      end

      def self.to_s
        'A valid decoded token payload attribute'
      end
    end

    class DecodedTokenHeader
      def self.valid?(val)
        Contracts::HashOf[Contracts::Enum['typ', 'alg'] => Contracts::Or['JWT', Contracts::TokenAlgorithm]].valid?(val)
      end

      def self.to_s
        'A valid decoded token header attribute'
      end
    end
  end
end
