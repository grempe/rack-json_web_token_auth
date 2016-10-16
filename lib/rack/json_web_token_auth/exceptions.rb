module Rack
  class JsonWebTokenAuth
    class TokenError < StandardError; end
    class HttpMethodError < StandardError; end
  end
end
