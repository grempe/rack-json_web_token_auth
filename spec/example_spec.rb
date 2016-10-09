require 'spec_helper'

describe 'README examples' do
  let(:claims) do
    {
      name: 'John Doe',
      iat: Time.now.to_i - 1,
      nbf: Time.now.to_i - 5,
      exp: Time.now.to_i + 10,
      aud: %w(api web),
      sub: 'my-user-id',
      jti: 'my-unique-token-id',
      iss: 'https://my.example.com/'
    }
  end

  let(:claims_stringified) { Hashie.stringify_keys(claims) }

  let(:inner_app) do
    ->(env) { [200, env, [claims.to_json]] }
  end

  let(:app) do
    Rack::JsonWebTokenAuth.new(inner_app) do
      jwt_opts = {
        key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
        alg: 'HS256',
        aud: 'api',
        sub: 'my-user-id',
        jti: 'my-unique-token-id',
        iss: 'https://my.example.com/',
        leeway_seconds: 30
      }

      unsecured do
        resource '/public'
      end

      secured do
        resource '/private', jwt: jwt_opts
      end
    end
  end

  describe 'work as expected with a full claims set' do
    it 'and an unsecured path' do
      get('/public')
      expect(last_response.status).to eq 200
      expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      expect(last_response.headers['jwt.claims']).to be nil
    end
  end

  describe 'work as expected with a full claims set' do
    it 'and a secured path' do
      key = '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3'
      header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
      get('/private')
      expect(last_response.status).to eq 200
      expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
    end
  end
end
