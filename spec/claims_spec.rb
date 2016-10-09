require 'spec_helper'
require 'securerandom'

describe Rack::JsonWebTokenAuth do
  let(:key)    { '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3' }
  let(:claims) { { foo: 'bar' } }
  let(:claims_stringified) { Hashie.stringify_keys(claims) }

  let(:inner_app) do
    ->(env) { [200, env, [claims.to_json]] }
  end

  context 'with a valid claim for' do
    let(:app) do
      Rack::JsonWebTokenAuth.new(inner_app) do
        jwt_opts = {
          key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
          alg: 'HS256'
        }

        secured do
          resource '/', jwt: jwt_opts
        end
      end
    end

    describe 'exp in the future' do
      it 'returns a 200' do
        claims = { exp: Time.now.to_i + 5 }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'nbf in the past' do
      it 'returns a 200' do
        claims = { nbf: Time.now.to_i - 5 }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'iat in the past' do
      it 'returns a 200' do
        claims = { iat: Time.now.to_i - 5 }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'iss match' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            iss: 'me'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        claims = { iss: 'me' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'sub match' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            sub: 'me'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        claims = { sub: 'me' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'jti match' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            jti: 'me'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        claims = { jti: 'me' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'aud match when token contains an aud array' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            aud: 'api'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        claims = { aud: ['www', 'api'] }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end

    describe 'aud match when token contains an aud string' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            aud: 'api'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        claims = { aud: 'api' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(Hashie.stringify_keys(claims))
      end
    end
  end

  context 'with an invalid claim for' do
    let(:app) do
      Rack::JsonWebTokenAuth.new(inner_app) do
        jwt_opts = {
          key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
          alg: 'HS256'
        }

        secured do
          resource '/', jwt: jwt_opts
        end
      end
    end

    describe 'exp in the past' do
      it 'returns a 401' do
        claims = { exp: Time.now.to_i - 1 }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : exp')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'nbf in the future' do
      it 'returns a 401' do
        claims = { nbf: Time.now.to_i + 10 }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : nbf')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'iat in the future' do
      it 'returns a 401' do
        claims = { iat: Time.now.to_i + 10 }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : iat')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'iss mismatch' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            iss: 'you'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 401' do
        claims = { iss: 'me' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : iss')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'sub mismatch' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            sub: 'you'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 401' do
        claims = { sub: 'me' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : sub')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'jti mismatch' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            jti: 'you'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 401' do
        claims = { jti: 'me' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : jti')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'aud mismatch when token contains an aud array' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            aud: 'api'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 401' do
        claims = { aud: ['web1', 'web2'] }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : aud')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'aud mismatch when token contains an aud string' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS256',
            aud: 'api'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 401' do
        claims = { aud: 'web' }
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT claims : aud')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

  end
end
