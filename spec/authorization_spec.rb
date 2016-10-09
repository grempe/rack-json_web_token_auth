require 'spec_helper'
require 'securerandom'

describe Rack::JsonWebTokenAuth do
  let(:key)    { '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3' }
  let(:claims) { { foo: 'bar' } }
  let(:claims_stringified) { Hashie.stringify_keys(claims) }

  let(:inner_app) do
    ->(env) { [200, env, [claims.to_json]] }
  end

  context 'received valid Authorization header and signed token with alg' do
    describe 'NONE' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'none'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'authorizes access' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'none')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'HS256' do
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

      it 'authorizes access' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'HS384' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS384'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'authorizes access' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS384')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'HS512' do
      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
            alg: 'HS512'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'authorizes access' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS512')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'RS256' do
      rsa_private = OpenSSL::PKey::RSA.generate(2048)
      rsa_public = rsa_private.public_key

      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: rsa_public,
            alg: 'RS256'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: rsa_private, alg: 'RS256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'RS384' do
      rsa_private = OpenSSL::PKey::RSA.generate(2048)
      rsa_public = rsa_private.public_key

      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: rsa_public,
            alg: 'RS384'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: rsa_private, alg: 'RS384')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'RS512' do
      rsa_private = OpenSSL::PKey::RSA.generate(2048)
      rsa_public = rsa_private.public_key

      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: rsa_public,
            alg: 'RS512'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: rsa_private, alg: 'RS512')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'ES256' do
      ecdsa = OpenSSL::PKey::EC.new('prime256v1')
      ecdsa.generate_key
      let(:ecdsa) { ecdsa }
      ecdsa_pub = OpenSSL::PKey::EC.new(ecdsa)
      ecdsa_pub.private_key = nil
      let(:ecdsa_pub) { ecdsa_pub }

      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: ecdsa_pub,
            alg: 'ES256'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: ecdsa, alg: 'ES256')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'ES384' do
      ecdsa = OpenSSL::PKey::EC.new('secp384r1')
      ecdsa.generate_key
      let(:ecdsa) { ecdsa }
      ecdsa_pub = OpenSSL::PKey::EC.new(ecdsa)
      ecdsa_pub.private_key = nil
      let(:ecdsa_pub) { ecdsa_pub }

      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: ecdsa_pub,
            alg: 'ES384'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: ecdsa, alg: 'ES384')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end

    describe 'ES512' do
      ecdsa = OpenSSL::PKey::EC.new('secp521r1')
      ecdsa.generate_key
      let(:ecdsa) { ecdsa }
      ecdsa_pub = OpenSSL::PKey::EC.new(ecdsa)
      ecdsa_pub.private_key = nil
      let(:ecdsa_pub) { ecdsa_pub }

      let(:app) do
        Rack::JsonWebTokenAuth.new(inner_app) do
          jwt_opts = {
            key: ecdsa_pub,
            alg: 'ES512'
          }

          secured do
            resource '/', jwt: jwt_opts
          end
        end
      end

      it 'returns a 200' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: ecdsa, alg: 'ES512')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.claims']).to eq(claims_stringified)
        expect(JSON.parse(last_response.body)).to eq(claims_stringified)
      end
    end
  end

  context 'received invalid Authorization header' do
    # Accept default HS256 keys
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

    describe 'with missing header' do
      it 'returns a 401' do
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and schema, but empty token' do
      it 'returns a 401' do
        header 'Authorization', 'Bearer '
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and token but missing schema' do
      it 'returns a 401' do
        header 'Authorization', JsonWebToken.sign(claims, key: key, alg: 'HS256')
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and valid token but incorrect schema' do
      it 'returns a 401' do
        header 'Authorization', "Badstuff #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and valid token but incorrectly cased schema' do
      it 'returns a 401' do
        header 'Authorization', "bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and malformed double periods token' do
      it 'returns a 401' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256').gsub(/\./, '..')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and malformed trailing period token' do
      it 'returns a 401' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256') + '.'}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and malformed leading period token' do
      it 'returns a 401' do
        header 'Authorization', "Bearer #{'.' + JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and malformed bad character token' do
      it 'returns a 401' do
        header 'Authorization', "Bearer #{'!' + JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : malformed Authorization header or token')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end

    describe 'with header and valid token but a different secret in the token than on server' do
      it 'returns a 401' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        expect(last_response.body).to eq('Unauthorized : invalid JWT')
        expect(last_response.headers['jwt.claims']).to eq(nil)
      end
    end
  end
end
