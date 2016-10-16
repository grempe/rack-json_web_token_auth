require 'spec_helper'

describe 'when initializing with' do
  let(:key) { '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3' }

  let(:claims) do
    { exp: Time.now.to_i + 10 }
  end

  let(:inner_app) do
    ->(env) { [200, env, ['ok']] }
  end

  let(:app) {
    Rack::JsonWebTokenAuth.new(inner_app) do
      jwt_opts = { key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3', name: 'foo' }

      unsecured do
        resource '/public1_block1'
        resource '/public2_block1'
      end

      unsecured do
        resource '/public1_block2'
        resource '/public2_block2'
      end

      secured do
        resource '/private1_block1', jwt: jwt_opts
        resource '/private2_block1', jwt: jwt_opts
      end

      secured do
        resource '/private1_block2', jwt: jwt_opts
        resource '/private2_block2', jwt: jwt_opts
      end

      secured do
        resource '/wildcard/*', jwt: jwt_opts
        resource '/nested_wildcard/*/deep', jwt: jwt_opts
      end

      secured do
        resource '/special.chars/*', jwt: jwt_opts
        resource '/special+chars/*', jwt: jwt_opts
      end

      # a secure block that defines the same resources
      # as a previous unsecured block (should be ignored)
      secured do
        resource '/public1_block1', jwt: jwt_opts
        resource '/public2_block1', jwt: jwt_opts
      end

      secured do
        resource '/private_http_any',       jwt: jwt_opts, methods: [:any]
        resource '/private_http_get',       jwt: jwt_opts, methods: [:get]
        resource '/private_http_head',      jwt: jwt_opts, methods: [:head]
        resource '/private_http_post',      jwt: jwt_opts, methods: [:post]
        resource '/private_http_put',       jwt: jwt_opts, methods: [:put]
        resource '/private_http_patch',     jwt: jwt_opts, methods: [:patch]
        resource '/private_http_delete',    jwt: jwt_opts, methods: [:delete]
        resource '/private_http_options',   jwt: jwt_opts, methods: [:options]
      end
    end
  }

  context 'an invalid unsecured block' do
    describe 'with missing block' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            unsecured
          end
        }.to raise_error(ParamContractError)
      end
    end
  end

  context 'an invalid secured block' do
    describe 'with missing block' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured
          end
        }.to raise_error(ParamContractError)
      end
    end
  end

  context 'invalid resources' do
    describe 'missing valid path' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured do
              resource true
            end
          end
        }.to raise_error(ParamContractError)
      end
    end
  end

  context 'secured resources' do
    describe 'missing a valid :jwt key' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured do
              resource '/private'
            end
          end
        }.to raise_error(RuntimeError, 'invalid or missing jwt options for secured resource')
      end
    end

    describe 'where :jwt has no nested :key' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured do
              resource '/private', jwt: {}
            end
          end
        }.to raise_error(RuntimeError, 'invalid or missing jwt options for secured resource')
      end
    end

    describe 'where :jwt :key is empty' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured do
              resource '/private', jwt: { key: '' }
            end
          end
        }.to raise_error(RuntimeError, 'invalid or missing jwt options for secured resource')
      end
    end

    describe 'where :jwt :key is nil' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured do
              resource '/private', jwt: { key: nil }
            end
          end
        }.to raise_error(RuntimeError, 'invalid or missing jwt options for secured resource')
      end
    end

    describe 'where :jwt :key is nil but :alg is valid' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            secured do
              resource '/private', jwt: { key: nil, alg: 'HS256' }
            end
          end
        }.to raise_error(RuntimeError, 'invalid or missing jwt options for secured resource')
      end
    end

    context 'where :jwt :key is nil and :alg == "none"' do
      let (:app) {
        Rack::JsonWebTokenAuth.new(inner_app) do
          secured do
            resource '/private', jwt: { key: nil, alg: 'none' }
          end
        end
      }

      describe 'allow access with a valid none token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: nil, alg: 'none')}"
          get('/private')
          expect(last_response.status).to eq 200
        end
      end
    end

    context 'defined in the first block' do
      describe 'allow access to first resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/private1_block1')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access to second resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/private2_block1')
          expect(last_response.status).to eq 200
        end
      end

      describe 'deny access with an invalid token' do
        it 'and return 401' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
          get('/private1_block1')
          expect(last_response.status).to eq 401
        end
      end

      describe 'deny access with no token' do
        it 'and return 401' do
          get('/private1_block1')
          expect(last_response.status).to eq 401
        end
      end
    end

    context 'defined in the second block' do
      describe 'allow access with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/private1_block2')
          expect(last_response.status).to eq 200
        end
      end

      describe 'deny access with an invalid token' do
        it 'and return 401' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
          get('/private1_block1')
          expect(last_response.status).to eq 401
        end
      end

      describe 'deny access with no token' do
        it 'and return 401' do
          get('/private1_block1')
          expect(last_response.status).to eq 401
        end
      end
    end

    context 'defined in a wildcard path' do
      describe 'allow access to wildcard resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/wildcard/foo')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access to nested wildcard resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/nested_wildcard/foo/deep')
          expect(last_response.status).to eq 200
        end
      end

      describe 'deny access with an invalid token' do
        it 'and return 401' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
          get('/wildcard/foo')
          expect(last_response.status).to eq 401
        end
      end

      describe 'deny access with no token' do
        it 'and return 401' do
          get('/wildcard/foo')
          expect(last_response.status).to eq 401
        end
      end
    end

    context 'defined in a special char path' do
      describe 'allow access to . special char resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/special.chars/foo')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access to + special char resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/special+chars/foo')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access to ? special char resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/special.chars/foo?bar=baz')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access to # special char resource with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/special.chars/foo#bar')
          expect(last_response.status).to eq 200
        end
      end

      describe 'deny access with an invalid token' do
        it 'and return 401' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
          get('/special.chars/foo')
          expect(last_response.status).to eq 401
        end
      end

      describe 'deny access with no token' do
        it 'and return 401' do
          get('/special.chars/foo')
          expect(last_response.status).to eq 401
        end
      end
    end

    context 'with methods option' do
      describe 'and additional options present with :any' do
        it 'raises an exception' do
          expect {
            Rack::JsonWebTokenAuth.new(inner_app) do
              jwt_opts = {
                key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3'
              }

              secured do
                resource '/me', jwt: jwt_opts, methods: [:any, :get]
              end
            end
          }.to raise_error(RuntimeError)
        end
      end

      describe 'should allow access using HTTP GET by default with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/private_http_get')
          expect(last_response.status).to eq 200
        end
      end

      describe 'should ignore a second resource defined for the same path with different HTTP options' do
        let(:app) do
          Rack::JsonWebTokenAuth.new(inner_app) do
            jwt_opts = {
              key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3'
            }

            secured do
              resource '/me', jwt: jwt_opts, methods: [:get]
              resource '/me', jwt: jwt_opts, methods: [:post]
            end
          end
        end

        it 'and return appropriate response' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/me')
          expect(last_response.status).to eq 200
          post('/me')
          expect(last_response.status).to eq 401
        end
      end

      describe 'should deny access by default with a request that does not match the HTTP method with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/private_http_head')
          expect(last_response.status).to eq 401
          get('/private_http_post')
          expect(last_response.status).to eq 401
          get('/private_http_put')
          expect(last_response.status).to eq 401
          get('/private_http_patch')
          expect(last_response.status).to eq 401
          get('/private_http_delete')
          expect(last_response.status).to eq 401
          get('/private_http_options')
          expect(last_response.status).to eq 401
        end
      end

      describe 'should allow access with any request method against an :any method path with a valid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
          get('/private_http_any')
          expect(last_response.status).to eq 200
          head('/private_http_any')
          expect(last_response.status).to eq 200
          post('/private_http_any')
          expect(last_response.status).to eq 200
          put('/private_http_any')
          expect(last_response.status).to eq 200
          patch('/private_http_any')
          expect(last_response.status).to eq 200
          delete('/private_http_any')
          expect(last_response.status).to eq 200
          options('/private_http_any')
          expect(last_response.status).to eq 200
        end
      end
    end
  end

  # unsecured
  ###########

  context 'unsecured resources' do
    describe 'provided with a :jwt key' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            unsecured do
              resource '/public', jwt: { key: 'abc123' }
            end
          end
        }.to raise_error(RuntimeError, 'unexpected :jwt option provided for unsecured resource')
      end
    end

    describe 'provided with a :methods key' do
      it 'raises an exception' do
        expect {
          Rack::JsonWebTokenAuth.new(inner_app) do
            unsecured do
              resource '/public', methods: [:any]
            end
          end
        }.to raise_error(RuntimeError, 'unexpected :methods option provided for unsecured resource')
      end
    end

    context 'defined in the first block' do
      describe 'allow access with an invalid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
          get('/public1_block1')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access with no token' do
        it 'and return 200' do
          get('/public2_block1')
          expect(last_response.status).to eq 200
        end
      end
    end

    context 'defined in the second block' do
      describe 'allow access with an invalid token' do
        it 'and return 200' do
          header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
          get('/public1_block2')
          expect(last_response.status).to eq 200
        end
      end

      describe 'allow access with no token' do
        it 'and return 200' do
          get('/public2_block2')
          expect(last_response.status).to eq 200
        end
      end
    end
  end

  context 'unspecified resources' do
    describe 'deny access with a valid token' do
      it 'and return 401' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: key, alg: 'HS256')}"
        get('/foo')
        expect(last_response.status).to eq 401
      end
    end

    describe 'deny access with an invalid token' do
      it 'and return 401' do
        header 'Authorization', "Bearer #{JsonWebToken.sign(claims, key: SecureRandom.hex(32), alg: 'HS256')}"
        get('/foo')
        expect(last_response.status).to eq 401
      end
    end

    describe 'deny access with no token' do
      it 'and return 401' do
        get('/foo')
        expect(last_response.status).to eq 401
      end
    end
  end
end
