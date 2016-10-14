# encoding: UTF-8

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/json_web_token_auth/version'

Gem::Specification.new do |spec|
  spec.name          = 'rack-json_web_token_auth'
  spec.version       = Rack::JsonWebTokenAuth::VERSION
  spec.authors       = ['Glenn Rempe']
  spec.email         = ['glenn@rempe.us']
  spec.summary       = 'Rack middleware for authentication using JSON Web Tokens'
  spec.description   = 'Rack middleware for authentication using JSON Web Tokens using the jwt_claims and json_web_token gems.'
  spec.homepage      = 'https://github.com/grempe/rack-json_web_token_auth'
  spec.license       = 'MIT'

  spec.files         = Dir.glob('lib/**/*') + %w(LICENSE.txt README.md)
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ['lib']
  spec.platform      = Gem::Platform::RUBY

  spec.required_ruby_version = '>= 2.2.5'

  cert = File.expand_path('~/.gem-certs/gem-private_key_grempe_2026.pem')
  if cert && File.exist?(cert)
    spec.signing_key = cert
    spec.cert_chain = ['certs/gem-public_cert_grempe_2026.pem']
  end

  spec.add_runtime_dependency 'contracts', '~> 0.14'
  spec.add_runtime_dependency 'hashie', '~> 3.4'

  spec.add_runtime_dependency 'json_web_token', '~> 0.3.2'
  spec.add_runtime_dependency 'jwt_claims', '~> 0.1'

  spec.add_development_dependency 'rake',      '~> 11.3'
  spec.add_development_dependency 'bundler',   '~> 1.13'
  spec.add_development_dependency 'rspec',     '~> 3.4'
  spec.add_development_dependency 'rack-test', '~> 0.6'
  spec.add_development_dependency 'simplecov', '~> 0.12'
  spec.add_development_dependency 'rubocop',   '~> 0.41'
  spec.add_development_dependency 'wwtd',      '~> 1.3'
end
