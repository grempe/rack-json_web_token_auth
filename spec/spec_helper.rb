require 'simplecov'
SimpleCov.start do
  add_filter 'spec/'
end

require 'rspec'
require 'rack/test'
require 'rack/json_web_token_auth'

RSpec.configure do |conf|
  conf.include Rack::Test::Methods
end
