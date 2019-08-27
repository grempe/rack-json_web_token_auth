# Rack::JsonWebTokenAuth

[![Build Status](https://travis-ci.org/grempe/rack-json_web_token_auth.svg?branch=master)](https://travis-ci.org/grempe/rack-json_web_token_auth)
[![Code Climate](https://codeclimate.com/github/grempe/rack-json_web_token_auth/badges/gpa.svg)](https://codeclimate.com/github/grempe/rack-json_web_token_auth)

## WARNING

This is pre-release software. It is pretty well tested but has not yet
been used in production. Your feedback is requested.

## About

`Rack::JsonWebTokenAuth` is a Rack middleware that makes it easy for your
Rack based application (Sinatra, Rails) to authenticate clients that
present a valid `Authorization: Bearer token` header with a [JSON Web Token (JWT)](https://jwt.io/).

This middleware was inspired by the similar [eigenbart/rack-jwt](https://github.com/eigenbart/rack-jwt)
middleware but provides a leaner codebase that relies upon the excellent
[garyf/jwt_claims](https://github.com/garyf/jwt_claims) and [garyf/json_web_token](https://github.com/garyf/json_web_token) gems to provide
all JWT token validation. This gem also makes extensive use of the [contracts](https://egonschiele.github.io/contracts.ruby/) gem to enforce strict
type checking on all inputs and outputs. It is designed to fail-fast on errors and
reject invalid inputs before even trying to parse them using JWT.

## Installation

Add this line to your application's `Gemfile`:

```ruby
gem 'rack-json_web_token_auth'
```

And then execute:

```
$ bundle install
```

Or install it directly with:

```
$ gem install rack-json_web_token_auth
```

## Usage

This Rack middleware is designed to allow adding a simple authentication layer,
using JSON Web Tokens (JWT), to your Rack based applications. It's easy
to configure with a simple Ruby DSL.

This middleware is not responsible for creating valid JWT tokens for you. It
only receives and validates them. If the token provided is valid for a specific
path the request will be allowed to continue as normal. If the token is invalid,
or the path requested is not a configured path, a `401 Not Authorized`
HTTP response will be sent.

For token creation I recommend the
[garyf/json_web_token](https://github.com/garyf/json_web_token) gem.

### Creating a JWT

Here is an example of creating a JWT with a pretty full set of claims. You may
not need all of these for your application.

```ruby
require 'json_web_token'

key = '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3'

claims = {
  name: 'John Doe',
  iat: Time.now.to_i - 1,
  nbf: Time.now.to_i - 5,
  exp: Time.now.to_i + 10,
  aud: %w(api web),
  sub: 'my-user-id',
  jti: 'my-unique-token-id',
  iss: 'https://my.example.com/'
}

# generate a signed token
jwt = JsonWebToken.sign(claims, key: key, alg: 'HS256')
#=> "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE0NzY0MTUwMjUsIm5iZiI6MTQ3NjQxNTAyMSwiZXhwIjoxNDc2NDE1MDM2LCJhdWQiOlsiYXBpIiwid2ViIl0sInN1YiI6Im15LXVzZXItaWQiLCJqdGkiOiJteS11bmlxdWUtdG9rZW4taWQiLCJpc3MiOiJodHRwczovL215LmV4YW1wbGUuY29tLyJ9.-zu-FGfLmwLX69DC2UIsk-8oEGoRSkCOUqbJwcarSm4"
```

### Submitting a JWT

Your client of choice needs to submit an [Authorization Bearer](http://self-issued.info/docs/draft-ietf-oauth-v2-bearer.html) request header.

How you do this is client specific and left as an exercise for the reader.

```
'Authorization' => "Bearer #{jwt}"
```

### Server Config

This middleware should be inserted as early as possible into your middleware
stack.

Configuring the Rack middleware to accept JWT tokens on your server is just a
matter of adding the middleware and configuring which paths are to be considered
public and `unsecured` (no JWT needed), and which require a valid token
to continue. These are private `secured` paths.

For each `secured` resource you must also provide the JWT config needed to validate
incoming tokens. The available claims are processed by the [garyf/jwt_claims](https://github.com/garyf/jwt_claims) gem and more info about
claims can be found in the README for that project. At a minimum a `:key` must
be provided except if the `none` algorithm is being used (probably not recommended).

For `secured` resources you can optionally also pass in a `:methods` option,
which specifies an array of HTTP methods that are allowed for the specified `resource`.
One or more of `[:any, :get, :head, :post, :put, :patch, :delete, :options]`
can be provided. If the `:any` option is desired it must be the only option provided.

Configuration directives are processed in the order that you provide and requests
match against the **first path match**. For this reason you should probably put your
`unsecured` resources first and order all resources from most specific to least
specific. If multiple resources with the same path are configured, but with different
options, only the first resource matched will be used to test the request, all
others will be ignored.

The DSL was heavily inspired by the [rack-cors](https://github.com/cyu/rack-cors)
gem.

```ruby
require 'rack/json_web_token_auth'

# Sinatra style Rack middleware `use` syntax
use Rack::JsonWebTokenAuth do

  # You can define JWT options for all `secured` resources globally
  # or you can specify a hash like this inside each block. If you want to
  # get really granular this config can even be different per `secure` resource.
  jwt_opts = {
    key: '4a7b98c31c3b6918f916d809443c096d02bf686d6bead5baa4a162642cea98b3',
    alg: 'HS256',
    aud: 'api',
    sub: 'my-user-id',
    jti: 'my-unique-token-id',
    iss: 'https://my.example.com/',
    leeway_seconds: 30
  }

  # Resources defined in this block are whitelisted and
  # require no token for requests to the configured
  # resource path. You should probably define your unsecured
  # paths first. Resources in this block will raise an exception
  # if provided with the :jwt options hash.
  unsecured do
    resource '/users/registration'
    resource '/users/login'
  end

  # Resources defined in this block require a valid JWT token
  # for access. Each resource takes a path and a Hash of options.
  # The only option supported at the moment is `jwt`. The `:jwt` Hash
  # key should be set to a Hash and only a `:key` must be defined
  # which is a random key of sufficient strength.
  #
  # Additional JWT claims can also be provided in this hash as shown in
  # this example.
  #
  # Resources defined in this block will raise an exception if they
  # are not provided with the `:jwt` options hash and a valid `:key`
  # (unless using the 'none' algorithm).
  secured do
    # a resource can start with a slash and match an exact path
    resource '/private', jwt: jwt_opts

    # or it can contain a wildcard '*'. The entire path
    # can even be specified with '*' if you wanted to
    # match all paths.
    resource '/private/*/wildcard', jwt: jwt_opts

    # Every resource can be configured with its own
    # JWT keys and all other valid JWT claim options.
    # For example you could require one token config for
    # login and registration, and on successful login mint
    # another flavor of token for all other app API access.
    resource '/another/path', jwt: {key: 'a long random key', alg: 'HS512'}
  end

  # You can get very granular by specifying that a resource can only be accessed
  # when requested with certain HTTP methods. The default for any resource is
  # to allow HTTP `GET` requests only. You need to pass in a :methods array if
  # you want to expose additional methods.
  #
  # The available choices are:
  #   [:any, :get, :head, :post, :put, :patch, :delete, :options]
  #
  # If you try to specify :methods on an `unsecured` resource it will throw
  # an exception.
  secured do
    # GET only
    resource '/http_get_only', jwt: jwt_opts, methods: [:get]

    # GET or POST
    resource '/http_post_or_get', jwt: jwt_opts, methods: [:get, :post]

    # ANY HTTP method allowed
    resource '/http_any', jwt: jwt_opts, methods: [:any]

    # ANY HTTP method allowed (alternate)
    # This is the same as [:any]
    resource '/http_any_manual', jwt: jwt_opts, methods: [:get, :head, :post, :put, :patch, :delete, :options]

    # IGNORED! This resource path was already defined above!
    # Even though it has different methods allowed it will be ignored.
    resource '/http_post_or_get', jwt: jwt_opts, methods: [:post]
  end

  # You can have more than one `unsecured` or `secured` block if you like.
  unsecured do
    # WARNING : this resource will never be used since it is masked
    # by another resource higher in the stack with the same '/private' path.
    resource '/private'
  end

  # Requests to any resource path not explictly marked as 'secured' or
  # `unsecured` above will fail-safe and return a 401 status.
  # e.g. /path/to/somewhere/else
end
```

## Development

After checking out the repo, run `bundle install` to install dependencies. Then,
run `bundle exec rake` to run the specs.

To install this gem onto your local machine, run `bundle exec rake install`.

### Installation Security : Signed Git Commits

Most, if not all, of the commits and tags to this repository are
signed with my PGP/GPG code signing key. I have uploaded my code signing public
keys to GitHub and you can now verify those signatures with the GitHub UI.
See [this list of commits](https://github.com/grempe/rack-json_web_token_auth/commits/master)
and look for the `Verified` tag next to each commit. You can click on that tag
for additional information.

You can also clone the repository and verify the signatures locally using your
own GnuPG installation. You can find my certificates and read about how to conduct
this verification at [https://www.rempe.us/keys/](https://www.rempe.us/keys/).

### Contributing

Bug reports and pull requests are welcome on GitHub
at [https://github.com/grempe/rack-json_web_token_auth](https://github.com/grempe/rack-json_web_token_auth). This project is intended to be a safe, welcoming space for collaboration, and
contributors are expected to adhere to the
[Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Legal

### Copyright

(c) 2016 Glenn Rempe <[glenn@rempe.us](mailto:glenn@rempe.us)> ([https://www.rempe.us/](https://www.rempe.us/))

### License

The gem is available as open source under the terms of
the [MIT License](http://opensource.org/licenses/MIT).

### Warranty

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the LICENSE.txt file for the
specific language governing permissions and limitations under
the License.

## Thank You!

Thanks to Gary Fleshman ([@garyf](https://github.com/garyf)) for
his very well written implementation of JWT and for accepting my patches.

And of course thanks to Mr. Eigenbart ([@eigenbart](https://github.com/eigenbart))
for the inspiration.
