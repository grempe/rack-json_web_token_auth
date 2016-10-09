# Rack::JsonWebTokenAuth

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

WIP

## Development

After checking out the repo, run `bundle install` to install dependencies. Then,
run `bundle exec rake` to run the specs.

To install this gem onto your local machine, run `bundle exec rake install`.

### Contributing

Bug reports and pull requests are welcome on GitHub
at [https://github.com/grempe/rack-json_web_token_auth](https://github.com/grempe/rack-json_web_token_auth). This
project is intended to be a safe, welcoming space for collaboration, and
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
