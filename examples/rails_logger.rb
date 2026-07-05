# frozen_string_literal: true

# Rails-shaped request lifecycle: the Rack middleware and the redacting Logger
# working *together* to scrub one request end-to-end. In a real Rails app these
# are wired once (see the bottom of this file) and every request is scrubbed
# automatically — no per-call redaction.
#
# This script needs neither Rails nor the `rack` gem installed: it simulates a
# request by building a plain Rack env Hash and calling the middleware directly.
#
#   bundle exec ruby examples/rails_logger.rb
#
# The two integrations cover complementary surfaces of a request:
#   - Rack middleware  → scrubs the response body + sensitive request/response
#                        headers (Authorization, Set-Cookie, X-Api-Key, ...).
#   - Logger formatter → scrubs whatever your app writes to the log, so a stray
#                        `logger.info(params.inspect)` can't leak a secret.

require "logger"
require "data_redactor/integrations/logger"
require "data_redactor/integrations/rack"

# 1. A redacting application logger. Set the formatter once; every line your app
#    logs from here on is scrubbed before it is written.
logger = Logger.new($stdout)
logger.formatter = DataRedactor::Integrations::Logger.new

# 2. A trivial "controller" that logs an incoming request and returns a body
#    echoing user data — both of which leak PII/secrets in the clear.
inner_app = lambda do |env|
  logger.info("params: #{env['QUERY_STRING']}")               # app log line
  body    = ["Welcome alice@example.com — your API key is AKIAIOSFODNN7EXAMPLE"]
  headers = { "Content-Type" => "text/plain", "Set-Cookie" => "session=AKIAIOSFODNN7EXAMPLE" }
  [200, headers, body]
end

# 3. Wrap the controller in the redaction middleware (scrubs body + headers).
app = DataRedactor::Integrations::Rack.new(inner_app)

# 4. Simulate an inbound request carrying a secret in its Authorization header.
env = {
  "REQUEST_METHOD"     => "GET",
  "PATH_INFO"          => "/account",
  "QUERY_STRING"       => "email=alice@example.com&token=AKIAIOSFODNN7EXAMPLE",
  "HTTP_AUTHORIZATION" => "Bearer AKIAIOSFODNN7EXAMPLE",
}

puts "--- log output (scrubbed by the Logger formatter) ---"
status, headers, body = app.call(env)   # emits the scrubbed app log line above
# => I, [...] -- : params: email=[REDACTED]&token=[REDACTED]

puts "\n--- response (scrubbed by the Rack middleware) ---"
puts "status:            #{status}"
puts "body:              #{body.first}"
# => body:              Welcome [REDACTED] — your API key is [REDACTED]
puts "Set-Cookie header: #{headers['Set-Cookie']}"
# => Set-Cookie header: session=[REDACTED]
puts "request auth (scrubbed in env for downstream loggers): #{env['HTTP_AUTHORIZATION']}"
# => request auth (...): [REDACTED]

# In a real Rails app you wire both once and forget them:
#
#   # config/application.rb
#   require "data_redactor/integrations/rack"
#   config.middleware.use DataRedactor::Integrations::Rack, scrub: [:body, :headers]
#
#   # config/initializers/data_redactor.rb
#   require "data_redactor/integrations/logger"
#   Rails.logger.formatter = DataRedactor::Integrations::Logger.new(
#     inner: Rails.logger.formatter   # keep Rails' own formatting, just scrub the result
#   )
#
# See also examples/rails_filter.rb for scrubbing request *params* in the logs
# via Rails' built-in `config.filter_parameters`.
