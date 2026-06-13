# frozen_string_literal: true

# Rack middleware: scrub the response body and/or sensitive headers. Works with
# any Rack app (Rails, Sinatra, bare Rack). No `rack` gem needed to RUN this
# example — we call the middleware with a plain Rack env Hash directly.
#
#   ruby examples/rack_middleware.rb

require "data_redactor/integrations/rack"

# A trivial downstream app that leaks PII in its body and echoes an auth header.
inner_app = lambda do |_env|
  body    = ["Welcome alice@example.com — token AKIAIOSFODNN7EXAMPLE"]
  headers = { "Content-Type" => "text/plain", "X-Api-Key" => "AKIAIOSFODNN7EXAMPLE" }
  [200, headers, body]
end

# Default scrubs both body and headers. Pass scrub: [:headers] for headers only.
app = DataRedactor::Integrations::Rack.new(inner_app)

env = {
  "REQUEST_METHOD"     => "GET",
  "PATH_INFO"          => "/",
  "HTTP_AUTHORIZATION" => "Bearer AKIAIOSFODNN7EXAMPLE", # redacted in env for downstream loggers
}

status, headers, body = app.call(env)

puts "status:  #{status}"
puts "body:    #{body.first}"
# => body:    Welcome [REDACTED] — token [REDACTED]
puts "X-Api-Key header: #{headers['X-Api-Key']}"
# => X-Api-Key header: [REDACTED]
puts "request Authorization (scrubbed in env): #{env['HTTP_AUTHORIZATION']}"
# => request Authorization (scrubbed in env): Bearer [REDACTED]

# In a real app you'd just add it to config.ru / config/application.rb:
#
#   use DataRedactor::Integrations::Rack, scrub: [:body, :headers]
