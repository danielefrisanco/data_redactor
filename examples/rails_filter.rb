# frozen_string_literal: true

# Rails integration: scrub params before they hit the logs via Rails'
# `config.filter_parameters`. This file shows the wiring; it does NOT require
# Rails to be installed — the snippet below goes in your Rails app.
#
# In config/initializers/filter_parameter_logging.rb:
#
#   require "data_redactor/integrations/rails"
#
#   Rails.application.config.filter_parameters += [
#     DataRedactor::Integrations::Rails.filter
#   ]
#
#   # Or restrict to specific tags:
#   Rails.application.config.filter_parameters += [
#     DataRedactor::Integrations::Rails.filter(only: [:credentials, :financial])
#   ]
#
# `.filter` returns a (key, value) Proc — exactly what Rails' parameter filter
# expects. Rails calls it for every leaf in the params tree; we redact String
# values in place (the rest pass through). Keys are never touched.
#
# To SEE it work without a Rails app, here's the same proc applied by hand:

require "data_redactor/integrations/rails"

redactor = DataRedactor::Integrations::Rails.filter

value = +"alice@example.com"        # Rails passes a mutable String
redactor.call("email", value)       # filter mutates it in place
puts value                          # => [REDACTED]

untouched = 42
redactor.call("age", untouched)     # non-String -> ignored
puts untouched                      # => 42
