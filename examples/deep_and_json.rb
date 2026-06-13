# frozen_string_literal: true

# Structured data: redact every string leaf of a nested Hash/Array, or a JSON
# string, without flattening it. Keys are never redacted, only values.
#
#   ruby examples/deep_and_json.rb

require "data_redactor"
require "json"

# redact_deep walks Hashes and Arrays, redacting String leaves in a COPY
# (the input is never mutated). Non-string leaves pass through untouched.
params = {
  "user"    => { "email" => "alice@example.com", "age" => 31 },
  "tokens"  => ["AKIAIOSFODNN7EXAMPLE", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"],
}

clean = DataRedactor.redact_deep(params)
puts JSON.pretty_generate(clean)
# => email -> "[REDACTED]", both tokens -> "[REDACTED]", age 31 unchanged

puts "input untouched? #{params['user']['email'] == 'alice@example.com'}"
# => input untouched? true

# redact_json parses a JSON string, redacts its string leaves, re-serialises.
json_in = '{"customer":{"iban":"DE89370400440532013000","name":"public"}}'
puts DataRedactor.redact_json(json_in)
# => {"customer":{"iban":"[REDACTED]","name":"public"}}

# Same filters as redact apply throughout.
puts JSON.pretty_generate(DataRedactor.redact_deep(params, only: [:credentials]))
# => email kept (contact), tokens redacted (credentials)
