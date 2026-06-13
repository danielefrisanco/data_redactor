# frozen_string_literal: true

# Core redaction: the one method you need 90% of the time.
#
#   ruby examples/basic_redact.rb
#
# Run from the repo root after `bundle exec rake compile`, or after the gem is
# installed (`gem install data_redactor`) drop the -Ilib below.

require "data_redactor"

text = "User CF is RSSMRA85M01H501Z, email alice@example.com, key AKIAIOSFODNN7EXAMPLE"

# Redact everything the gem knows about.
puts DataRedactor.redact(text)
# => "User CF is [REDACTED], email [REDACTED], key [REDACTED]"

# Only certain tags (see DataRedactor.tags for the full list).
puts DataRedactor.redact(text, only: [:credentials])
# => "...email alice@example.com, key [REDACTED]"  (CF + email left alone)

# Everything except one pattern by name.
puts DataRedactor.redact(text, except: ["email"])
# => "...email alice@example.com..."  (email kept, the rest redacted)

# Placeholder modes: plain (default), :tagged, :hash.
puts DataRedactor.redact(text, placeholder: :tagged)
# => "...email [REDACTED:CONTACT], key [REDACTED:CREDENTIALS]"

puts DataRedactor.redact(text, placeholder: :hash)
# => "...email [CONTACT_xxxx]..."  (deterministic djb2: same value -> same token)

puts DataRedactor.redact(text, placeholder: "***")
# => "...email ***, key ***"
