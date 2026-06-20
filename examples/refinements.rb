# frozen_string_literal: true

# Opt-in refinements: add `#redact` to String, Hash, and Array as sugar over
# DataRedactor.redact / DataRedactor.redact_deep. Refinements are lexically
# scoped — `#redact` exists only in files that `using` them, so the core
# classes are never patched globally. DataRedactor.redact stays the main API.
#
#   bundle exec ruby examples/refinements.rb

require "data_redactor/refinements"
using DataRedactor::Refinements

# String#redact -> DataRedactor.redact
puts "email alice@example.com".redact
# => email [REDACTED]

# Forwards only:/except:/placeholder: just like DataRedactor.redact
puts "card 4111111111111111 mail a@b.com".redact(only: [:financial])
# => card [REDACTED] mail a@b.com
puts "mail a@b.com".redact(placeholder: :tagged)
# => mail [REDACTED:CONTACT]

# Hash#redact / Array#redact -> DataRedactor.redact_deep (deep copy, keys kept)
p({ "user" => { "email" => "a@b.com" }, "count" => 3 }.redact)
# => {"user"=>{"email"=>"[REDACTED]"}, "count"=>3}
p ["a@b.com", 3, "clean"].redact
# => ["[REDACTED]", 3, "clean"]

# The receiver is never mutated.
original = "ssn 123-45-6789"
original.redact
puts original
# => ssn 123-45-6789
