# frozen_string_literal: true

# Dry-run / report mode: find sensitive values without rewriting the text.
# `scan` returns the redacted string PLUS a list of what it found, with byte
# offsets into the original input — useful for audit logs and "what would be
# redacted?" tooling.
#
#   ruby examples/scan_report.rb

require "data_redactor"

text = "User AKIAIOSFODNN7EXAMPLE logged in from 192.168.1.1"

result = DataRedactor.scan(text)

puts result[:redacted]
# => "User [REDACTED] logged in from [REDACTED]"

result[:matches].each do |m|
  # start/length are BYTE offsets into the ORIGINAL text, so byteslice them back.
  original = text.byteslice(m[:start], m[:length])
  puts format("  %-12s %-20s %s (at %d, %d bytes)",
              m[:tag], m[:name], original, m[:start], m[:length])
end
# =>   credentials  aws_access_key_id    AKIAIOSFODNN7EXAMPLE (at 5, 20 bytes)
#      network      ipv4                 192.168.1.1          (at 41, 11 bytes)

# scan takes the same only:/except:/placeholder: filters as redact.
only_network = DataRedactor.scan(text, only: [:network])
puts "network-only matches: #{only_network[:matches].map { |m| m[:name] }.inspect}"
