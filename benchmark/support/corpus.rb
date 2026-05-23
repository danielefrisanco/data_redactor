# frozen_string_literal: true

require "json"

# Shared payload builders and the pure-Ruby baseline redactor for the
# benchmark suite. Not part of the gem — lives under benchmark/ only.
module Corpus
  module_function

  # A realistic application log line carrying a few secrets and PII.
  def log_line
    "[2026-05-22T10:14:33Z] INFO request user=mario.rossi@example.com " \
      "ip=192.168.12.40 token=AKIAIOSFODNN7EXAMPLE card=4111111111111111 " \
      "cf=RSSMRA85M01H501Z completed in 42ms"
  end

  # A nested payload (~2 KB) with PII buried in values, for redact_deep / JSON.
  def json_hash
    {
      "user" => {
        "name"  => "Mario Rossi",
        "email" => "mario.rossi@example.com",
        "phone" => "+39 06 1234 5678",
        "tax"   => { "cf" => "RSSMRA85M01H501Z", "iban" => "IT60X0542811101000000123456" }
      },
      "payment" => {
        "card"   => "4111 1111 1111 1111",
        # Synthetic value that matches the Stripe sk_live_ pattern (8 + 24 alphanum)
        # but is obviously fake — using Stripe's own published test key tripped
        # GitHub push protection.
        "stripe" => "sk_live_" + "X" * 24
      },
      "session" => {
        "ip"    => "192.168.12.40",
        "agent" => "Mozilla/5.0",
        "trace" => Array.new(20) { |i| "event_#{i} ok" }.join(" ")
      },
      "aws" => { "key" => "AKIAIOSFODNN7EXAMPLE" }
    }
  end

  def json_blob
    JSON.generate(json_hash)
  end

  # Repeat salted log lines until the payload is approximately +mb+ megabytes.
  # Each line is salted with a counter so matches are not byte-identical.
  def log_file(mb:)
    target = mb * 1024 * 1024
    line   = log_line
    buf    = +""
    i      = 0
    buf << "#{i} #{line}\n" while (i += 1) && buf.bytesize < target
    buf
  end

  # Build a pure-Ruby baseline redactor that runs the *same* 88 patterns the
  # C extension uses. Sources come live from DataRedactor::BUILTIN_PATTERN_SOURCES
  # so there is no drift from ext/data_redactor/patterns.c. Boundary-flagged
  # patterns get the same wrapper the C Init applies via wrap_boundary().
  #
  # @return [Proc] takes a String, returns a redacted copy.
  def pure_ruby_redactor
    regexps = DataRedactor::BUILTIN_PATTERN_SOURCES
              .zip(DataRedactor::BUILTIN_PATTERN_BOUNDARY)
              .map do |source, wrapped|
      src = wrapped ? "(^|[^0-9A-Za-z])(#{source})([^0-9A-Za-z]|$)" : source
      Regexp.new(src)
    end

    # Mirror the C engine: each pattern runs sequentially over the working buffer.
    ->(text) { regexps.reduce(text) { |acc, re| acc.gsub(re, "[REDACTED]") } }
  end

  # Megabytes-per-second given a byte count and a wall-clock duration.
  def mb_per_s(bytes, seconds)
    (bytes / (1024.0 * 1024.0)) / seconds
  end
end
