# frozen_string_literal: true

# Custom patterns: redact internal IDs and people's names the gem can't ship.
#
#   ruby examples/custom_pattern.rb

require "data_redactor"

# 1. A simple internal-ID pattern. regex: accepts a Regexp or a POSIX-ERE String
#    (POSIX subset only — no \d, \s, \w, \b, lookaround). Defaults to tag: :custom.
DataRedactor.add_pattern(name: "employee_id", regex: /EMP-[0-9]{6}/)

puts DataRedactor.redact("ticket from EMP-004217 reassigned")
# => "ticket from [REDACTED] reassigned"

# 2. name_pattern builds a POSIX-ERE String for a person's name — handles
#    separators (space/comma/hyphen), optional middle name, and diacritics
#    (Jose <-> José) — so you don't hand-write the regex.
name_re = DataRedactor.name_pattern("Mario", "Rossi")
DataRedactor.add_pattern(name: "vip_mario", regex: name_re)

puts DataRedactor.redact("call from Mario Rossi about the José Muñoz account")
# => "call from[REDACTED]about the José Muñoz account"
#    (the name_pattern boundary wrapper consumes the surrounding spaces; only the
#    registered name is redacted, the unrelated José Muñoz is left alone)

# Custom patterns run under the :custom tag by default, so you can target them.
puts DataRedactor.redact("EMP-004217 and Mario Rossi", only: [:custom])
# => "[REDACTED] and[REDACTED]"

# Inspect and tidy up (clear_custom_patterns! is mainly for test suites).
puts DataRedactor.custom_patterns.map { |p| p[:name] }.inspect
# => ["employee_id", "vip_mario"]
DataRedactor.remove_pattern("employee_id")
DataRedactor.clear_custom_patterns!
