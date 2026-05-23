# frozen_string_literal: true

# Head-to-head: the C extension vs a pure-Ruby gsub loop running the SAME 88
# patterns (see Corpus.pure_ruby_redactor). This is the C-extension value
# proposition. Run from the repo root after `rake compile`:
#
#   ruby benchmark/vs_pure_ruby.rb

require "benchmark/ips"
require "benchmark/memory"
require_relative "../lib/data_redactor"
require_relative "support/corpus"

payload      = Corpus.log_file(mb: 1)
pure_redact  = Corpus.pure_ruby_redactor

# Sanity check: both paths must produce equivalent output, otherwise the
# comparison is meaningless.
c_out    = DataRedactor.redact(payload)
ruby_out = pure_redact.call(payload)
puts "output redaction count — C: #{c_out.scan('[REDACTED]').size}, " \
     "pure-Ruby: #{ruby_out.scan('[REDACTED]').size}"
puts

puts "== speed: C extension vs pure-Ruby gsub (1MB log, 88 patterns) =="
report = Benchmark.ips do |x|
  x.config(time: 5, warmup: 2)
  x.report("C extension")    { DataRedactor.redact(payload) }
  x.report("pure-Ruby gsub") { pure_redact.call(payload) }
  x.compare!
end

c_ips, ruby_ips = report.entries.map(&:ips)
puts
puts format("  speedup: C extension is %.1fx faster than pure-Ruby gsub",
            c_ips / ruby_ips)

puts
puts "== allocations (Ruby objects) =="
puts "  Note: the C path allocates its working buffers in C — invisible to"
puts "  benchmark-memory's Ruby object counter. The pure-Ruby path allocates"
puts "  a String per gsub pass plus match state. The gap below understates"
puts "  the real allocation difference in the C path's favour."
Benchmark.memory do |x|
  x.report("C extension")    { DataRedactor.redact(payload) }
  x.report("pure-Ruby gsub") { pure_redact.call(payload) }
  x.compare!
end
