# frozen_string_literal: true

# Cost of each built-in pattern in isolation. For every pattern, time
# `redact(payload, only: [name])` — the per-pattern scan cost over a fixed
# payload. Sorted slowest-first, this surfaces the expensive patterns
# (alternation-heavy ones, generic digit runs) to target in later perf work.
#
# Run from the repo root after `rake compile`:
#
#   ruby benchmark/per_pattern.rb

require "benchmark"
require_relative "../lib/data_redactor"
require_relative "support/corpus"

# A 1MB payload — large enough that per-pattern differences are measurable
# above timer noise.
payload = Corpus.log_file(mb: 1)
names   = DataRedactor.pattern_names

puts "== per-pattern scan cost (1MB payload, only: [name]) =="
puts "  timing #{names.size} patterns..."

results = names.map do |name|
  DataRedactor.redact(payload, only: [name]) # warm up
  time = 3.times.map { Benchmark.realtime { DataRedactor.redact(payload, only: [name]) } }.min
  [name, time]
end

results.sort_by! { |(_, t)| -t }

puts
puts format("  %-34s %12s %10s", "pattern", "time (ms)", "MB/s")
results.each do |name, time|
  puts format("  %-34s %12.3f %10.1f",
              name, time * 1000, Corpus.mb_per_s(payload.bytesize, time))
end

total = results.sum { |(_, t)| t }
puts
puts format("  sum of all %d patterns: %.1f ms", results.size, total * 1000)
puts "  (a full redact runs all patterns over the same buffer in one pass)"
