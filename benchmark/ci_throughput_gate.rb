# frozen_string_literal: true

# Relative-throughput regression gate for CI.
#
# Absolute MB/s is too noisy to gate on: GitHub runners vary 5-15% run to run.
# But the RATIO of the C engine to a pure-Ruby gsub loop running the SAME
# patterns cancels runner speed almost entirely — a slow runner slows both paths
# equally. So we gate on that ratio, not on wall-clock throughput.
#
# The known result on the 1 MB log is ~2.25x (see TODO "Bench the gem
# end-to-end"). The floor is set well below that so the job only trips on a real
# regression, not on noise. Throughput numbers are printed informationally.
#
#   ruby benchmark/ci_throughput_gate.rb            # uses MIN_RATIO below
#   MIN_RATIO=1.8 ruby benchmark/ci_throughput_gate.rb
#
# Set BENCHMARK_JSON=<path> to also write the result in github-action-benchmark's
# customBiggerIsBetter schema, for the throughput-trend job to append to the
# gh-pages history. This is a side effect of the same measurement — it never
# changes the pass/fail decision (the ratio floor above is the only gate).

require "benchmark/ips"
require "json"
require_relative "../lib/data_redactor"
require_relative "support/corpus"

MIN_RATIO = Float(ENV.fetch("MIN_RATIO", "1.5"))

pure_redact = Corpus.pure_ruby_redactor
payload = Corpus.log_file(mb: 1)

# Correctness guard first: a "faster" engine that redacts less is not a pass.
c_hits    = DataRedactor.redact(payload).scan("[REDACTED]").size
ruby_hits = pure_redact.call(payload).scan("[REDACTED]").size
unless c_hits == ruby_hits
  abort "FAIL: redaction count diverged (C: #{c_hits}, Ruby: #{ruby_hits})"
end

report = Benchmark.ips do |x|
  x.config(time: 5, warmup: 2, quiet: true)
  x.report("C extension")    { DataRedactor.redact(payload) }
  x.report("pure-Ruby gsub") { pure_redact.call(payload) }
end

c_ips, ruby_ips = report.entries.map(&:ips)
ratio = c_ips / ruby_ips

puts "== CI throughput gate (1 MB log, #{c_hits} redactions) =="
puts format("  C extension:    %9.1f i/s", c_ips)
puts format("  pure-Ruby gsub: %9.1f i/s", ruby_ips)
puts format("  ratio:          %.2fx  (floor: %.2fx)", ratio, MIN_RATIO)

if ratio < MIN_RATIO
  abort format("FAIL: C engine only %.2fx faster than pure Ruby; below %.2fx floor", ratio, MIN_RATIO)
end

puts "OK: C engine #{format('%.2f', ratio)}x faster than pure Ruby (>= #{MIN_RATIO}x floor)"

# Emit the trend data point only on a passing run: a regression aborts above, so
# the history records a ratio the gate accepted, not a failing one.
#
# Only the RATIO goes in the alerting JSON. The absolute i/s figures swing 5-15%
# with runner speed (the whole reason this gate is ratio-based), so feeding them
# to github-action-benchmark's threshold would fire false alerts; they stay in
# the log above as informational. The ratio cancels runner speed, so a drop in
# it is a real engine regression — safe to alert on.
if (json_path = ENV["BENCHMARK_JSON"])
  File.write(json_path, JSON.pretty_generate([
    { "name" => "C/pure-Ruby throughput ratio", "unit" => "x", "value" => ratio.round(3) }
  ]))
  puts "Wrote benchmark JSON to #{json_path}"
end
