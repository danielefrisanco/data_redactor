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

pure_redact = Corpus.pure_ruby_redactor

# The gem is called many times on small strings (a log line per scrub, a JSON
# leaf per redact_deep) far more often than once on a 1 MB payload — so we
# measure both the typical case and the stress test. Small-string per-call
# latency dominates 88×regexec setup cost; 1 MB stresses the matching loop.

small_payloads = {
  "log line  (168B)"  => Corpus.log_line,
  "json blob (~580B)" => Corpus.json_blob,
  "8 log lines (~1.3KB)" => Array.new(8) { Corpus.log_line }.join("\n"),
  "100 log lines (~17KB)" => Array.new(100) { Corpus.log_line }.join("\n")
}

# Sanity check across all sizes: both paths must produce equivalent output.
puts "== correctness: same redaction count across sizes =="
(small_payloads.values + [Corpus.log_file(mb: 1)]).each_with_index do |text, i|
  c    = DataRedactor.redact(text).scan("[REDACTED]").size
  ruby = pure_redact.call(text).scan("[REDACTED]").size
  ok   = c == ruby ? "✓" : "✗"
  label = i < small_payloads.size ? small_payloads.keys[i] : "1 MB log"
  puts "  #{ok}  #{label.ljust(22)} C: #{c}  Ruby: #{ruby}"
end
puts

puts "== speed: per-call latency on small strings (the typical case) =="
small_payloads.each do |label, text|
  report = Benchmark.ips do |x|
    x.config(time: 2, warmup: 1, quiet: true)
    x.report("C")    { DataRedactor.redact(text) }
    x.report("Ruby") { pure_redact.call(text) }
  end
  c_ips, ruby_ips = report.entries.map(&:ips)
  ratio = c_ips / ruby_ips
  verdict = ratio >= 1.0 ? format("C is %.1fx faster", ratio) : format("C is %.1fx slower", 1.0 / ratio)
  puts format("  %-22s C: %9.1f ips  Ruby: %9.1f ips  → %s",
              label, c_ips, ruby_ips, verdict)
end
puts

payload = Corpus.log_file(mb: 1)
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
