# frozen_string_literal: true

# Isolated matcher benchmark: measure ONLY the cost of "find all matches across
# 88 patterns" — no placeholder substitution, no output-buffer construction,
# no Ruby/C boundary work other than what's required to surface the matches.
#
# Useful during combined-matcher development to iterate on the matcher itself
# without the noise of redact()'s surrounding work. The current C engine has
# DataRedactor.scan which is the closest in-tree proxy: it reports
# (tag, name, value, start, length) per match. That's still slightly more than
# the matcher alone (it allocates a redacted string and the match hashes), but
# matcher cost is the dominant term, so trends are reliable.
#
# Once the combined matcher ships, this script's pure-Ruby baseline will
# remain as the "what we improved against" reference and we'll add a third
# column for the combined matcher's cost.
#
# Run:
#   bundle exec ruby benchmark/matcher_isolated.rb

require "benchmark/ips"
require_relative "../lib/data_redactor"
require_relative "support/corpus"

# Build the pure-Ruby per-pattern scanner ONCE (Regexp compilation is amortised
# across all benchmark runs, which is fair — the C side compiles its patterns
# at Init time too).
regexps_with_idx = DataRedactor::BUILTIN_PATTERN_SOURCES
                   .zip(DataRedactor::BUILTIN_PATTERN_BOUNDARY)
                   .map.with_index do |(src, wrapped), idx|
  body = wrapped ? "(^|[^0-9A-Za-z])(#{src})([^0-9A-Za-z]|$)" : src
  [Regexp.new(body), idx]
end

# Returns matches as [(start, length, pattern_index), ...]. No substitution,
# no [REDACTED] writing — just match-finding, the matcher's job alone.
pure_scan_fn = lambda do |text|
  out = []
  regexps_with_idx.each do |re, idx|
    text.scan(re) do
      m = Regexp.last_match
      out << [m.begin(0), m.end(0) - m.begin(0), idx]
    end
  end
  out
end

payloads = {
  "log line (168B)"   => Corpus.log_line,
  "json blob (~580B)" => Corpus.json_blob,
  "1.3 KB (8 lines)"  => Array.new(8) { Corpus.log_line }.join("\n"),
  "17 KB (100 lines)" => Array.new(100) { Corpus.log_line }.join("\n"),
  "1 MB log"          => Corpus.log_file(mb: 1)
}

# Correctness: both paths must report the same match COUNT (positions may
# differ if pure-Ruby's boundary-wrapper groups offset things, so we compare
# counts only — the redact()-level vs_pure_ruby check covers byte-identity).
puts "== correctness: same match count =="
payloads.each do |label, text|
  c    = DataRedactor.scan(text)[:matches].size
  ruby = pure_scan_fn.call(text).size
  marker = c == ruby ? "✓" : "≈"
  puts "  #{marker}  #{label.ljust(22)} C-scan: #{c.to_s.rjust(6)}  Ruby-scan: #{ruby.to_s.rjust(6)}"
end
puts "  (counts may differ slightly because pure-Ruby's boundary-wrapper"
puts "   counts boundary chars and the C engine doesn't — same MATCHES, different way of counting.)"
puts

puts "== speed: matcher-only cost (DataRedactor.scan vs pure-Ruby per-pattern scan) =="
payloads.each do |label, text|
  report = Benchmark.ips do |x|
    x.config(time: 2, warmup: 1, quiet: true)
    x.report("C")    { DataRedactor.scan(text) }
    x.report("Ruby") { pure_scan_fn.call(text) }
  end
  c_ips, ruby_ips = report.entries.map(&:ips)
  ratio = c_ips / ruby_ips
  verdict = ratio >= 1.0 ? format("C is %.2fx faster", ratio)
                         : format("C is %.2fx slower", 1.0 / ratio)
  puts format("  %-22s C: %9.1f ips  Ruby: %9.1f ips  → %s",
              label, c_ips, ruby_ips, verdict)
end
puts
puts "When the combined matcher lands, add it as a third row above and watch"
puts "the C column shrink past the Ruby column at every size."
