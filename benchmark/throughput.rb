# frozen_string_literal: true

# Throughput of DataRedactor.redact on representative payloads, plus redact_deep
# and scan for comparison. Run from the repo root after `rake compile`:
#
#   ruby benchmark/throughput.rb

require "benchmark/ips"
require_relative "../lib/data_redactor"
require_relative "support/corpus"

log_line  = Corpus.log_line
json_blob = Corpus.json_blob
json_hash = Corpus.json_hash
file_1mb  = Corpus.log_file(mb: 1)
file_10mb = Corpus.log_file(mb: 10)

payloads = {
  "redact log line"   => log_line,
  "redact json blob"  => json_blob,
  "redact 1MB log"    => file_1mb,
  "redact 10MB log"   => file_10mb
}

puts "== DataRedactor.redact throughput =="
payloads.each do |label, text|
  report = Benchmark.ips do |x|
    x.config(time: 3, warmup: 1)
    x.report(label) { DataRedactor.redact(text) }
  end
  entry = report.entries.first
  mbps  = Corpus.mb_per_s(text.bytesize, 1.0 / entry.ips)
  puts format("  %-20s %10.1f ips  %8.1f MB/s  (%d bytes)",
              label, entry.ips, mbps, text.bytesize)
end

puts
puts "== redact_deep / scan =="
Benchmark.ips do |x|
  x.config(time: 3, warmup: 1)
  x.report("redact_deep json hash") { DataRedactor.redact_deep(json_hash) }
  x.report("scan log line")         { DataRedactor.scan(log_line) }
  x.compare!
end
