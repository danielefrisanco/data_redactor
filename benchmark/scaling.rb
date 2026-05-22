# frozen_string_literal: true

# Runtime vs input size. If redaction is linear, MB/s stays roughly flat and
# the per-row time ratio tracks the size ratio. Run from the repo root after
# `rake compile`:
#
#   ruby benchmark/scaling.rb

require "benchmark"
require_relative "../lib/data_redactor"
require_relative "support/corpus"

# (label, byte size) — small sizes built from a sliced 1MB buffer, large ones
# from log_file directly.
base_1mb = Corpus.log_file(mb: 1)
sizes = [
  ["1 KB",   1 * 1024],
  ["10 KB",  10 * 1024],
  ["100 KB", 100 * 1024],
  ["1 MB",   1024 * 1024],
  ["10 MB",  10 * 1024 * 1024],
  ["50 MB",  50 * 1024 * 1024]
]

payloads = sizes.map do |label, bytes|
  text = bytes <= base_1mb.bytesize ? base_1mb.byteslice(0, bytes) : Corpus.log_file(mb: bytes / (1024 * 1024))
  [label, text]
end

puts "== DataRedactor.redact scaling =="
puts format("  %-8s %12s %10s %10s", "size", "time (ms)", "MB/s", "time ratio")

prev_time = nil
payloads.each do |label, text|
  # Warm up once, then take the best of 3 runs.
  DataRedactor.redact(text)
  time = 3.times.map { Benchmark.realtime { DataRedactor.redact(text) } }.min
  mbps = Corpus.mb_per_s(text.bytesize, time)
  ratio = prev_time ? format("%.1fx", time / prev_time) : "-"
  puts format("  %-8s %12.3f %10.1f %10s", label, time * 1000, mbps, ratio)
  prev_time = time
end

puts
puts "  Linear scaling: each 10x size step should show ~10x time and flat MB/s."
