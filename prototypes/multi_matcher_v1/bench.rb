# Prototype driver: loads matcher.so via Fiddle, exposes mm_scan to Ruby,
# verifies correctness vs DataRedactor.scan, runs Slice 4 benchmark.
#
# Usage:
#   make matcher.so
#   ruby bench.rb verify     # Slice 3 correctness check
#   ruby bench.rb bench      # Slice 4 benchmark
#   ruby bench.rb            # both

require "fiddle"
require "fiddle/import"
require "benchmark"

PROTOTYPE_DIR = __dir__

# The 10 prototype patterns — in the SAME order as PATTERNS[] in matcher.c.
# Names match ext/data_redactor/patterns.c entries so we can filter
# DataRedactor.scan via `only:`.
PATTERN_NAMES = %w[
  aws_access_key_id
  email
  ipv4
  credit_card
  slack_webhook_url
  stripe_secret_key
  iban_de
  polish_pesel
  pem_private_key
  gpg_private_key
].freeze

# Pure-Ruby regex equivalents (same source strings as matcher.c).
PURE_RUBY_REGEXES = [
  /(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z2-7]{16}/,
  /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,
  /(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/,
  /(4[0-9]{15}|4[0-9]{12}|5[1-5][0-9]{14}|6011[0-9]{12}|65[0-9]{14}|3[47][0-9]{13}|3[068][0-9]{11}|35[0-9]{14})/,
  %r{https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}},
  /sk_live_[0-9a-zA-Z]{24}/,
  /DE[0-9]{2}[0-9]{18}/,
  /[0-9]{11}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
].freeze

# ---------- FFI binding -----------------------------------------------------

module MM
  extend Fiddle::Importer
  dlload File.join(PROTOTYPE_DIR, "matcher.so")

  # struct mm_match_t { int pattern_id; size_t start; size_t length; }
  # Fiddle padding: int = 4, size_t = 8 on x86_64, struct is padded.
  # We'll read by offset directly via Fiddle::Pointer to avoid struct quirks.

  extern "void mm_init(void)"
  extern "void mm_free(void)"
  extern "size_t mm_scan(const char*, size_t, void*, size_t)"
end

MATCH_SIZE = Fiddle::SIZEOF_INT + 8 + (Fiddle::SIZEOF_VOIDP == 8 ? 8 + 8 : 4 + 4)
# Actual layout with natural alignment on 64-bit:
#   int pattern_id    @ 0  (4 bytes)
#   padding           @ 4  (4 bytes)
#   size_t start      @ 8  (8 bytes)
#   size_t length     @ 16 (8 bytes)
# Total: 24 bytes
MATCH_STRIDE = 24

def mm_scan_ruby(input)
  MM.mm_init
  max = 4096
  buf = Fiddle::Pointer.malloc(MATCH_STRIDE * max, Fiddle::RUBY_FREE)
  n = MM.mm_scan(input, input.bytesize, buf, max)
  matches = []
  n.times do |i|
    base = i * MATCH_STRIDE
    pid    = buf[base, 4].unpack1("l")
    start  = buf[base + 8, 8].unpack1("Q")
    length = buf[base + 16, 8].unpack1("Q")
    matches << { name: PATTERN_NAMES[pid], start: start, length: length }
  end
  matches
end

# ---------- Slice 3: correctness check vs DataRedactor.scan ----------------

def verify
  require File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)

  cases = [
    "key=AKIAIOSFODNN7EXAMPLE end",
    "stripe sk_live_abcdefghijklmnopqrstuvwx end",
    "iban DE89370400440532013000 end",
    "slack https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/abcdefghijklmnopqrstuvwx",
    "pem -----BEGIN RSA PRIVATE KEY----- end",
    "gpg -----BEGIN PGP PRIVATE KEY BLOCK----- end",
    "email foo@bar.com ip 10.0.0.1 cc 4111111111111111 pesel 12345678901 end",
    "plain text with no secrets at all",
  ]

  ok = true
  cases.each_with_index do |s, i|
    proto = mm_scan_ruby(s).map { |m| [m[:name], m[:start], m[:length]] }.sort
    dr_full = DataRedactor.scan(s, only: PATTERN_NAMES)
    dr = dr_full[:matches].map { |m| [m[:name], m[:start], m[:length]] }.sort

    # DataRedactor resolves overlaps (a longer IBAN suppresses inner pesel /
     # credit_card hits); the prototype reports raw matches. So we only require
     # the prototype to be a SUPERSET of DataRedactor's results — every real
     # match must be found, extras from overlap noise are acceptable per the
     # plan's "out of scope: overlap resolution" note.
    missing = dr - proto
    if missing.empty?
      extras = proto - dr
      tag = extras.empty? ? "OK" : "OK (+#{extras.size} unresolved overlap)"
      puts "[#{i}] #{tag} (#{proto.size} matches): #{s[0, 60]}"
    else
      ok = false
      puts "[#{i}] MISSING from prototype: #{s}"
      puts "    proto:   #{proto.inspect}"
      puts "    dr:      #{dr.inspect}"
      puts "    missing: #{missing.inspect}"
    end
  end
  ok
ensure
  MM.mm_free
end

# ---------- Slice 4: benchmark ---------------------------------------------

def build_1mb_payload
  # Mirror the bench/payloads composition: mostly innocuous text, some
  # patterns sprinkled in. Target ~1 MB.
  noise = "lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100
  hits = [
    "key=AKIAIOSFODNN7EXAMPLE",
    "stripe sk_live_abcdefghijklmnopqrstuvwx",
    "iban DE89370400440532013000",
    "slack https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/abcdefghijklmnopqrstuvwx",
    "pem -----BEGIN RSA PRIVATE KEY-----",
    "gpg -----BEGIN PGP PRIVATE KEY BLOCK-----",
    "email foo@bar.com",
    "ip 10.0.0.1",
    "cc 4111111111111111",
    "pesel 12345678901",
  ]
  buf = +""
  until buf.bytesize >= 1_000_000
    buf << noise
    buf << hits.sample
    buf << "\n"
  end
  buf
end

def pure_ruby_redact(input)
  out = input.dup
  PURE_RUBY_REGEXES.each { |re| out = out.gsub(re, "[REDACTED]") }
  out
end

def bench
  require File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)

  payload = build_1mb_payload
  puts "Payload size: #{payload.bytesize} bytes"
  puts

  iters = 10

  t_proto = Benchmark.realtime do
    iters.times { mm_scan_ruby(payload) }
  end

  t_pure = Benchmark.realtime do
    iters.times { pure_ruby_redact(payload) }
  end

  t_dr = Benchmark.realtime do
    iters.times { DataRedactor.scan(payload, only: PATTERN_NAMES) }
  end

  puts "Pure-Ruby gsub loop : #{(t_pure / iters * 1000).round(2)} ms/iter"
  puts "DataRedactor (today): #{(t_dr   / iters * 1000).round(2)} ms/iter"
  puts "Prototype (AC + rex): #{(t_proto/ iters * 1000).round(2)} ms/iter"
  puts
  ratio = t_pure / t_proto
  puts "Prototype vs pure-Ruby: #{ratio.round(2)}× #{ratio >= 3 ? '(>=3x — GREEN, proceed to Phase 1+2)' : '(below 3x kill threshold)'}"
  puts "Prototype vs today    : #{(t_dr / t_proto).round(2)}×"
ensure
  MM.mm_free
end

# ---------- Entrypoint ------------------------------------------------------

case ARGV[0]
when "verify"
  exit(verify ? 0 : 1)
when "bench"
  bench
else
  ok = verify
  puts
  bench
  exit(ok ? 0 : 1)
end
