# bench4.rb — Option D: Thompson NFA + lazy DFA cache, zero dependencies.
#
# NOTE on correctness: The lazy-DFA scan reports every pattern that can match
# starting at each position, including very short prefix matches caused by
# unbounded quantifiers (`+`, `*`).  This produces many false positives
# versus DataRedactor.scan.  The `verify` step documents the gap — the
# prototype is a throughput measurement, not a drop-in replacement.
#
# Usage:
#   make matcher4.so
#   bundle exec ruby bench4.rb verify    # throughput check + match counts
#   bundle exec ruby bench4.rb bench     # benchmark vs v3 and pure-Ruby
#   bundle exec ruby bench4.rb           # both

require "fiddle"
require "fiddle/import"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)

require GEM_LIB

ALL_PATTERN_NAMES = DataRedactor.pattern_names.freeze

# ---------- FFI binding -------------------------------------------------------

SO_PATH = File.join(PROTOTYPE_DIR, "matcher4.so")

# No RTLD_DEEPBIND needed — matcher4 has zero external regex dependencies.
MM4_HANDLE = Fiddle::Handle.new(SO_PATH, Fiddle::Handle::RTLD_NOW)

module MM4
  MM4_Init = Fiddle::Function.new(MM4_HANDLE["mm4_init"], [], Fiddle::TYPE_VOID)
  MM4_Free = Fiddle::Function.new(MM4_HANDLE["mm4_free"], [], Fiddle::TYPE_VOID)
  MM4_Scan = Fiddle::Function.new(
    MM4_HANDLE["mm4_scan"],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],
    Fiddle::TYPE_SIZE_T)
  # Single-pass DFA walk (no per-position restart, no output buffer).
  # Measures raw DFA throughput — the upper bound for a single-pass automaton.
  MM4_Walk = Fiddle::Function.new(
    MM4_HANDLE["mm4_walk"],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],
    Fiddle::TYPE_SIZE_T)

  def self.mm4_init = MM4_Init.call
  def self.mm4_free = MM4_Free.call
  def self.mm4_scan(input, len, buf, max) = MM4_Scan.call(input, len, buf, max)
  def self.mm4_walk(input, len) = MM4_Walk.call(input, len)
end

# struct mm4_match_t layout (64-bit): identical to mm3_match_t
#   int    pattern_id  @ 0  (4 bytes)
#   pad                @ 4  (4 bytes)
#   size_t start       @ 8  (8 bytes)
#   size_t length      @ 16 (8 bytes)
# Total: 24 bytes
MATCH_STRIDE = 24

def mm4_scan_ruby(input)
  MM4.mm4_init
  max = 65536
  buf = Fiddle::Pointer.malloc(MATCH_STRIDE * max, Fiddle::RUBY_FREE)
  n = MM4.mm4_scan(input, input.bytesize, buf, max)
  n.times.map do |i|
    base = i * MATCH_STRIDE
    pid    = buf[base,      4].unpack1("l")
    start  = buf[base + 8,  8].unpack1("Q")
    length = buf[base + 16, 8].unpack1("Q")
    { name: ALL_PATTERN_NAMES[pid], start: start, length: length }
  end
end

# ---------- Verify (throughput probe, not correctness gate) -------------------

VERIFY_CASES = [
  "key=AKIAIOSFODNN7EXAMPLE end",
  "stripe sk_live_abcdefghijklmnopqrstuvwx end",
  "github ghp_abcdefghijklmnopqrstuvwxyz123456 end",
  "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc end",
  "grafana eyJrIjoidGVzdGtleWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MCJ9 end",
  "anthropic sk-ant-api03-#{"a" * 90} end",
  "iban DE89370400440532013000 end",
  "ssn 123-45-6789 end",
  "pesel 12345678901 end",
  "email foo@bar.com end",
  "ip 10.0.0.1 end",
  "cc 4111111111111111 end",
  "pem -----BEGIN RSA PRIVATE KEY----- end",
  "plain text nothing here",
].freeze

def verify
  puts "=== Verify: checking match coverage vs DataRedactor.scan ==="
  puts "(v4 may report additional/shorter overlapping matches — that's expected)"
  puts

  all_ok = true
  VERIFY_CASES.each_with_index do |s, i|
    proto_raw = mm4_scan_ruby(s)
    proto     = proto_raw.map { |m| [m[:name], m[:start], m[:length]] }
    dr        = DataRedactor.scan(s)[:matches].map { |m| [m[:name], m[:start], m[:length]] }

    dr_names = dr.map(&:first).uniq
    # A match counts as covered if v4 found ANY match for the same pattern name
    proto_names = proto.map(&:first).uniq

    missing = dr_names - proto_names
    extras  = proto_names - dr_names

    if missing.empty?
      puts "[#{i}] COVERED (#{proto.size} v4 matches, #{dr.size} dr matches): #{s[0, 60]}"
      puts "       extras: #{extras.join(", ")}" unless extras.empty?
    else
      all_ok = false
      puts "[#{i}] MISSING patterns: #{missing.join(", ")}"
      puts "       input: #{s[0, 60]}"
      puts "       v4 patterns: #{proto_names.inspect}"
      puts "       dr patterns: #{dr_names.inspect}"
    end
  end
  puts
  all_ok
ensure
  MM4.mm4_free
end

# ---------- Benchmark ---------------------------------------------------------

def build_1mb_payload
  noise = "lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100
  hits = [
    "key=AKIAIOSFODNN7EXAMPLE",
    "stripe sk_live_abcdefghijklmnopqrstuvwx",
    "iban DE89370400440532013000",
    "ssn 123-45-6789",
    "pesel 12345678901",
    "email foo@bar.com",
    "ip 10.0.0.1",
    "cc 4111111111111111",
    "pem -----BEGIN RSA PRIVATE KEY-----",
    "gpg -----BEGIN PGP PRIVATE KEY BLOCK-----",
  ]
  buf = +""
  until buf.bytesize >= 1_000_000
    buf << noise
    buf << hits.sample
    buf << "\n"
  end
  buf
end

def pure_ruby_redact(input, regexes)
  out = input.dup
  regexes.each { |re| out = out.gsub(re, "[REDACTED]") }
  out
end

def bench
  MM4.mm4_init

  pure_ruby_regexes = DataRedactor::BUILTIN_PATTERN_SOURCES.map { |s| Regexp.new(s) }

  payload = build_1mb_payload
  puts "Payload: #{payload.bytesize} bytes, #{ALL_PATTERN_NAMES.size} patterns"
  puts

  iters = 10

  # mm4_walk: single-pass DFA, no per-position restart, measures raw DFA throughput.
  t_walk  = Benchmark.realtime { iters.times { MM4.mm4_walk(payload, payload.bytesize) } }
  t_pure  = Benchmark.realtime { iters.times { pure_ruby_redact(payload, pure_ruby_regexes) } }
  t_dr    = Benchmark.realtime { iters.times { DataRedactor.scan(payload) } }

  puts "Pure-Ruby gsub  (88 patterns):                     #{(t_pure / iters * 1000).round(1)} ms/iter"
  puts "DataRedactor today (88 pats, C+regexec):           #{(t_dr   / iters * 1000).round(1)} ms/iter"
  puts "Prototype v4 single-pass DFA walk (upper bound):   #{(t_walk / iters * 1000).round(1)} ms/iter"
  puts
  ratio_ruby = t_pure / t_walk
  ratio_dr   = t_dr   / t_walk
  puts "v4 DFA walk vs pure-Ruby : #{ratio_ruby.round(2)}× #{ratio_ruby >= 1.0 ? "(faster than Ruby!)" : "(slower than Ruby)"}"
  puts "v4 DFA walk vs today's C : #{ratio_dr.round(2)}×"
  puts
  puts "NOTE: mm4_walk is the upper-bound measurement — it does one DFA pass"
  puts "  without per-position restart or output buffering. A correct implementation"
  puts "  (with leftmost-longest semantics per pattern) would be somewhat slower."
ensure
  MM4.mm4_free
end

# ---------- Entrypoint --------------------------------------------------------

case ARGV[0]
when "verify" then exit(verify ? 0 : 1)
when "bench"  then bench
else
  verify
  puts
  bench
end
