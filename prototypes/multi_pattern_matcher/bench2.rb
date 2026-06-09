# bench2.rb — Option B: 88-pattern AC + glibc regexec prototype.
#
# Usage:
#   make matcher2.so
#   bundle exec ruby bench2.rb verify    # correctness vs DataRedactor.scan
#   bundle exec ruby bench2.rb bench     # benchmark
#   bundle exec ruby bench2.rb           # both

require "fiddle"
require "fiddle/import"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)

require GEM_LIB

# All 88 pattern names, in the same order as patterns_generated.h.
# Sourced from DataRedactor.pattern_names so they stay in sync.
ALL_PATTERN_NAMES = DataRedactor.pattern_names.freeze

# ---------- FFI binding -----------------------------------------------------

module MM88
  extend Fiddle::Importer
  dlload File.join(PROTOTYPE_DIR, "matcher2.so")

  extern "void mm88_init(void)"
  extern "void mm88_free(void)"
  extern "size_t mm88_scan(const char*, size_t, void*, size_t)"
end

# struct mm88_match_t layout (64-bit):
#   int    pattern_id  @ 0  (4 bytes)
#   pad                @ 4  (4 bytes)
#   size_t start       @ 8  (8 bytes)
#   size_t length      @ 16 (8 bytes)
# Total: 24 bytes
MATCH_STRIDE = 24

def mm88_scan_ruby(input)
  MM88.mm88_init
  max = 65536
  buf = Fiddle::Pointer.malloc(MATCH_STRIDE * max, Fiddle::RUBY_FREE)
  n = MM88.mm88_scan(input, input.bytesize, buf, max)
  n.times.map do |i|
    base = i * MATCH_STRIDE
    pid    = buf[base,      4].unpack1("l")
    start  = buf[base + 8,  8].unpack1("Q")
    length = buf[base + 16, 8].unpack1("Q")
    { name: ALL_PATTERN_NAMES[pid], start: start, length: length }
  end
end

# ---------- Correctness check -----------------------------------------------

VERIFY_CASES = [
  # prefixed tokens
  "key=AKIAIOSFODNN7EXAMPLE end",
  "stripe sk_live_abcdefghijklmnopqrstuvwx end",
  "github ghp_abcdefghijklmnopqrstuvwxyz123456 end",
  "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc end",
  "grafana eyJrIjoidGVzdGtleWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MCJ9 end",
  "anthropic sk-ant-api03-#{"a" * 90} end",
  # IBANs
  "iban DE89370400440532013000 end",
  "iban FR7612345678901234567890156 end",
  # boundary-wrapped
  "ssn 123-45-6789 end",
  "pesel 12345678901 end",
  "swiss 756.1234.5678.90 end",
  # always-candidate
  "email foo@bar.com end",
  "ip 10.0.0.1 end",
  "cc 4111111111111111 end",
  # PEM
  "pem -----BEGIN RSA PRIVATE KEY----- end",
  "gpg -----BEGIN PGP PRIVATE KEY BLOCK----- end",
  # clean
  "plain text nothing here",
].freeze

def verify
  ok = true
  VERIFY_CASES.each_with_index do |s, i|
      proto = mm88_scan_ruby(s + "\0").map { |m| [m[:name], m[:start], m[:length]] }.sort
    dr    = DataRedactor.scan(s)[:matches].map { |m| [m[:name], m[:start], m[:length]] }.sort

    missing = dr - proto
    if missing.empty?
      extras = proto - dr
      tag = extras.empty? ? "OK" : "OK (+#{extras.size} extras/overlaps)"
      puts "[#{i}] #{tag}: #{s[0, 70]}"
    else
      ok = false
      puts "[#{i}] MISSING: #{s[0, 70]}"
      puts "    proto  : #{proto.inspect}"
      puts "    dr     : #{dr.inspect}"
      puts "    missing: #{missing.inspect}"
    end
  end
  ok
ensure
  MM88.mm88_free
end

# ---------- Benchmark -------------------------------------------------------

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
  # Build pure-Ruby regex equivalents from the gem's pattern sources
  pure_ruby_regexes = DataRedactor::BUILTIN_PATTERN_SOURCES.map { |s| Regexp.new(s) }

  payload     = build_1mb_payload
  payload_nul = payload + "\0"   # NUL-terminated copy for prototype (regexec needs it)
  puts "Payload: #{payload.bytesize} bytes, #{ALL_PATTERN_NAMES.size} patterns"
  puts

  iters = 10

  t_proto = Benchmark.realtime { iters.times { mm88_scan_ruby(payload_nul) } }
  t_pure  = Benchmark.realtime { iters.times { pure_ruby_redact(payload, pure_ruby_regexes) } }
  t_dr    = Benchmark.realtime { iters.times { DataRedactor.scan(payload) } }

  puts "Pure-Ruby gsub (88 patterns): #{(t_pure  / iters * 1000).round(1)} ms/iter"
  puts "DataRedactor today (88 pats): #{(t_dr    / iters * 1000).round(1)} ms/iter"
  puts "Prototype v2 (AC+regexec 88): #{(t_proto / iters * 1000).round(1)} ms/iter"
  puts
  ratio = t_pure / t_proto
  puts "v2 vs pure-Ruby : #{ratio.round(2)}× #{ratio >= 1.0 ? "(beats Ruby!)" : "(slower than Ruby)"}"
  puts "v2 vs today's C : #{(t_dr / t_proto).round(2)}×"
ensure
  MM88.mm88_free
end

# ---------- Entrypoint ------------------------------------------------------

case ARGV[0]
when "verify" then exit(verify ? 0 : 1)
when "bench"  then bench
else
  ok = verify
  puts
  bench
  exit(ok ? 0 : 1)
end
