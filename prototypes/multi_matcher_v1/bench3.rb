# bench3.rb — Option A: 88-pattern AC + Onigmo (libonig-dev, no Ruby VM).
#
# Usage:
#   make matcher3.so
#   bundle exec ruby bench3.rb verify    # correctness vs DataRedactor.scan
#   bundle exec ruby bench3.rb bench     # benchmark
#   bundle exec ruby bench3.rb           # both

require "fiddle"
require "fiddle/import"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)

require GEM_LIB

ALL_PATTERN_NAMES = DataRedactor.pattern_names.freeze

# ---------- FFI binding -----------------------------------------------------
#
# Load matcher3.so with RTLD_DEEPBIND so that its onig_* calls resolve to
# system libonig (libonig.so.5) rather than being interposed by libruby's
# statically-linked Onigmo, which has a different OnigRegion struct layout.

SO_PATH = File.join(PROTOTYPE_DIR, "matcher3.so")

# RTLD_DEEPBIND (8) makes matcher3.so resolve its own onig_* symbols against
# system libonig.so.5, not libruby's statically-linked Onigmo. The two have
# different OnigRegion struct layouts; without DEEPBIND the region->beg[] reads
# return garbage.
MM3_HANDLE = Fiddle::Handle.new(SO_PATH, Fiddle::Handle::RTLD_NOW | 8)

module MM3
  MM3_Init = Fiddle::Function.new(MM3_HANDLE["mm3_init"], [], Fiddle::TYPE_VOID)
  MM3_Free = Fiddle::Function.new(MM3_HANDLE["mm3_free"], [], Fiddle::TYPE_VOID)
  MM3_Scan = Fiddle::Function.new(
    MM3_HANDLE["mm3_scan"],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],
    Fiddle::TYPE_SIZE_T)

  def self.mm3_init = MM3_Init.call
  def self.mm3_free = MM3_Free.call
  def self.mm3_scan(input, len, buf, max) = MM3_Scan.call(input, len, buf, max)
end

# struct mm3_match_t layout (64-bit):
#   int    pattern_id  @ 0  (4 bytes)
#   pad                @ 4  (4 bytes)
#   size_t start       @ 8  (8 bytes)
#   size_t length      @ 16 (8 bytes)
# Total: 24 bytes
MATCH_STRIDE = 24

def mm3_scan_ruby(input)
  MM3.mm3_init
  max = 65536
  buf = Fiddle::Pointer.malloc(MATCH_STRIDE * max, Fiddle::RUBY_FREE)
  n = MM3.mm3_scan(input, input.bytesize, buf, max)
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
  "key=AKIAIOSFODNN7EXAMPLE end",
  "stripe sk_live_abcdefghijklmnopqrstuvwx end",
  "github ghp_abcdefghijklmnopqrstuvwxyz123456 end",
  "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc end",
  "grafana eyJrIjoidGVzdGtleWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MCJ9 end",
  "anthropic sk-ant-api03-#{"a" * 90} end",
  "iban DE89370400440532013000 end",
  "iban FR7612345678901234567890156 end",
  "ssn 123-45-6789 end",
  "pesel 12345678901 end",
  "swiss 756.1234.5678.90 end",
  "email foo@bar.com end",
  "ip 10.0.0.1 end",
  "cc 4111111111111111 end",
  "pem -----BEGIN RSA PRIVATE KEY----- end",
  "gpg -----BEGIN PGP PRIVATE KEY BLOCK----- end",
  "plain text nothing here",
].freeze

def verify
  ok = true
  VERIFY_CASES.each_with_index do |s, i|
    proto = mm3_scan_ruby(s).map { |m| [m[:name], m[:start], m[:length]] }.sort
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
  MM3.mm3_free
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
  pure_ruby_regexes = DataRedactor::BUILTIN_PATTERN_SOURCES.map { |s| Regexp.new(s) }

  payload = build_1mb_payload
  puts "Payload: #{payload.bytesize} bytes, #{ALL_PATTERN_NAMES.size} patterns"
  puts

  iters = 10

  t_proto = Benchmark.realtime { iters.times { mm3_scan_ruby(payload) } }
  t_pure  = Benchmark.realtime { iters.times { pure_ruby_redact(payload, pure_ruby_regexes) } }
  t_dr    = Benchmark.realtime { iters.times { DataRedactor.scan(payload) } }

  puts "Pure-Ruby gsub  (88 patterns): #{(t_pure  / iters * 1000).round(1)} ms/iter"
  puts "DataRedactor today (88 pats): #{(t_dr    / iters * 1000).round(1)} ms/iter"
  puts "Prototype v3 (AC+Onigmo 88): #{(t_proto / iters * 1000).round(1)} ms/iter"
  puts
  ratio = t_pure / t_proto
  puts "v3 vs pure-Ruby : #{ratio.round(2)}× #{ratio >= 1.0 ? "(beats Ruby!)" : "(slower than Ruby)"}"
  puts "v3 vs today's C : #{(t_dr / t_proto).round(2)}×"
ensure
  MM3.mm3_free
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
