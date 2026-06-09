# bench7.rb — v7: 88-pattern AC + BM + PCRE2 (interpreter and JIT).
#
# Usage:
#   make matcher7.so
#   bundle exec ruby bench7.rb verify    # correctness vs DataRedactor.scan
#   bundle exec ruby bench7.rb bench     # benchmark (all three: no-JIT, JIT, vs v5)
#   bundle exec ruby bench7.rb           # both

require "fiddle"
require "fiddle/import"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)

require GEM_LIB

ALL_PATTERN_NAMES = DataRedactor.pattern_names.freeze

# ---------- FFI binding -----------------------------------------------------
#
# matcher7.so links only against libpcre2, no Onigmo — no RTLD_DEEPBIND needed.

SO_PATH = File.join(PROTOTYPE_DIR, "matcher7.so")
MM7_HANDLE = Fiddle::Handle.new(SO_PATH, Fiddle::Handle::RTLD_NOW)

module MM7
  MM7_Init = Fiddle::Function.new(MM7_HANDLE["mm7_init"],
               [Fiddle::TYPE_INT], Fiddle::TYPE_VOID)
  MM7_Free = Fiddle::Function.new(MM7_HANDLE["mm7_free"], [], Fiddle::TYPE_VOID)
  MM7_Scan = Fiddle::Function.new(
    MM7_HANDLE["mm7_scan"],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],
    Fiddle::TYPE_SIZE_T)

  def self.mm7_init(use_jit) = MM7_Init.call(use_jit)
  def self.mm7_free          = MM7_Free.call
  def self.mm7_scan(input, len, buf, max) = MM7_Scan.call(input, len, buf, max)
end

# struct mm7_match_t layout (64-bit):
#   int    pattern_id  @ 0  (4 bytes)
#   pad                @ 4  (4 bytes)
#   size_t start       @ 8  (8 bytes)
#   size_t length      @ 16 (8 bytes)
# Total: 24 bytes
MATCH_STRIDE = 24

def mm7_scan_ruby(input, use_jit: 0)
  MM7.mm7_init(use_jit)
  max = 65536
  buf = Fiddle::Pointer.malloc(MATCH_STRIDE * max, Fiddle::RUBY_FREE)
  n = MM7.mm7_scan(input, input.bytesize, buf, max)
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

def verify(use_jit: 0)
  label = use_jit == 1 ? "JIT" : "no-JIT"
  puts "=== Correctness check (PCRE2 #{label}) ==="
  ok = true
  VERIFY_CASES.each_with_index do |s, i|
    proto = mm7_scan_ruby(s, use_jit: use_jit)
              .map { |m| [m[:name], m[:start], m[:length]] }.sort
    dr    = DataRedactor.scan(s)[:matches]
              .map { |m| [m[:name], m[:start], m[:length]] }.sort

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
  MM7.mm7_free
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

  t_pure = Benchmark.realtime { iters.times { pure_ruby_redact(payload, pure_ruby_regexes) } }
  t_dr   = Benchmark.realtime { iters.times { DataRedactor.scan(payload) } }

  MM7.mm7_init(0)
  t_v7_nojit = Benchmark.realtime { iters.times { MM7.mm7_scan(payload, payload.bytesize, Fiddle::Pointer.malloc(MATCH_STRIDE * 65536), 65536) } }
  MM7.mm7_free

  MM7.mm7_init(1)
  t_v7_jit = Benchmark.realtime { iters.times { MM7.mm7_scan(payload, payload.bytesize, Fiddle::Pointer.malloc(MATCH_STRIDE * 65536), 65536) } }
  MM7.mm7_free

  puts "Pure-Ruby gsub      (88 pats): #{(t_pure     / iters * 1000).round(1)} ms/iter  (baseline)"
  puts "DataRedactor today  (88 pats): #{(t_dr       / iters * 1000).round(1)} ms/iter"
  puts
  puts "v7 PCRE2 no-JIT (AC+BM+PCRE2): #{(t_v7_nojit / iters * 1000).round(1)} ms/iter  #{(t_pure / t_v7_nojit).round(2)}× over pure-Ruby"
  puts "v7 PCRE2 JIT    (AC+BM+PCRE2): #{(t_v7_jit   / iters * 1000).round(1)} ms/iter  #{(t_pure / t_v7_jit).round(2)}× over pure-Ruby"
  puts
  puts "JIT speedup over interpreter: #{(t_v7_nojit / t_v7_jit).round(2)}×"
  puts "v7-JIT vs today's C         : #{(t_dr / t_v7_jit).round(2)}×"
end

# ---------- Entrypoint ------------------------------------------------------

case ARGV[0]
when "verify"
  ok_nojit = verify(use_jit: 0)
  puts
  ok_jit = verify(use_jit: 1)
  exit((ok_nojit && ok_jit) ? 0 : 1)
when "bench"
  bench
else
  ok_nojit = verify(use_jit: 0)
  puts
  ok_jit = verify(use_jit: 1)
  puts
  bench
  exit((ok_nojit && ok_jit) ? 0 : 1)
end
