# bench7_compare.rb — head-to-head: plain PCRE2 vs AC+BM+PCRE2, with and without JIT.
#
# All four variants run on the exact same payload (same Random seed) so
# numbers are directly comparable. This is the publication-quality comparison.
#
# Usage:
#   make matcher7.so matcher7_plain.so
#   bundle exec ruby bench7_compare.rb

require "fiddle"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)
require GEM_LIB

ALL_PATTERN_NAMES = DataRedactor.pattern_names.freeze
MATCH_STRIDE = 24  # sizeof(mm7_match_t): 4 + 4pad + 8 + 8

# ---------- Load both .so files ---------------------------------------------

MM7P_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher7_plain.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM7_HANDLE   = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher7.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM7PO_HANDLE = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher7_plain_onig.so"),
                                   Fiddle::Handle::RTLD_NOW | 8)  # RTLD_DEEPBIND

module MM7P
  Init = Fiddle::Function.new(MM7P_HANDLE["mm7p_init"], [Fiddle::TYPE_INT], Fiddle::TYPE_VOID)
  Free = Fiddle::Function.new(MM7P_HANDLE["mm7p_free"], [], Fiddle::TYPE_VOID)
  Scan = Fiddle::Function.new(MM7P_HANDLE["mm7p_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init(jit) = Init.call(jit)
  def self.free      = Free.call
  def self.scan(inp, buf) = Scan.call(inp, inp.bytesize, buf, 65536)
end

module MM7
  Init = Fiddle::Function.new(MM7_HANDLE["mm7_init"], [Fiddle::TYPE_INT], Fiddle::TYPE_VOID)
  Free = Fiddle::Function.new(MM7_HANDLE["mm7_free"], [], Fiddle::TYPE_VOID)
  Scan = Fiddle::Function.new(MM7_HANDLE["mm7_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init(jit) = Init.call(jit)
  def self.free      = Free.call
  def self.scan(inp, buf) = Scan.call(inp, inp.bytesize, buf, 65536)
end

module MM7PO
  Init = Fiddle::Function.new(MM7PO_HANDLE["mm7po_init"], [], Fiddle::TYPE_VOID)
  Free = Fiddle::Function.new(MM7PO_HANDLE["mm7po_free"], [], Fiddle::TYPE_VOID)
  Scan = Fiddle::Function.new(MM7PO_HANDLE["mm7po_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init = Init.call
  def self.free = Free.call
  def self.scan(inp, buf) = Scan.call(inp, inp.bytesize, buf, 65536)
end

# ---------- Payload (fixed seed for reproducibility) -----------------------

def build_payload(seed: 42)
  rng   = Random.new(seed)
  noise = "lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100
  hits  = [
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
    buf << hits[rng.rand(hits.size)]
    buf << "\n"
  end
  buf
end

def pure_ruby_redact(input, regexes)
  out = input.dup
  regexes.each { |re| out = out.gsub(re, "[REDACTED]") }
  out
end

# ---------- Benchmark -------------------------------------------------------

ITERS   = 10
payload = build_payload(seed: 42)
buf     = Fiddle::Pointer.malloc(MATCH_STRIDE * 65536)

pure_ruby_regexes = DataRedactor::BUILTIN_PATTERN_SOURCES.map { |s| Regexp.new(s) }

puts "Payload: #{payload.bytesize} bytes | #{ALL_PATTERN_NAMES.size} patterns | #{ITERS} iterations"
puts "Random seed: 42 (fixed)"
puts

t_pure = Benchmark.realtime { ITERS.times { pure_ruby_redact(payload, pure_ruby_regexes) } }
t_dr   = Benchmark.realtime { ITERS.times { DataRedactor.scan(payload) } }

MM7P.init(0)
t_plain_nojit = Benchmark.realtime { ITERS.times { MM7P.scan(payload, buf) } }
MM7P.free

MM7P.init(1)
t_plain_jit = Benchmark.realtime { ITERS.times { MM7P.scan(payload, buf) } }
MM7P.free

MM7.init(0)
t_v7_nojit = Benchmark.realtime { ITERS.times { MM7.scan(payload, buf) } }
MM7.free

MM7.init(1)
t_v7_jit = Benchmark.realtime { ITERS.times { MM7.scan(payload, buf) } }
MM7.free

MM7PO.init
t_plain_onig = Benchmark.realtime { ITERS.times { MM7PO.scan(payload, buf) } }
MM7PO.free

base = t_pure / ITERS * 1000

def fmt(t, iters, base_ms)
  ms    = t / iters * 1000
  ratio = (base_ms / ms).round(2)
  dir   = ratio >= 1.0 ? "faster" : "slower"
  "#{ms.round(1).to_s.rjust(7)} ms/iter   #{ratio.to_s.rjust(5)}× #{dir} than pure-Ruby"
end

puts "%-42s %s" % ["Pure-Ruby gsub (88 patterns):",      fmt(t_pure,        ITERS, base)]
puts "%-42s %s" % ["DataRedactor today (glibc):",         fmt(t_dr,          ITERS, base)]
puts
puts "%-42s %s" % ["Plain Onigmo sequential:",             fmt(t_plain_onig,  ITERS, base)]
puts "%-42s %s" % ["Plain PCRE2 no-JIT sequential:",       fmt(t_plain_nojit, ITERS, base)]
puts "%-42s %s" % ["Plain PCRE2 JIT sequential:",          fmt(t_plain_jit,   ITERS, base)]
puts
puts "%-42s %s" % ["v5-equiv: AC+BM+Onigmo (from v5 run):", "  ~108.0 ms/iter    1.34× faster than pure-Ruby  (separate run, same day)"]
puts "%-42s %s" % ["v7 AC+BM+PCRE2 no-JIT:",               fmt(t_v7_nojit,   ITERS, base)]
puts "%-42s %s" % ["v7 AC+BM+PCRE2 JIT:",                   fmt(t_v7_jit,    ITERS, base)]
puts
puts "--- Key ratios ---"
puts "JIT speedup (plain PCRE2):          #{(t_plain_nojit / t_plain_jit).round(2)}×"
puts "JIT speedup (AC+BM):                #{(t_v7_nojit    / t_v7_jit).round(2)}×"
puts "AC+BM overhead on plain JIT:        #{(t_v7_jit   / t_plain_jit).round(2)}×  (>1 = pipeline slower than plain)"
puts "AC+BM overhead on plain no-JIT:     #{(t_v7_nojit / t_plain_nojit).round(2)}×"
puts "Plain Onigmo vs plain PCRE2 JIT:    #{(t_plain_onig / t_plain_jit).round(2)}×  (Onigmo is Nx slower)"
