# bench_realistic.rb — head-to-head comparison across four realistic payload types.
#
# Previous benchmarks (bench7_compare.rb) used a single synthetic payload with
# one hit every ~5700 bytes (prototype noise loop). That under-represents real
# workloads. This script tests four payloads:
#
#   sparse  — 1 hit per 5000 bytes (clean logs, long documents)
#   medium  — 1 hit per 500 bytes  (mixed application logs)
#   dense   — 1 hit per 50 bytes   (redaction-heavy output)
#   env     — ~100% secrets        (.env files, config dumps)
#
# All engines run on the identical payload bytes (same Random seed per type).
#
# Usage:
#   make matcher4.so matcher7.so matcher7_plain.so matcher7_plain_onig.so matcher11.so matcher14.so matcher15.so
#   bundle exec ruby bench_realistic.rb

require "fiddle"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)
require GEM_LIB

MATCH_STRIDE = 24  # sizeof(mm4_match_t) = sizeof(mm7_match_t)

# ---------- Load .so files --------------------------------------------------

MM4_HANDLE   = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher4.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM7P_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher7_plain.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM7_HANDLE   = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher7.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM7PO_HANDLE = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher7_plain_onig.so"),
                                   Fiddle::Handle::RTLD_NOW | 8)  # RTLD_DEEPBIND
# v9 and v10 are INCORRECT (over-count vs the Ruby gsub reference — see
# research_log.md §5). Excluded from the benchmark. v11 (bytecode VM) is the
# current correct baseline.
# MM9_HANDLE   = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher9.so"),
#                                    Fiddle::Handle::RTLD_NOW)
# MM10_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher10.so"),
#                                    Fiddle::Handle::RTLD_NOW)
# v11 excluded from live benchmark — ~1000 ms/iter, already documented in
# research_log.md §5. Numbers: sparse=1101ms, medium=1110ms, dense=1395ms.
# MM11_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher11.so"),
#                                    Fiddle::Handle::RTLD_NOW)
MM14_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher14.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM15_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher15.so"),
                                   Fiddle::Handle::RTLD_NOW)
MM17_HANDLE  = Fiddle::Handle.new(File.join(PROTOTYPE_DIR, "matcher17.so"),
                                   Fiddle::Handle::RTLD_NOW)

module MM4
  Init  = Fiddle::Function.new(MM4_HANDLE["mm4_init"],      [], Fiddle::TYPE_VOID)
  Free  = Fiddle::Function.new(MM4_HANDLE["mm4_free"],      [], Fiddle::TYPE_VOID)
  Scan  = Fiddle::Function.new(MM4_HANDLE["mm4_scan"],
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
             Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  Scan41 = Fiddle::Function.new(MM4_HANDLE["mm4_scan_v41"],
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
             Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  Scan42 = Fiddle::Function.new(MM4_HANDLE["mm4_scan_v42"],
            [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
             Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init              = Init.call
  def self.free              = Free.call
  def self.scan(inp, buf)    = Scan.call(inp, inp.bytesize, buf, 65536)
  def self.scan41(inp, buf)  = Scan41.call(inp, inp.bytesize, buf, 65536)
  def self.scan42(inp, buf)  = Scan42.call(inp, inp.bytesize, buf, 65536)
end

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

# v9 / v10 disabled — incorrect (see research_log.md §5).

module MM14
  Init = Fiddle::Function.new(MM14_HANDLE["mm14_init"], [], Fiddle::TYPE_VOID)
  Free = Fiddle::Function.new(MM14_HANDLE["mm14_free"], [], Fiddle::TYPE_VOID)
  Scan = Fiddle::Function.new(MM14_HANDLE["mm14_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init = Init.call
  def self.free = Free.call
  def self.scan(inp, buf) = Scan.call(inp, inp.bytesize, buf, 65536)
end

module MM15
  Init = Fiddle::Function.new(MM15_HANDLE["mm15_init"], [], Fiddle::TYPE_VOID)
  Free = Fiddle::Function.new(MM15_HANDLE["mm15_free"], [], Fiddle::TYPE_VOID)
  Scan = Fiddle::Function.new(MM15_HANDLE["mm15_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init = Init.call
  def self.free = Free.call
  def self.scan(inp, buf) = Scan.call(inp, inp.bytesize, buf, 65536)
end

module MM17
  Init = Fiddle::Function.new(MM17_HANDLE["mm17_init"], [], Fiddle::TYPE_VOID)
  Free = Fiddle::Function.new(MM17_HANDLE["mm17_free"], [], Fiddle::TYPE_VOID)
  Scan = Fiddle::Function.new(MM17_HANDLE["mm17_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  def self.init = Init.call
  def self.free = Free.call
  def self.scan(inp, buf) = Scan.call(inp, inp.bytesize, buf, 65536)
end

# ---------- Payload builders ------------------------------------------------

HITS = [
  "AKIAIOSFODNN7EXAMPLE",
  "sk_live_abcdefghijklmnopqrstuvwx",
  "DE89370400440532013000",
  "123-45-6789",
  "mario.rossi@example.com",
  "192.168.1.1",
  "4111111111111111",
  "-----BEGIN RSA PRIVATE KEY-----",
].freeze

NOISE_UNIT = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " \
              "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ").freeze

def build_spaced(hits_every_n_bytes, seed: 42)
  rng  = Random.new(seed)
  noise_chunk = NOISE_UNIT * ((hits_every_n_bytes / NOISE_UNIT.bytesize) + 1)
  buf  = +""
  until buf.bytesize >= 1_000_000
    buf << noise_chunk[0, hits_every_n_bytes]
    buf << HITS[rng.rand(HITS.size)]
    buf << "\n"
  end
  buf
end

def build_env(seed: 42)
  rng = Random.new(seed)
  lines = [
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "STRIPE_SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwx",
    "DATABASE_URL=postgres://user:s3cr3tpassword@db.example.com/prod",
    "GITHUB_TOKEN=ghp_#{"a" * 36}",
    "SENTRY_DSN=https://abcdef1234567890abcdef1234567890@o123.ingest.sentry.io/456",
    "ANTHROPIC_API_KEY=sk-ant-api03-#{"a" * 90}",
    "EMAIL_FROM=admin@example.com",
    "INTERNAL_IP=10.0.0.1",
    "SMTP_PASSWORD=hunter2supersecret",
    "CREDIT_CARD=4111111111111111",
  ].freeze
  buf = +""
  until buf.bytesize >= 1_000_000
    buf << lines[rng.rand(lines.size)] << "\n"
  end
  buf
end

PAYLOADS = {
  "sparse  (1 hit/5000B)" => build_spaced(5000),
  "medium  (1 hit/500B) " => build_spaced(500),
  "dense   (1 hit/50B)  " => build_spaced(50),
  "env     (all secrets)" => build_env,
}.freeze

# ---------- Pure-Ruby baseline ----------------------------------------------

PURE_RUBY_REGEXES = DataRedactor::BUILTIN_PATTERN_SOURCES
  .zip(DataRedactor::BUILTIN_PATTERN_BOUNDARY)
  .map { |s, b| Regexp.new(b ? "(^|[^0-9A-Za-z])(#{s})([^0-9A-Za-z]|$)" : s) }
  .freeze

def pure_ruby_redact(input)
  PURE_RUBY_REGEXES.reduce(input) { |acc, re| acc.gsub(re, "[REDACTED]") }
end

# ---------- Run benchmarks --------------------------------------------------

ITERS = 10
buf   = Fiddle::Pointer.malloc(MATCH_STRIDE * 65536)

MM7P.init(1); MM7P.free   # warm up PCRE2 JIT compile
MM7.init(1);  MM7.free    # warm up AC+BM+PCRE2 JIT compile
MM7PO.init;   MM7PO.free  # warm up Onigmo compile
MM14.init;    MM14.free   # warm up v14 (literal + first-byte filter)
MM15.init;    MM15.free   # warm up v15.1 (iterative addthread + O(1) accept)
MM17.init;    MM17.free   # warm up v17 (precomputed initial thread list)

puts "Realistic payload benchmark — #{ITERS} iterations per engine per payload"
puts "All payloads: ~1 MB, fixed seed 42"
puts
puts "%-26s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s" % [
  "", "Ruby", "C-today", "Onigmo", "PCRE2JIT", "v7JIT", "v14flt", "v15.1", "v17"
]
puts "-" * 99

# v4 NFA excluded from live benchmark — results already in research_log.md §8.5.
# Crashes on env (1600 ms/iter), and DFA cache cold-start is noisy on shorter payloads.

def run_engine(label)
  $stderr.print "  #{label}..."; $stderr.flush
  t = Benchmark.realtime { yield }
  $stderr.puts " done (#{(t * 1000).round(0)} ms total)"
  t
end

PAYLOADS.each do |name, payload|
  $stderr.puts "\n[#{name.strip}]"
  t = {}

  t[:ruby] = run_engine("ruby")   { ITERS.times { pure_ruby_redact(payload) } }
  t[:c]    = run_engine("C-today") { ITERS.times { DataRedactor.redact(payload) } }

  MM7PO.init
  t[:onig] = run_engine("onig") { ITERS.times { MM7PO.scan(payload, buf) } }
  MM7PO.free

  MM7P.init(1)
  t[:pcre2jit] = run_engine("pcre2jit") { ITERS.times { MM7P.scan(payload, buf) } }
  MM7P.free

  MM7.init(1)
  t[:v7jit] = run_engine("v7jit") { ITERS.times { MM7.scan(payload, buf) } }
  MM7.free

  MM14.init
  t[:v14] = run_engine("v14") { ITERS.times { MM14.scan(payload, buf) } }
  MM14.free

  MM15.init
  t[:v15] = run_engine("v15") { ITERS.times { MM15.scan(payload, buf) } }
  MM15.free

  MM17.init
  t[:v16] = run_engine("v17") { ITERS.times { MM17.scan(payload, buf) } }
  MM17.free

  ms = t.transform_values { |v| v.nil? ? nil : (v / ITERS * 1000).round(1) }

  puts "%-26s  %7.1f  %7.1f  %7.1f  %7.1f  %7.1f  %7.1f  %7.1f  %7.1f" % [
    name,
    ms[:ruby], ms[:c], ms[:onig], ms[:pcre2jit], ms[:v7jit], ms[:v14], ms[:v15], ms[:v16]
  ]
end

puts
puts "All times in ms/iter. Lower is better."
puts
puts "%-26s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s" % [
  "× over pure-Ruby", "Ruby", "C-today", "Onigmo", "PCRE2JIT", "v7JIT", "v14flt", "v15.1", "v17"
]
puts "-" * 99

PAYLOADS.each do |name, payload|
  $stderr.puts "\n[#{name.strip}] ratios"
  t = {}
  t[:ruby] = run_engine("ruby")    { ITERS.times { pure_ruby_redact(payload) } }
  t[:c]    = run_engine("C-today") { ITERS.times { DataRedactor.redact(payload) } }

  MM7PO.init
  t[:onig] = run_engine("onig") { ITERS.times { MM7PO.scan(payload, buf) } }
  MM7PO.free

  MM7P.init(1)
  t[:pcre2jit] = run_engine("pcre2jit") { ITERS.times { MM7P.scan(payload, buf) } }
  MM7P.free

  MM7.init(1)
  t[:v7jit] = run_engine("v7jit") { ITERS.times { MM7.scan(payload, buf) } }
  MM7.free

  MM14.init
  t[:v14] = run_engine("v14") { ITERS.times { MM14.scan(payload, buf) } }
  MM14.free

  MM15.init
  t[:v15] = run_engine("v15") { ITERS.times { MM15.scan(payload, buf) } }
  MM15.free

  MM17.init
  t[:v16] = run_engine("v17") { ITERS.times { MM17.scan(payload, buf) } }
  MM17.free

  base = t[:ruby]
  ratios = t.transform_values { |v| v.nil? ? nil : (base / v).round(2) }

  puts "%-26s  %8.2f  %8.2f  %8.2f  %8.2f  %8.2f  %8.2f  %8.2f  %8.2f" % [
    name,
    ratios[:ruby], ratios[:c], ratios[:onig], ratios[:pcre2jit],
    ratios[:v7jit], ratios[:v14], ratios[:v15], ratios[:v16]
  ]
end
