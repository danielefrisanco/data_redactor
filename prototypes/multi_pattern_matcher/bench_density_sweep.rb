# bench_density_sweep.rb — continuous match-density sweep (paper §5.2, crossover figure).
#
# bench_realistic.rb measures four discrete densities (sparse/medium/dense/env).
# This script sweeps the SAME build_spaced() construction across a log-spaced range
# of strides, so the four published points become points on a continuous curve and
# we can see WHERE the AC+BM pre-filter pipeline (v7) stops paying off relative to
# the no-pipeline engines (plain PCRE2 JIT, v19). The crossover density is the
# sharpest single result in the paper.
#
# Construction, hit mix (HITS), seed, ~1 MB buffer, and per-engine init/free are
# identical to bench_realistic.rb — only the stride varies — so the curve is
# continuous with the existing published numbers, not a new measurement regime.
#
# Output: CSV to stdout (and --csv FILE), one row per (stride, engine):
#   stride,hits_per_kb,bytes,engine,ms_min,ms_median,ms_mean,iters,reps
# ms_min is the headline (least scheduler/GC noise); median/mean for rigor.
#
# Usage:
#   make matcher7.so matcher7_plain.so matcher7_plain_onig.so \
#        matcher15.so matcher18.so matcher18_1.so matcher19.so
#   bundle exec ruby bench_density_sweep.rb [--csv out.csv] [--iters N] [--reps M] [--quick]

require "fiddle"
require "benchmark"

PROTOTYPE_DIR = __dir__
GEM_LIB = File.expand_path("../../lib/data_redactor", PROTOTYPE_DIR)
require GEM_LIB

MATCH_STRIDE = 24  # sizeof(mm*_match_t)

# ---------- CLI -------------------------------------------------------------

csv_path = nil
iters    = 10     # timed scans per rep (matches bench_realistic ITERS)
reps     = 5      # reps per (stride, engine); we report min/median/mean across reps
quick    = false
skip     = []     # engine names to exclude (e.g. --skip glibc_baseline)
ARGV.each_with_index do |a, i|
  case a
  when "--csv"   then csv_path = ARGV[i + 1]
  when "--iters" then iters = Integer(ARGV[i + 1])
  when "--reps"  then reps  = Integer(ARGV[i + 1])
  when "--quick" then quick = true
  when "--skip"  then skip = ARGV[i + 1].to_s.split(",")
  end
end

# ---------- Load .so files (same set as bench_realistic + v7 pipeline) ------

def handle(name, flags = Fiddle::Handle::RTLD_NOW)
  Fiddle::Handle.new(File.join(PROTOTYPE_DIR, name), flags)
end

def scan_fn(h, sym)
  Fiddle::Function.new(h[sym],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
     Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
end

def void_fn(h, sym, args = [])
  Fiddle::Function.new(h[sym], args, Fiddle::TYPE_VOID)
end

# Engine descriptor: name => { init:, free:, scan: } closures.
# init/free take no logical args here (JIT flag baked in per engine below).
HG    = handle("matcher_glibc.so")       # plain glibc regexec (pre-v19 reproduction)
H7    = handle("matcher7.so")            # AC + BM + PCRE2 JIT  (the PIPELINE)
H7P   = handle("matcher7_plain.so")      # plain PCRE2 JIT      (no pipeline)
H7PO  = handle("matcher7_plain_onig.so", Fiddle::Handle::RTLD_NOW | 8) # Onigmo, RTLD_DEEPBIND
H15   = handle("matcher15.so")
H18   = handle("matcher18.so")
H18_1 = handle("matcher18_1.so")
H19   = handle("matcher19.so")

ENGINES = {}

# C-today (the gem's current glibc regexec extension) and pure-Ruby are special:
# they redact a String directly, no Fiddle buffer.
PURE_RUBY_REGEXES = DataRedactor::BUILTIN_PATTERN_SOURCES
  .zip(DataRedactor::BUILTIN_PATTERN_BOUNDARY)
  .map { |s, b| Regexp.new(b ? "(^|[^0-9A-Za-z])(#{s})([^0-9A-Za-z]|$)" : s) }
  .freeze

def pure_ruby_redact(input)
  PURE_RUBY_REGEXES.reduce(input) { |acc, re| acc.gsub(re, "[REDACTED]") }
end

# Fiddle-based engines share one output buffer.
BUF = Fiddle::Pointer.malloc(MATCH_STRIDE * 65536)

# Helper to register a Fiddle scan engine with a JIT-flagged init.
def reg_fiddle(name, h, prefix, init_args: [], init_vals: [])
  init = void_fn(h, "#{prefix}_init", init_args)
  free = void_fn(h, "#{prefix}_free")
  scan = scan_fn(h, "#{prefix}_scan")
  ENGINES[name] = {
    init: -> { init.call(*init_vals) },
    free: -> { free.call },
    scan: ->(payload) { scan.call(payload, payload.bytesize, BUF, 65536) },
  }
end

ENGINES["ruby"] = {
  init: -> {}, free: -> {}, scan: ->(payload) { pure_ruby_redact(payload) },
}
ENGINES["c_today"] = {
  init: -> {}, free: -> {}, scan: ->(payload) { DataRedactor.redact(payload) },
}
reg_fiddle("glibc_baseline", HG, "mmg")  # pre-v19 reproduction (plain regexec)
reg_fiddle("onigmo",   H7PO,  "mm7po")
reg_fiddle("pcre2jit", H7P,   "mm7p",  init_args: [Fiddle::TYPE_INT], init_vals: [1])
reg_fiddle("v7_pipeline", H7, "mm7",   init_args: [Fiddle::TYPE_INT], init_vals: [1])
reg_fiddle("v15",      H15,   "mm15")
reg_fiddle("v18",      H18,   "mm18")
reg_fiddle("v18_1",    H18_1, "mm18_1")
reg_fiddle("v19",      H19,   "mm19")

# Column order for human-readable progress; CSV carries the engine name per row.
ENGINE_ORDER = %w[ruby c_today glibc_baseline onigmo pcre2jit v7_pipeline v15 v18 v18_1 v19].freeze

# ---------- Payload builder (identical to bench_realistic build_spaced) ------

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

TARGET_BYTES = 1_000_000

def build_spaced(stride, seed: 42)
  rng = Random.new(seed)
  noise_chunk = NOISE_UNIT * ((stride / NOISE_UNIT.bytesize) + 1)
  buf = +""
  until buf.bytesize >= TARGET_BYTES
    buf << noise_chunk[0, stride]
    buf << HITS[rng.rand(HITS.size)]
    buf << "\n"
  end
  buf
end

# Approximate hits per KB for the x-axis: each emitted unit is (stride + ~avg_hit
# + 1) bytes and contains exactly one hit.
AVG_HIT = HITS.sum(&:bytesize).to_f / HITS.size
def hits_per_kb(stride)
  unit = stride + AVG_HIT + 1
  (1024.0 / unit).round(4)
end

# ---------- Stride schedule (log-spaced) ------------------------------------
#
# From near-100% density (stride 5, ~1 hit/30B) to very sparse (stride 10000,
# ~1 hit/10KB). Log spacing concentrates points where the curve bends. The four
# bench_realistic strides (50, 500, 5000) are included exactly so the published
# points land on the curve; env is a separate construction, handled in
# bench_realistic, not reproduced here (different builder).
def log_strides(lo, hi, n)
  return [lo, hi] if n < 2
  ratio = (hi.to_f / lo)**(1.0 / (n - 1))
  (0...n).map { |i| (lo * (ratio**i)).round }.uniq
end

STRIDES =
  if quick
    [50, 500, 5000].freeze
  else
    # Union of a log-spaced grid with the three published build_spaced strides.
    (log_strides(5, 10_000, 18) + [50, 500, 5000]).uniq.sort.freeze
  end

# ---------- Timing ----------------------------------------------------------
#
# For each (stride, engine): init once, run `iters` scans `reps` times, record the
# best (min), median, and mean of the per-rep ms/scan. min is the headline (least
# noise); median/mean document spread for the rigor pass.

def time_engine(engine, payload, iters, reps)
  per_rep = []
  reps.times do
    t = Benchmark.realtime { iters.times { engine[:scan].call(payload) } }
    per_rep << (t / iters * 1000.0)
  end
  per_rep.sort!
  mid = per_rep.length / 2
  median = per_rep.length.odd? ? per_rep[mid] : (per_rep[mid - 1] + per_rep[mid]) / 2.0
  { min: per_rep.first, median: median, mean: per_rep.sum / per_rep.length }
end

# ---------- Run -------------------------------------------------------------

rows = []
rows << %w[stride hits_per_kb bytes engine ms_min ms_median ms_mean iters reps]

run_order = ENGINE_ORDER.reject { |n| skip.include?(n) }
$stderr.puts "Density sweep — #{STRIDES.length} strides × #{run_order.length} engines"
$stderr.puts "iters=#{iters} reps=#{reps} target=#{TARGET_BYTES} bytes seed=42"
$stderr.puts "skipped: #{skip.empty? ? '(none)' : skip.join(', ')}"
$stderr.puts

STRIDES.each do |stride|
  payload = build_spaced(stride)
  hpk = hits_per_kb(stride)
  $stderr.printf("stride=%-6d (~%.3f hits/KB, %d bytes)\n", stride, hpk, payload.bytesize)

  run_order.each do |name|
    eng = ENGINES[name]
    eng[:init].call
    # one warmup scan (DFA cache warm, JIT path hot) before timing
    eng[:scan].call(payload)
    r = time_engine(eng, payload, iters, reps)
    eng[:free].call
    $stderr.printf("  %-12s  min=%7.2f  med=%7.2f  mean=%7.2f ms\n",
                   name, r[:min], r[:median], r[:mean])
    rows << [stride, hpk, payload.bytesize, name,
             r[:min].round(3), r[:median].round(3), r[:mean].round(3), iters, reps]
  end
  $stderr.puts
end

# ---------- Emit CSV --------------------------------------------------------

csv = rows.map { |r| r.join(",") }.join("\n") + "\n"
if csv_path
  File.write(csv_path, csv)
  $stderr.puts "wrote #{csv_path} (#{rows.length - 1} data rows)"
else
  print csv
end
