# bench_https_variants.rb — three-way A/B of the https:// optimization.
#
#   v19  : committed baseline (digit + IBAN merges; https patterns full-scan to 'h')
#   v19b : v19 + scan_https_group union pass (one memmem("https://") sweep)
#   v19c : v19 + start-anchored "https://" req_literal (memmem skip, no new path)
#
# Same payloads as bench_realistic. Reports ms/iter so the https win (if any) is
# isolated against an identical baseline.
require "fiddle"
DIR = __dir__
STRIDE = 24

def load_engine(name)
  h = Fiddle::Handle.new(File.join(DIR, "matcher#{name}.so"), Fiddle::Handle::RTLD_NOW)
  { init: Fiddle::Function.new(h["mm#{name}_init"], [], Fiddle::TYPE_VOID),
    scan: Fiddle::Function.new(h["mm#{name}_scan"],
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
       Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T) }
end

ENGINES = { "v19" => load_engine("19"), "v19b" => load_engine("19b"), "v19c" => load_engine("19c") }
BUF = Fiddle::Pointer.malloc(STRIDE * 200_000)

HITS = %w[AKIAIOSFODNN7EXAMPLE sk_live_abcdefghijklmnopqrstuvwx
          DE89370400440532013000 123-45-6789 mario.rossi@example.com
          192.168.1.1 4111111111111111] +
       ["https://hooks.slack.com/services/T01234567/B89ABCDEF/abcdefghijklmnopqrstuvwx",
        "https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/42"]
NOISE = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " \
         "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ")

def build_spaced(every, seed:)
  rng = Random.new(seed)
  chunk = NOISE * ((every / NOISE.bytesize) + 1)
  buf = +""
  until buf.bytesize >= 1_000_000
    buf << chunk[0, every] << HITS[rng.rand(HITS.size)] << "\n"
  end
  buf
end

payloads = {
  "sparse (1/5000B)" => build_spaced(5000, seed: 42),
  "medium (1/500B)"  => build_spaced(500,  seed: 7),
  "dense  (1/50B)"   => build_spaced(50,   seed: 99),
  "noise (no hits)"  => NOISE * 8000,
}

ITERS = 20
def time_scan(engine, payload)
  engine[:init].call
  3.times { engine[:scan].call(payload, payload.bytesize, BUF, 200_000) }  # warm
  best = Float::INFINITY
  ITERS.times do
    t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    engine[:scan].call(payload, payload.bytesize, BUF, 200_000)
    dt = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t) * 1000.0
    best = dt if dt < best
  end
  best
end

puts "https:// variant A/B — best of #{ITERS} iters, ~1 MB payloads (https-bearing HITS)"
printf "%-20s %10s %10s %10s   %s\n", "payload", "v19", "v19b", "v19c", "best"
puts "-" * 70
payloads.each do |name, pl|
  r = ENGINES.transform_values { |e| time_scan(e, pl) }
  best = r.min_by { |_, v| v }.first
  printf "%-20s %9.2f %9.2f %9.2f   %s\n", name, r["v19"], r["v19b"], r["v19c"], best
end
