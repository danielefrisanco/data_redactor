# verify18.rb — exhaustive correctness check: v18 (lazy DFA) must produce the
# EXACT same match set as v15.1 (proven correct against the gsub reference) on
# every payload. Compares (pattern_id, start, length) triples, not just counts.
#
#   make matcher15.so matcher18.so
#   bundle exec ruby verify18.rb

require "fiddle"

DIR = __dir__
STRIDE = 24  # sizeof(mm_match_t): int + size_t + size_t, padded

def load_engine(name)
  h = Fiddle::Handle.new(File.join(DIR, "matcher#{name}.so"), Fiddle::Handle::RTLD_NOW)
  init = Fiddle::Function.new(h["mm#{name}_init"], [], Fiddle::TYPE_VOID)
  free = Fiddle::Function.new(h["mm#{name}_free"], [], Fiddle::TYPE_VOID)
  scan = Fiddle::Function.new(h["mm#{name}_scan"],
           [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
            Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T)
  [init, free, scan]
end

V15 = load_engine("15")
V18 = load_engine("18")

BUF = Fiddle::Pointer.malloc(STRIDE * 200_000)

def matches(engine, input)
  init, free, scan = engine
  init.call
  n = scan.call(input, input.bytesize, BUF, 200_000)
  out = []
  n.times do |i|
    base = BUF + i * STRIDE
    pid = base[0, 4].unpack1("l")
    st  = base[8, 8].unpack1("Q")
    ln  = base[16, 8].unpack1("Q")
    out << [pid, st, ln]
  end
  free.call
  out.sort
end

# ---- Payloads: smoke cases + realistic + adversarial -----------------------

HITS = [
  "AKIAIOSFODNN7EXAMPLE", "sk_live_abcdefghijklmnopqrstuvwx",
  "DE89370400440532013000", "123-45-6789", "mario.rossi@example.com",
  "192.168.1.1", "4111111111111111", "-----BEGIN RSA PRIVATE KEY-----",
].freeze
NOISE = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " \
         "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ").freeze

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
  "smoke-jwt"    => "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "smoke-email"  => "contact us at user@example.com please",
  "smoke-ssn"    => "ssn: 123-45-6789 end",
  "smoke-uri"    => "db url postgres://user:s3cr3tpw@db.example.com/prod here",
  "smoke-bearer" => "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789 ok",
  "sparse"       => build_spaced(5000, seed: 42),
  "medium"       => build_spaced(500,  seed: 7),
  "dense"        => build_spaced(50,   seed: 99),
  "noise"        => NOISE * 8000,
}

# 600-scan sequential stress (catches cross-call state bugs): interleave small
# strings so g_gen / seen[] reuse paths are exercised between scans.
stress = []
600.times { |i| stress << HITS[i % HITS.size] + " noise " + (i.to_s) }

all_ok = true
payloads.each do |name, pl|
  a = matches(V15, pl)
  b = matches(V18, pl)
  ok = (a == b)
  all_ok &&= ok
  if ok
    puts "  %-14s OK   (%d matches)" % [name, a.size]
  else
    puts "  %-14s MISMATCH  v15=%d v18=%d" % [name, a.size, b.size]
    only15 = (a - b).first(5)
    only18 = (b - a).first(5)
    puts "      only in v15: #{only15.inspect}" unless only15.empty?
    puts "      only in v18: #{only18.inspect}" unless only18.empty?
  end
end

# stress: scan each sequentially through the SAME engine instance lifecycle.
# We compare the full concatenated match streams.
def stress_matches(engine, inputs)
  init, free, scan = engine
  init.call
  acc = []
  inputs.each do |inp|
    n = scan.call(inp, inp.bytesize, BUF, 200_000)
    row = []
    n.times do |i|
      base = BUF + i * STRIDE
      row << [base[0,4].unpack1("l"), base[8,8].unpack1("Q"), base[16,8].unpack1("Q")]
    end
    acc << row.sort
  end
  free.call
  acc
end

s15 = stress_matches(V15, stress)
s18 = stress_matches(V18, stress)
if s15 == s18
  puts "  %-14s OK   (600 sequential scans identical)" % "stress-600"
else
  all_ok = false
  diff = s15.zip(s18).each_index.find { |i| s15[i] != s18[i] }
  puts "  %-14s MISMATCH at scan #%d: v15=%p v18=%p" % ["stress-600", diff, s15[diff], s18[diff]]
end

puts
puts all_ok ? "ALL CORRECTNESS CHECKS PASS — v18 == v15" : "FAILURES PRESENT"
exit(all_ok ? 0 : 1)
