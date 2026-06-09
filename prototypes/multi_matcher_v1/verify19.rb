# verify19.rb — correctness check: v19 (merged pure-digit group) vs v15.1 reference.
#
# v15 is the ground truth (full position-sensitive NFA). v19 must equal it exactly,
# INCLUDING the boundary-wrapped digit patterns at buffer edges (^ at pos 0, $ at end)
# — cases v18.1's DFA path silently dropped because addthread_dfa cannot fire EOL.
# The digit-edge payloads below exercise precisely those.
require "fiddle"
DIR = __dir__
STRIDE = 24

def load_engine(name)
  h = Fiddle::Handle.new(File.join(DIR, "matcher#{name}.so"), Fiddle::Handle::RTLD_NOW)
  [ Fiddle::Function.new(h["mm#{name}_init"], [], Fiddle::TYPE_VOID),
    Fiddle::Function.new(h["mm#{name}_free"], [], Fiddle::TYPE_VOID),
    Fiddle::Function.new(h["mm#{name}_scan"],
      [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,
       Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T], Fiddle::TYPE_SIZE_T) ]
end

V15   = load_engine("15")
V19 = load_engine("19")
BUF   = Fiddle::Pointer.malloc(STRIDE * 200_000)

def matches(engine, input)
  init, free, scan = engine
  init.call
  n = scan.call(input, input.bytesize, BUF, 200_000)
  out = n.times.map { |i|
    base = BUF + i * STRIDE
    [base[0,4].unpack1("l"), base[8,8].unpack1("Q"), base[16,8].unpack1("Q")]
  }.sort
  free.call
  out
end

HITS = %w[AKIAIOSFODNN7EXAMPLE sk_live_abcdefghijklmnopqrstuvwx
          DE89370400440532013000 123-45-6789 mario.rossi@example.com
          192.168.1.1 4111111111111111 -----BEGIN\ RSA\ PRIVATE\ KEY-----]
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
  "smoke-jwt"    => "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "smoke-email"  => "contact us at user@example.com please",
  "smoke-ssn"    => "ssn: 123-45-6789 end",
  "smoke-uri"    => "db url postgres://user:s3cr3tpw@db.example.com/prod here",
  "smoke-bearer" => "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789 ok",
  "sparse"       => build_spaced(5000, seed: 42),
  "medium"       => build_spaced(500,  seed: 7),
  "dense"        => build_spaced(50,   seed: 99),
  "noise"        => NOISE * 8000,
  # digit-group edge cases (buffer-edge boundaries, letter-abutting, run lengths)
  "digit-eos11"  => "12345678901",            # 11-run, ^ and $ both edges
  "digit-bos11"  => "x 12345678901",          # leading boundary, $ at end
  "digit-eos9"   => "id 123456789",           # 9-run ending at $
  "digit-letter" => "a12345678901a",          # letters abut → no match
  "digit-mix"    => "n=12345678 m=123456789012 z=1234567890123 end",
  "digit-runs"   => (["12345678901", "123456789", "12345678", "1234567",
                      "123456789012", "1234567890123"].join(" ")),
  "digit-nl"     => "12345678901\n123456789\n12345678",
  # IBAN union-pass edge cases (buffer end, back-to-back, mixed countries, near-miss prefix)
  "iban-eob"     => "pay to DE89370400440532013000",            # ends at buffer end
  "iban-b2b"     => "DE89370400440532013000 NL91ABNA0417164300",# two different countries adjacent
  "iban-same"    => "DE89370400440532013000 DE89370400440532013000", # same pattern twice (non-overlap cursor)
  "iban-mixed"   => "x FR1420041010050500013M02606 y PT50000201231234567890154 z",
  "iban-nearmis" => "DEXX370400440532013000 and AB12345678901234",# bad check digits / unknown country
  "iban-bulk"    => (["DE89370400440532013000", "AT611904300234573201",
                      "BE68539007547034", "ES9121000418450200051332"].join("  ")),
}

def stress_matches(engine, inputs)
  init, free, scan = engine
  init.call
  acc = inputs.map { |inp|
    n = scan.call(inp, inp.bytesize, BUF, 200_000)
    n.times.map { |i|
      base = BUF + i * STRIDE
      [base[0,4].unpack1("l"), base[8,8].unpack1("Q"), base[16,8].unpack1("Q")]
    }.sort
  }
  free.call
  acc
end

stress = 600.times.map { |i| HITS[i % HITS.size] + " noise " + i.to_s }
all_ok = true

# Pure-digit members handled by v19's merged pass. Differences on NON-member
# patterns whose span ends exactly at end-of-buffer are the pre-existing v18.1
# v19.1: the v18.1 EOL-at-buffer-end bug is fixed — scan_one now NFA-falls-back
# in the final ~max_len bytes for $-anchored patterns, so v19 must equal v15
# EXACTLY on every payload, including the buffer-edge digit/ID cases below. Any
# diff is a hard failure (no KNOWN escape hatch — that would mask a regression).
payloads.each do |name, pl|
  a = matches(V15, pl)
  b = matches(V19, pl)
  if a == b
    puts "  %-14s OK   (%d matches)" % [name, a.size]
    next
  end
  only_v15 = a - b
  only_v19 = b - a
  all_ok = false
  puts "  %-14s MISMATCH  v15=%d v19=%d" % [name, a.size, b.size]
  only_v15.first(3).each { |m| puts "    only v15:  #{m.inspect}" }
  only_v19.first(3).each { |m| puts "    only v19:#{m.inspect}" }
end

s15 = stress_matches(V15, stress)
s181 = stress_matches(V19, stress)
if s15 == s181
  puts "  %-14s OK   (600 sequential scans identical)" % "stress-600"
else
  all_ok = false
  diff = s15.each_index.find { |i| s15[i] != s181[i] }
  puts "  %-14s MISMATCH at scan #%d" % ["stress-600", diff]
end

puts
puts all_ok ?
  "v19 CORRECTNESS PASS — byte-for-byte equal to v15 on all payloads (EOL fixed)" :
  "FAILURES PRESENT"
exit all_ok ? 0 : 1
