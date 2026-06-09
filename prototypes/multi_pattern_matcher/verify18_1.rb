# verify18_1.rb — correctness check: v18.1 (anchor lowering) vs v15.1 reference.
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
V18_1 = load_engine("18_1")
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

payloads.each do |name, pl|
  a = matches(V15, pl)
  b = matches(V18_1, pl)
  ok = (a == b)
  all_ok &&= ok
  if ok
    puts "  %-14s OK   (%d matches)" % [name, a.size]
  else
    puts "  %-14s MISMATCH  v15=%d v18.1=%d" % [name, a.size, b.size]
    (a - b).first(3).each { |m| puts "    only v15:  #{m.inspect}" }
    (b - a).first(3).each { |m| puts "    only v18.1:#{m.inspect}" }
  end
end

s15 = stress_matches(V15, stress)
s181 = stress_matches(V18_1, stress)
if s15 == s181
  puts "  %-14s OK   (600 sequential scans identical)" % "stress-600"
else
  all_ok = false
  diff = s15.each_index.find { |i| s15[i] != s181[i] }
  puts "  %-14s MISMATCH at scan #%d" % ["stress-600", diff]
end

puts
puts all_ok ? "ALL CORRECTNESS CHECKS PASS — v18.1 == v15" : "FAILURES PRESENT"
exit all_ok ? 0 : 1
