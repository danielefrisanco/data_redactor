# verify_gem_refactor.rb — belt-and-suspenders gate for the scan_state_t refactor.
#
# Differentially tests the CURRENT gem matcher.c against a frozen BASELINE build
# (captured before the refactor) over a large randomized + edge corpus. The
# scan_state_t / per-thread-state refactor must not change a single emitted
# (pattern_id, start, length) event. Any diff is a hard failure.
#
# Usage:
#   1. Before refactoring, snapshot the baseline:
#        cp ext/data_redactor/{matcher,patterns}.c ext/data_redactor/{matcher,patterns,tags}.h /tmp/diffgate/
#   2. Build both .so's and run:
#        ruby prototypes/multi_pattern_matcher/verify_gem_refactor.rb
#
# The two builds export the same symbols (mm_init/mm_scan), so each is loaded
# into its own Fiddle::Handle and driven independently.
require "fiddle"

EXT      = File.expand_path("../../ext/data_redactor", __dir__)
REPO     = File.expand_path("../..", __dir__)
BASELINE = "/tmp/diffgate"
BUILD    = "/tmp/diffgate/build"
STRIDE   = 24  # sizeof(mm_match_t): int pad + size_t start + size_t length

# The frozen baseline is the matcher as it was BEFORE the per-thread scan-state
# refactor (parent of the "refactor: move matcher per-scan state ..." commit).
# /tmp is volatile, so re-materialise the snapshot from git if it's missing —
# the gate then works from a clean checkout with no manual setup.
BASELINE_REF = "3c3b386^"
BASELINE_FILES = %w[matcher.c patterns.c matcher.h patterns.h tags.h].freeze

require "fileutils"
FileUtils.mkdir_p(BUILD)

unless BASELINE_FILES.all? { |f| File.exist?(File.join(BASELINE, f)) }
  Dir.chdir(REPO) do
    BASELINE_FILES.each do |f|
      src = `git show #{BASELINE_REF}:ext/data_redactor/#{f}`
      abort "cannot materialise baseline #{f} from #{BASELINE_REF}" unless $?.success?
      File.write(File.join(BASELINE, f), src)
    end
  end
  warn "baseline re-materialised from git #{BASELINE_REF}"
end

# Rename the exported symbols per build so the two .so's never collide in the
# global symbol namespace (otherwise the second dlopen could resolve to the
# first's mm_scan and the diff would be vacuously equal).
def compile(srcdir, incdir, out, prefix)
  cmd = %W[
    cc -O2 -D_GNU_SOURCE -shared -fPIC
    -Dmm_init=#{prefix}_init -Dmm_scan=#{prefix}_scan
    -Dmm_resolve=#{prefix}_resolve -Dmm_pattern_name=#{prefix}_pname
    -Dmm_pattern_count=#{prefix}_pcount -Dmm_add=#{prefix}_add
    -Dmm_remove=#{prefix}_remove -Dmm_clear_custom=#{prefix}_clear
    -I#{incdir}
    #{srcdir}/matcher.c #{srcdir}/patterns.c
    -o #{out}
  ]
  system(*cmd) or abort "compile failed: #{cmd.join(' ')}"
end

# baseline: sources + headers both from /tmp/diffgate
compile(BASELINE, BASELINE, "#{BUILD}/baseline.so", "base")
# candidate: current gem sources + headers from the live ext dir
compile(EXT, EXT, "#{BUILD}/candidate.so", "cand")

def load_engine(path, prefix)
  h = Fiddle::Handle.new(path, Fiddle::Handle::RTLD_NOW)
  init = Fiddle::Function.new(h["#{prefix}_init"], [], Fiddle::TYPE_VOID)
  scan = Fiddle::Function.new(h["#{prefix}_scan"],
    [Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,   # input, len
     Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T,   # enable_bits, n_bits
     Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],  # out, max
    Fiddle::TYPE_SIZE_T)
  init.call
  scan
end

MAX = 8192
OUT = Fiddle::Pointer.malloc(STRIDE * MAX)
# all-enabled bits sized for built-ins (88); no customs in this gate
NBITS = 88
BITS  = Fiddle::Pointer.malloc(Fiddle::SIZEOF_INT * NBITS)
NBITS.times { |i| BITS[i * Fiddle::SIZEOF_INT, Fiddle::SIZEOF_INT] = [1].pack("l") }

BASE = load_engine("#{BUILD}/baseline.so", "base")
CAND = load_engine("#{BUILD}/candidate.so", "cand")

def events(scan, input)
  n = scan.call(input, input.bytesize, BITS, NBITS, OUT, MAX)
  n.times.map { |i|
    b = OUT + i * STRIDE
    [b[0, 4].unpack1("l"), b[8, 8].unpack1("Q"), b[16, 8].unpack1("Q")]
  }.sort
end

# ---- corpus: edge cases + randomized adjacency-heavy inputs --------------
TOKENS = %w[
  AKIAIOSFODNN7EXAMPLE sk_live_abcdefghijklmnopqrstuvwx
  DE89370400440532013000 NL91ABNA0417164300 123-45-6789
  mario.rossi@example.com 192.168.1.1 4111111111111111
  ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 12345678901 123456789
  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEFghij
]
SEPS = ["", " ", "\n", ",", ";", "-", ".", "/", "@", "  ", "x"]

edge = [
  "", "no secrets here at all", "\n\n\n",
  "12345678901", "x 12345678901", "id 123456789", "a12345678901a",
  "123-45-6789192.168.1.1", "192.168.1.1123-45-6789",
  "DE89370400440532013000NL91ABNA0417164300",
  "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678985121612345",
  ("A".b * 5000), ("0123456789" * 600),
]

rng = Random.new(1234)
random = Array.new(6000) {
  parts = Array.new(rng.rand(1..6)) { TOKENS.sample(random: rng) }
  parts.zip(Array.new(parts.size) { SEPS.sample(random: rng) }).flatten.join
}

corpus = edge + random

mismatches = 0
checked = 0
corpus.each_with_index do |inp, idx|
  a = events(BASE, inp)
  b = events(CAND, inp)
  checked += 1
  next if a == b
  mismatches += 1
  if mismatches <= 5
    puts "MISMATCH ##{idx}: #{inp.inspect[0, 80]}"
    puts "  only baseline:  #{(a - b).first(4).inspect}"
    puts "  only candidate: #{(b - a).first(4).inspect}"
  end
end

puts
if mismatches.zero?
  puts "PASS — candidate matcher byte-for-byte identical to baseline on #{checked} inputs"
  exit 0
else
  puts "FAIL — #{mismatches}/#{checked} inputs diverged"
  exit 1
end
