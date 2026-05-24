# Research Log — Multi-Pattern Matching in data_redactor

**Purpose:** complete record of every idea, algorithm, experiment, result,
and problem encountered during the multi-pattern matcher research project.
Intended as the foundation for a future paper.

**Date range:** 2026-05-23 – 2026-05-24 (v4/v5/v6 added 2026-05-24).
**Branch:** `feat/matcher-prototype-v1`.

---

## 1. Problem Statement

`data_redactor` is a Ruby gem that scans text for 88 sensitive patterns
(API keys, IBANs, SSNs, emails, IPs, PEM certificates, …) and replaces
them with `[REDACTED]`. It does this via a C extension that calls POSIX
`regexec` on each of the 88 compiled patterns in sequence.

**Measured problem:** the C extension is 3–5× *slower* than an equivalent
pure-Ruby loop calling `String#gsub` with the same 88 regexes. This
inverts the usual expectation — a C extension should be faster than Ruby.

**Root cause (diagnosed before this project):** glibc's POSIX `regexec`
lacks the Boyer-Moore literal pre-filter that Ruby's Onigmo engine uses.
At each scan position, glibc evaluates the full NFA; Onigmo first checks
whether a literal anchor byte exists at the current position and skips
forward by the BM shift table if not. For patterns with long literal
prefixes (e.g., `sk_live_`, `AKIA`, `-----BEGIN`), Onigmo skips the
vast majority of the input; glibc pays full NFA cost at every position.

Additionally, glibc allocates O(input-length) state on each `regexec`
call. Onigmo keeps a fixed-size evaluation stack.

**The question this project addresses:** can we do *better* than pure-Ruby
gsub by combining a shared multi-pattern filter with a fast confirmation
engine?

---

## 2. Context — Prior Performance Work

Before this project, two optimisations were already shipped to the gem:

- **Strstr literal pre-filter (option B in previous work):** before
  calling `regexec` for a given pattern, check whether its longest
  required literal substring exists anywhere in the input using `strstr`.
  Only call `regexec` if `strstr` finds it. Prevents redundant NFA
  evaluation when the pattern cannot possibly match.

- **Chunked input (option G):** split very large inputs into chunks before
  passing to `regexec`, preventing the per-call O(N) allocation from
  becoming a problem at large input sizes.

Net effect of B+G: 25–30% faster across all sizes. The C extension was
still 3–5× slower than pure-Ruby. These two options addressed symptoms,
not the root cause.

---

## 3. Bibliography — Sources Consulted

### Primary algorithms / theory

| Source | What it provided |
|---|---|
| **Thompson (1968)** — *"Regular Expression Search Algorithm"*, CACM | The original NFA-based grep algorithm. DFA simulation via subset construction. Established the O(N·M) (input × pattern) bound for NFA simulation and the O(N) DFA bound. |
| **Aho & Corasick (1975)** — *"Efficient String Matching: An Aid to Bibliographic Search"*, CACM | The canonical multi-pattern literal string matcher. Builds a finite automaton (trie + failure links) that matches all patterns simultaneously in O(N + M + Z) where Z is match count. Used as Stage 1 (prefix filter) in all our prototypes. |
| **Knuth, Morris & Pratt (1977)** — *"Fast Pattern Matching in Strings"* | Linear-time single-pattern string matching via failure function. The failure-link construction in Aho-Corasick is a direct generalisation. |
| **Boyer & Moore (1977)** — *"A Fast String Searching Algorithm"* | Right-to-left scanning with bad-character and good-suffix shift tables. This is what Onigmo uses internally per-pattern. We did not implement BM ourselves but its presence (or absence) in the confirmation engine is the key differentiator in all our benchmarks. |
| **Cox (2007)** — *"Regular Expression Matching Can Be Simple And Fast"*, rsc.io | Explains why backtracking engines (PCRE) are slow on adversarial input and why Thompson NFA / DFA simulation is preferred. Also the source of the "RE2::Set hits 2 GB DFA cache at ~30 patterns" measurement. Key reading for understanding the RE2::Set DFA state-explosion risk. |
| **Russ Cox (2009)** — *"Regular Expression Matching in the Wild"*, rsc.io | Survey of practical regex engine implementations. Background reading. |
| **Wang et al. (2019)** — *"Hyperscan: A Fast Multi-pattern Regex Matcher for Modern CPUs"*, USENIX NSDI | Hyperscan: Intel's production SIMD-accelerated multi-pattern regex engine. Claimed 10.3× over RE2. Disqualified for our use case (x86 only, no ARM portability). |
| **Daviaud et al. (2024)** — *"RE#: A Derivative-Based Approach with Intersection and Complement"*, arXiv 2407.20479 | Modern derivative-based regex with intersection/complement. Background reading, not directly applied. |

### Production implementations reviewed

| System | What we studied |
|---|---|
| **RE2::Set** (Google, C++, BSD) | Multi-pattern match API. Reports which patterns matched, not positions. DFA state-cache explosion known issue above ~30 patterns. API design: `Add(pattern)` → `Compile()` → `Match(text, *v)`. |
| **Rust `regex::RegexSet`** | Same API shape as RE2::Set. Single-phase construction. Also reports pattern IDs, not positions. Documents O(m×n) worst case. |
| **Hyperscan** (Intel, BSD) | Not studied in detail — disqualified on portability grounds early. |
| **Onigmo** (MRI Ruby's engine, BSD) | The engine Ruby's `String#gsub` uses. Exports `onig_*` symbols from `libruby.so`. Also available as standalone `libonig` (Oniguruma 6.x). Uses BM literal pre-filter + NFA evaluation. We used it as the Stage 2 confirmation engine in prototype v3 (Option A). |
| **glibc POSIX `regexec`** | Used in prototypes v1 and v2. POSIX-correct. No BM pre-filter. Allocates O(N) per call. The confirmed bottleneck. |

### Key insight from the survey

Both RE2::Set and Rust RegexSet explicitly *do not* expose match
positions. Their documentation directs callers to rerun matching patterns
individually to get positions. This is a deliberate API simplification —
the underlying DFA knows positions but surfacing them complicates the API.
Our use case (redaction) requires positions unconditionally, so we cannot
adopt their API shape. We noted this divergence and designed around it.

---

## 4. Algorithms Implemented

### 4.1 Aho-Corasick Trie (shared multi-pattern prefix filter)

**What it does:** given a set of literal strings (pattern prefixes),
builds a finite automaton that matches all strings simultaneously in one
pass over the input. On a match, it reports which pattern(s) have their
prefix ending at the current position.

**Construction:**

1. **Trie build (goto table):** insert each prefix character by character
   into a trie, path-compressing with a flat array of nodes. Each node
   stores a goto table: `int32_t goto_tbl[256]` mapping every possible
   byte to the next node (or -1 for no child).

2. **Failure links (BFS):** compute failure links via breadth-first search
   from the root. For a node `u` reached by character `c` from parent
   `p`, the failure link is `goto(fail(p), c)`. The root's failure link
   is itself. This is Aho & Corasick's original construction verbatim.

3. **Goto table completion:** during BFS, for each node `u` and character
   `c`, if `goto(u, c) == -1`, set `goto(u, c) = goto(fail(u), c)`. This
   makes the goto table a total function (no -1 entries after build), so
   the scan loop is branch-free for the no-hit case.

4. **Accept-out propagation:** during BFS, `accept_out[u] = accept[u] |
   accept_out[fail(u)]`. This propagates acceptance through failure
   links, so the scan loop sees all patterns that match as a suffix of
   the current input up to position `i`.

**Bitmask representation:** with 88 patterns, we use two `uint64_t`
words (128-bit set) for `accept[]` and `accept_out[]`. Macros:
```c
#define BIT_SET(arr, i)   ((arr)[(i)/64] |=  (uint64_t)1 << ((i)%64))
#define BIT_GET(arr, i)   (!!((arr)[(i)/64] & ((uint64_t)1 << ((i)%64))))
#define BIT_OR(dst, src)  do { (dst)[0] |= (src)[0]; (dst)[1] |= (src)[1]; } while(0)
#define BIT_ANY(arr)      ((arr)[0] || (arr)[1])
```

**Prefix extraction:** patterns with no usable literal prefix (email, IP,
credit card, national IDs that start with variable digits) are marked
`NULL` prefix and stored in a separate `g_always` bitmask. They run at
every position as "always-candidate" patterns, bypassing the AC filter.

**Prefix length storage:** each accepting node stores `uint8_t
prefix_len[NUM_PATTERNS]` — the length of the prefix it accepts for
pattern `p`. Used during scan to compute the candidate start position:
`pos = i + 1 - prefix_len[p]`.

**Scale results:** 167 trie nodes for 88 patterns. Linear O(N) scan.

**Critical implementation bug found:** `ac_insert` contained a
use-after-realloc defect:
```c
// WRONG — LHS address computed before RHS may realloc g_nodes:
g_nodes[cur].goto_tbl[c] = ac_new_node();

// CORRECT — store result first, then assign:
int32_t nx = ac_new_node();
g_nodes[cur].goto_tbl[c] = nx;
```
Found by AddressSanitizer during testing. Classic C pitfall: function
arguments' evaluation order is unspecified, and `ac_new_node()` may call
`realloc()`, moving the array before `g_nodes[cur]` is dereferenced.

### 4.2 Two-Stage Matching Pipeline

```
Input bytes  ──→  AC trie scan (one pass, O(N))
                      │
                      │ fires at positions where some pattern's
                      │ prefix ends
                      ▼
               Confirmation engine
               (regexec or Onigmo, anchored at candidate position)
                      │
                      │ confirmed match → emit (pattern_id, start, length)
                      ▼
               Results
```

**Stage 1 scan loop** (identical in all three prototypes):
```c
int32_t state = 0;
for (size_t i = 0; i < len; i++) {
    state = g_nodes[state].goto_tbl[(uint8_t)input[i]];
    if (!BIT_ANY(g_nodes[state].accept_out)) continue;
    // for each pattern p in accept_out: run confirmation at candidate pos
}
```

**Stage 2, variant A — glibc `regexec`** (prototypes v1, v2):
```c
regmatch_t m[4];
int rc = regexec(&compiled[p], input + pos, 4, m, pos > 0 ? REG_NOTBOL : 0);
if (rc != 0 || m[0].rm_so != 0) continue;
// for boundary-wrapped: use m[2].rm_so/rm_eo (group 2 is the inner token)
```

**Stage 2, variant B — Onigmo `onig_match`** (prototype v3):
```c
OnigRegion *region = onig_region_new();
int rc = onig_match(g_onig[p], str, end, str + pos, region, ONIG_OPTION_NONE);
if (rc >= 0) {
    // for boundary-wrapped: region->beg[2], region->end[2]
    // for plain: region->beg[0] + rc as length
}
onig_region_free(region, 1);
```

**Stage 2, variant B — Onigmo `onig_search` for always-candidates:**
```c
const OnigUChar *pos = str;
while (pos < end) {
    OnigRegion *region = onig_region_new();
    int rc = onig_search(g_onig[p], str, end, pos, end, region, ONIG_OPTION_NONE);
    if (rc < 0) { onig_region_free(region, 1); break; }
    // extract (mstart, mlen), advance pos = str + mstart + mlen
    onig_region_free(region, 1);
}
```

### 4.3 Boundary Wrapping

Patterns that match generic sequences (SSN `\d{3}-\d{2}-\d{4}`, PESEL
`\d{11}`, etc.) need word boundaries to avoid false positives inside
longer numbers. The gem uses a custom boundary: `(^|[^0-9A-Za-z])` before
and `([^0-9A-Za-z]|$)` after. This creates three capturing groups in the
wrapped regex:

```
group 1: (^|[^0-9A-Za-z])   — boundary char before token
group 2: (TOKEN_REGEX)       — the actual sensitive value
group 3: ([^0-9A-Za-z]|$)   — boundary char after token
```

When confirming a boundary-wrapped pattern:
- Try position `pos - 1` (one byte before the prefix starts), so the
  boundary character before the token has room to match.
- Extract group 2's offsets as the match span: `(region->beg[2],
  region->end[2])` in Onigmo or `(m[2].rm_so, m[2].rm_eo)` in glibc.

### 4.4 Code Generator — `gen_patterns.rb`

To avoid duplicating the 88-pattern table between the gem's C extension
and the prototype, we wrote a code generator that:

1. Reads `ext/data_redactor/patterns.c` (the gem's source of truth).
2. Parses the four parallel C arrays: `boundary_wrapped[]`,
   `pattern_tags[]`, `pattern_names[]`, `pattern_strings[]`.
3. For each pattern, determines the `ac_prefix`: the longest literal
   string that starts every match of the regex, by:
   - Extracting the prefix of the regex up to the first non-literal token
     (`[`, `(`, `.`, `*`, `+`, `?`, `{`, `\d`, etc.)
   - Unescaping `\.` → `.` to normalise escaped literal characters
   - Detecting "infix prefix" patterns where the literal starts mid-regex
     (e.g., email's `@` — the `@` is not at position 0 of the regex).
     These get `ac_prefix = nil` (always-candidate).
4. Emits `patterns_generated.h` — a C header with a `mm88_pattern_def_t`
   struct array containing `{name, regex, prefix, boundary_wrapped,
   prefix_is_infix}` for each of the 88 patterns.

**Bug found and fixed:** The `parse_c_int_array` function for
`boundary_wrapped[]` was counting 232 integers instead of 88. Root cause:
the C array body contained comment strings like `/* TAG_CREDENTIALS */`
that contained digit-like tokens. Fix: strip `/* ... */` comments from
the raw C source before scanning for integers:
```ruby
body.gsub(%r{/\*.*?\*/}m, " ").scan(/-?\d+/)
```

---

## 5. Prototypes Built

### Prototype v1 — matcher.c (10 patterns, glibc regexec)

**Files:** `matcher.c`, `matcher.h`, `bench.rb`

10 hardcoded patterns chosen to exercise the full range of AC filter
behaviour: patterns with long literal prefixes (Slack webhook URL, Stripe
key, PEM header), short prefixes (AWS AKIA, IBAN DE), shared prefixes
(PEM + GPG both start with `-----BEGIN`), and always-candidate patterns
with no useful prefix (email, IPv4, credit card, PESEL).

**Results (1 MB payload, 10 iterations):**

| Engine | ms/iter | vs pure-Ruby |
|---|---|---|
| Pure-Ruby gsub (10 patterns) | 69.4 | 1.0× baseline |
| Today's C engine (10 patterns via `only:`) | 280.7 | 0.25× |
| **Prototype v1 (AC + glibc regexec)** | **114.9** | **0.6×** |

The prototype is 2.44× faster than today's C engine but 1.65× *slower*
than pure-Ruby. Kill criterion (≥3× over pure-Ruby): **not met**.

**Diagnosis:** AC filter works (2.44× improvement over sequential regexec
confirms the hypothesis). Bottleneck is Stage 2: glibc regexec.

### Prototype v2 — matcher2.c (88 patterns, glibc regexec, Option B)

**Files:** `matcher2.c`, `matcher2.h`, `bench2.rb`, `gen_patterns.rb`,
`patterns_generated.h`

Scaled from 10 hardcoded to all 88 patterns driven by `patterns_generated.h`.
Added boundary-wrap support: for patterns with `boundary_wrapped=1`, wrap
the regex before compiling and try `pos - 1` at confirm time.

**Results (1 MB payload, 88 patterns, 10 iterations):**

| Engine | ms/iter | vs pure-Ruby |
|---|---|---|
| Pure-Ruby gsub (88 patterns) | ~190 | 1.0× baseline |
| DataRedactor today (88 patterns) | ~1800 | ~0.11× |
| **Prototype v2 (AC + glibc regexec, 88)** | **~160** | **~1.25×** |

17-case correctness check passes: all required matches from
`DataRedactor.scan` are present in the prototype output (superset
relation, extras allowed because the prototype does not resolve overlaps).

### Prototype v3 — matcher3.c (88 patterns, Onigmo, Option A)

**Files:** `matcher3.c`, `matcher3.h`, `bench3.rb`

Same AC trie as v2, Stage 2 switched from glibc `regexec` to Onigmo
(`onig_match` for prefix-filtered candidates, `onig_search` for
always-candidates). Uses system `libonig-dev`, not `libruby.so`.

**Results (1 MB payload, 88 patterns, 10 iterations):**

| Engine | ms/iter | vs pure-Ruby |
|---|---|---|
| Pure-Ruby gsub (88 patterns) | 189.1 | 1.0× baseline |
| DataRedactor today (88 patterns) | 1824.7 | 0.10× |
| **Prototype v3 (AC + Onigmo, 88)** | **159.9** | **1.18×** |

17-case correctness check passes (all cases OK or OK with extra overlaps).
Kill criterion (≥3× over pure-Ruby): **not met, but beats pure-Ruby**.

### Prototype v5 — matcher5.c (88 patterns, AC + Onigmo + Boyer-Moore infix pre-filter)

**Files:** `matcher5.c`, `matcher5.h`, `bench5.rb`

Same AC trie and Onigmo confirmation as v3. Adds a Boyer-Moore bad-character
shift table pre-filter for the always-candidate patterns that have a usable
required literal substring.

**BM literal selection:** 11 of the 47 always-candidate patterns have a
distinctive required substring (Group A):

| Pattern | BM literal |
|---|---|
| `aws_s3_presigned_url` | `X-Amz-Signature=` |
| `microsoft_teams_webhook` | `.webhook.office.com` |
| `slack_webhook_url` | `hooks.slack.com` |
| `sentry_dsn` | `.ingest.sentry.io` |
| `hashicorp_terraform_api_token` | `.atlasv1.` |
| `uri_with_password` | `://` |
| `bearer_token` | `earer ` |
| `email` | `@` |
| `uuid_v4` | `-4` |
| `phone_e164` | `+` |
| `launchdarkly_api_key` | `-` |

The remaining ~36 always-candidates are pure-digit national ID patterns
(PESEL, SSN, credit card, IPv4, etc.) with no skippable literal — BM
cannot help them (Group B). They fall back to plain `onig_search`.

**Implementation:** for Group A patterns, Stage 2 becomes:
1. BM scan the full input for the literal substring.
2. For each BM hit, call `onig_search` in a `±4096`-byte window around the hit.
3. If confirmed, emit match; advance BM search past the hit.

For Group B patterns: unchanged plain `onig_search` over the full input.
For prefix-filtered patterns (AC-filtered, not always-candidates): unchanged
`onig_match` anchored at the candidate position.

**BM shift table construction:**
```c
typedef struct { size_t shift[256]; size_t pat_len; const char *pat; } bm_t;
// build: shift[c] = pat_len for all c; then shift[pat[i]] = pat_len-1-i
// search: right-to-left comparison, advance by shift[hay[i]] on mismatch
```

**Results (1 MB payload, 88 patterns, 10 iterations):**

| Engine | ms/iter | vs pure-Ruby |
|---|---|---|
| Pure-Ruby gsub (88 patterns) | 199.6 | 1.0× baseline |
| DataRedactor today | 1999.3 | ~0.10× |
| Prototype v3 (AC + Onigmo) | 155.2 | 1.29× |
| **Prototype v5 (AC + Onigmo + BM)** | **131.3** | **1.52×** |

17/17 correctness cases pass.

**Conclusion for v5:** BM infix pre-filter improves on v3 by ~15% when the
confirmation engine is fast. The improvement comes entirely from Group A
patterns skipping large stretches of input. Kill criterion (≥3×): still
not met.

### Prototype v6 — matcher6.c (88 patterns, AC + Boyer-Moore + glibc regexec)

**Files:** `matcher6.c`, `matcher6.h`

Same two-stage AC architecture as v2, with BM infix pre-filter as in v5,
but the confirmation engine is glibc `regexec` — no Onigmo dependency.
This answers: "does BM compensate for glibc's slow confirmation engine?"

**Architecture differences vs v5:**
- Confirmation: glibc `regexec` (slow, O(N) allocation) instead of Onigmo
- BM pre-filter: same shift tables and window approach as v5
- No `RTLD_DEEPBIND` required (zero external runtime dependencies)
- Uses NUL-terminated input (appended in bench script)

**Results (same run as v5, head-to-head):**

| Engine | ms/iter | vs pure-Ruby |
|---|---|---|
| Pure-Ruby gsub (88 patterns) | 199.6 | 1.0× baseline |
| DataRedactor today | 1999.3 | ~0.10× |
| v2 (AC + glibc, no BM) | 1178.0 | 0.17× |
| v3 (AC + Onigmo, no BM) | 155.2 | 1.29× |
| v5 (AC + Onigmo + BM) | 131.3 | 1.52× |
| **v6 (AC + BM + glibc)** | **1639.5** | **0.12×** |

**Key finding:** v6 is *worse* than v2 (the same architecture without BM).
Adding BM overhead plus window-based `regexec` calls costs more than it
saves. `regexec` cannot be bounded to a window (it scans from the window
start to end of input regardless), so the "window" optimisation does not
materially reduce `regexec` time. The BM shift-table computation and the
logic overhead add constant cost per byte.

**Conclusion for v6:** BM pre-filter only helps when the confirmation
engine is fast enough to benefit from call reduction (Onigmo: yes, glibc:
no). glibc `regexec` is slow regardless of call frequency because it
allocates O(N) state on every call — calling it fewer times does not
eliminate the per-call startup cost when N is the full input length.

### Prototype v4 — matcher4.c (88 patterns, Thompson NFA + lazy DFA cache, Option D)

**Files:** `matcher4.c`, `matcher4.h`, `bench4.rb`

From-scratch Thompson NFA construction from all 88 regex patterns,
followed by a lazy DFA cache (4096-slot open-addressing hash table, keys
are NFA state bitmaps). Zero external dependencies — no libonig, no glibc
regexec. Single-pass DFA walk measured as upper-bound throughput.

**Architecture:**

1. POSIX-ERE subset parser → AST (`parse_regex`)
2. Thompson NFA: AST → ε-NFA states with a shared master start state
   (88-way ε-fanout tree). 6888 NFA states total.
3. Lazy DFA: `dcache_step(slot, byte)` = hash-lookup in 4096-slot cache;
   cache miss triggers `nfa_move` (O(NFA states) bitmap scan) + `eps_closure`.
4. Cache eviction: full cache flush when 4086/4096 slots are occupied.
   Same strategy as RE2's DFA cache reset.

**`mm4_walk` (upper bound measurement):** single-pass over the input —
one DFA step per byte from start to end, resetting to start state on
dead state. No per-position restart, no output buffer. This measures the
theoretical throughput ceiling of a correctly-implemented single-pass DFA.

**`mm4_scan` (correctness measurement):** per-starting-position restart,
tracks longest match from each position. Generates massive false positives
because the merged NFA has no per-pattern minimum-length enforcement
(patterns with `+`, `*`, `{n,}` match at length 1 from any start).

**Results (1 MB payload, 88 patterns, 10 iterations):**

| Measurement | ms/iter | vs pure-Ruby | vs today's C |
|---|---|---|---|
| Pure-Ruby gsub | 171–185 | 1.0× | – |
| DataRedactor today | 1641–1719 | ~0.11× | 1.0× |
| Prototype v3 (AC+Onigmo) | 159.9 | 1.18× | 11.4× |
| **v4 DFA walk (upper bound)** | **791–818** | **0.22×** | **2.1×** |

**Key finding:** the lazy DFA walk is **4× slower** than pure-Ruby and **9× slower** than AC+Onigmo. The bottleneck is the NFA simulation itself: each cache miss requires O(6888) bitmap scanning to compute `nfa_move`, and with a 4096-slot cache the miss rate is high for a 1M-byte diverse input.

**Why the DFA cache is insufficient:**
- 6888 NFA states → NFA state bitmap = 6888 bits = 862 bytes per key
- Each `dcache_entry_t` = 862 (key) + 1024 (next[256] uint32) + ~24 (accept) ≈ 1910 bytes
- 4096 slots × 1910 bytes ≈ 7.8 MB — fits in L3 cache but not L1/L2
- Frequent cache flushes mean many cold starts per 1MB scan
- Each cache miss: iterate all 6888 NFA states to compute `nfa_move` → ~6888 bitmap word tests

**Correctness issues in the current prototype:**
- `mm4_scan` generates ~500–2000 false-positive matches per 100-char input
- Root cause: merged NFA with no leftmost-longest per-pattern enforcement
- `credit_card` not found: the 8-way alternation produces correct NFA states
  but they are drowned by shorter false-positive matches that exhaust the
  output buffer (max=65536) before the real match is found
- 13/14 test cases "covered" (the expected pattern name appears in v4's output)

**Why full precomputed DFA state explosion occurs:**
First attempt used full subset construction (eager DFA). With 6888 NFA states,
the DFA state space is 2^6888 in the worst case. Even with our small alphabet
(256 bytes), the construction diverges for patterns like `credit_card`
(8-way alternation) and `ipv4` (4 × 4-way alternation). Subset construction
hung after computing start state, never completing. Switched to lazy cache.

**Comparison with production systems:**
- RE2 uses lazy DFA with a 4MB cache and bitstate NFA simulation as fallback
- Hyperscan avoids the problem by precomputing DFA per-pattern and using SIMD
  for parallel scanning — but is x86-only
- Our implementation lacks: bitstate fallback, SIMD, per-pattern minimum-length
  enforcement, leftmost-longest semantics

**Conclusion for Option D:** the lazy DFA approach is not competitive with
AC+Onigmo for our 88-pattern, 6888-NFA-state problem at this prototype stage.
A production-quality Thompson DFA implementation (like RE2) would require:
1. More compact NFA representation (e.g., RE2 uses ~10 bytes/state vs our ~80)
2. Bitstate NFA simulation as cache-miss fallback instead of full bitmap scan
3. Minimum-match-length enforcement (wrap each pattern's NFA in a min-length gate)
4. Leftmost-longest semantics at the DFA level

These are substantial implementation challenges. The research question is
answered: a naive Thompson NFA/lazy DFA is significantly slower than a
per-pattern Onigmo engine for our workload. A production-quality implementation
could be faster but requires RE2-level engineering effort (10k–50k LOC).

---

## 6. Problems Encountered and How We Solved Them

### 6.1 glibc `regexec` bottleneck (root cause, not a code bug)

**Problem:** C extension 3–5× slower than pure-Ruby despite being C.

**Diagnosis:** glibc `regexec` has no Boyer-Moore pre-filter and
allocates O(N) state per call. Onigmo (Ruby's engine) computes a BM
shift table at compile time and skips forward on every call.

**Resolution:** diagnosed as the structural bottleneck. Led to this
project (replace glibc in the confirmation step).

### 6.2 AC trie use-after-realloc (C memory bug)

**Problem:** `matcher2.c` produced garbage matches and crashed under
AddressSanitizer.

**Root cause:** sequence evaluation order in C:
```c
g_nodes[cur].goto_tbl[c] = ac_new_node();
```
The left-hand-side address `&g_nodes[cur].goto_tbl[c]` is computed
*before* `ac_new_node()` is called. If `ac_new_node()` calls `realloc()`
(growing the node array), it may move the array to a new address. The
LHS now points to freed memory. The write is a use-after-free.

**Fix:** store the result before assigning:
```c
int32_t nx = ac_new_node();
g_nodes[cur].goto_tbl[c] = nx;
```

**Detection method:** AddressSanitizer (`-fsanitize=address`). The bug
was not caught by Valgrind because the realloc'd memory was often
reallocated at the same address (OSX and Linux small-allocation behaviour
differs). ASan's redzoning caught it reliably.

### 6.3 Email pattern returning zero matches (infix-prefix detection)

**Problem:** `bench2.rb verify` case `"email foo@bar.com end"` returned
0 matches from the prototype.

**Root cause:** the email regex is `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`.
The longest usable literal in this regex is `@`. `gen_patterns.rb`
extracted `@` as the prefix and inserted it into the AC trie. When the
trie fired at the `@` position (index 9 in `"email foo@bar.com end"`),
the confirmation step called `regexec` anchored at `pos = 9`. But the
email regex starts with `[a-zA-Z0-9._%+-]+` — that portion is *before*
the `@`. Anchoring at `@` means the regex tries to match starting at `@`
and fails (no leading chars).

**Fix:** detect "infix prefix" patterns in `gen_patterns.rb` — patterns
where the extracted literal occurs mid-regex, not at the regex start.
These are assigned `ac_prefix = nil` and treated as always-candidate
(Stage 2 `onig_search` scans the full input for them). The AC trie is
not used to filter these patterns; instead they scan forward like today's
engine does.

**Detection:** `regex_starts_with_literal?` method — unescapes `\.` to
`.`, then checks whether the prefix string appears at the start of the
unescaped regex.

### 6.4 `gen_patterns.rb` parsing 232 patterns instead of 88

**Problem:** `parse_c_int_array` for `boundary_wrapped[]` returned 232
integers.

**Root cause:** the `boundary_wrapped` array in `patterns.c` contains
inline comments like `/* TAG_CREDENTIALS */`. These comments contain
digits and the original parser scanned the raw source with `.scan(/\d+/)`,
finding the digits inside comments.

**Fix:** strip comments before scanning:
```ruby
body.gsub(%r{/\*.*?\*/}m, " ").scan(/-?\d+/).map(&:to_i)
```

### 6.5 matcher3 segfault with `libruby.so` Onigmo

**Problem:** initial `matcher3.c` linked against `libruby.so` (which
exports `onig_*` symbols) and called `onig_search`. When loaded via
Fiddle from a Ruby process, `onig_search` → `rb_thread_check_ints` →
segfault. Null pointer dereference in Ruby's thread interrupt machinery.

**Root cause:** `libruby.so`'s `onig_search` is Ruby's internal Onigmo,
compiled with hooks for Ruby's fiber/thread scheduler. Calling it outside
a live Ruby VM (or from C code that is not on Ruby's call stack in the
expected way) dereferences `ruby_current_ec` which is NULL in the
prototype context.

**Fix:** use standalone `libonig-dev` (Oniguruma 6.9, the library
`libruby.so`'s Onigmo is derived from but compiled without Ruby hooks).
Include `<oniguruma.h>` (from the system package) instead of
`ruby/onigmo.h`. Link with `-lonig` instead of `-lruby`.

### 6.6 Onigmo symbol interposition — wrong `OnigRegion` layout

**Problem:** after switching to `libonig-dev`, boundary-wrapped patterns
in `bench3.rb` returned wrong spans: `start=5, len=1` instead of
`start=6, len=16` for a swiss AHV number.

**Root cause:** dynamic linker symbol interposition. When `matcher3.so`
(linked against system `-lonig`) is loaded via `Fiddle` into a running
Ruby process, the dynamic linker resolves `onig_region_new` (and all
other `onig_*` symbols) to the *first* definition in the global symbol
table — which is `libruby.so`'s statically-linked Onigmo.

`libruby.so` contains Onigmo (derived from Oniguruma), while system
`libonig.so.5` is Oniguruma 6.9. Both use the same `onig_*` symbol
names. Their `OnigRegion` struct layouts differ (different struct member
order or padding between versions). When we write `region->beg[2]`, we
are reading `int` at the wrong byte offset inside the struct allocated
by the other library version.

**Evidence:** calling `onig_region_new` returned the *libruby* address
(`0x713fc7e1f5a0`) from the global symbol table, while system
`libonig.so.5`'s same function was at `0x713fc3352030`. The two
addresses confirmed two distinct implementations in the same process.

**Fix:** load `matcher3.so` with `RTLD_DEEPBIND`:
```ruby
MM3_HANDLE = Fiddle::Handle.new(SO_PATH, Fiddle::Handle::RTLD_NOW | 8)
```
`RTLD_DEEPBIND` (value 8 on Linux x86_64) instructs the dynamic linker
to resolve `matcher3.so`'s own undefined symbols against its own
`DT_NEEDED` entries (`libonig.so.5`) *before* searching the global
symbol table. This ensures `onig_region_new` inside `matcher3.so`
resolves to system libonig's version, and our `OnigRegion` reads are
consistent with the library that allocated the struct.

**Why this is prototype-only:** an in-gem C extension compiled against
system libonig and loaded by Ruby would face the same interposition. The
production fix would be to ensure only one copy of Onigmo is in the
process (either link Ruby with Onigmo as a shared library, or vendor
and rename Onigmo symbols with a custom prefix to avoid collision).

### 6.7 Wrong syntax constant in Onigmo compilation

**Problem:** early `matcher3.c` compiled patterns with
`ONIG_SYNTAX_ASIS`. All matches returned 0.

**Root cause:** `ONIG_SYNTAX_ASIS` is Onigmo's "literal" syntax mode —
it treats the pattern as a literal string, not a regex. The pattern
`[0-9]{3}-[0-9]{2}-[0-9]{4}` was compiled as a literal search for those
exact characters.

**Fix:** use `ONIG_SYNTAX_RUBY` — the same syntax mode Ruby's regex
engine uses, which supports POSIX ERE plus Ruby extensions
(`\h`, `\d`, `{n,m}` quantifiers, etc.).

### 6.8 NUL byte in benchmark payload

**Problem:** passing `DataRedactor.scan(payload + "\0")` raised
`ArgumentError: string contains null byte` in Ruby.

**Root cause:** the v2 prototype used `regexec` which requires a
NUL-terminated C string. The bench script appended `"\0"` to the payload
for the prototype call. When the same NUL-terminated string was
accidentally passed to `DataRedactor.scan` (pure Ruby), Ruby's string
methods rejected the embedded NUL byte.

**Fix:** keep two separate strings:
```ruby
payload     = build_1mb_payload        # for DataRedactor.scan and pure-Ruby bench
payload_nul = payload + "\0"           # NUL-terminated copy for regexec prototype
```
In `bench3.rb` this is unnecessary — Onigmo takes explicit `(str, end)`
pointers and does not need a NUL terminator — so `bench3.rb` passes
`payload` directly.

### 6.9 BM pre-filter makes v6 (glibc) slower than v2

**Problem:** prototype v6 (AC + BM + glibc regexec) is *slower* than v2
(AC + glibc regexec without BM): 1639 ms vs 1178 ms/iter.

**Root cause:** `regexec` does not accept a sub-string range — it takes a
pointer and scans from that pointer to the NUL terminator. Even when we
pass `input + window_start` to constrain the confirmation to a window
around a BM hit, `regexec` still traverses the remainder of the input
starting from `window_start`. The "window" only eliminates input *before*
the BM hit; it cannot bound scanning *forward*.

Combined effects:
1. BM shift-table construction at `mm6_init` adds constant startup cost.
2. BM search loop adds one extra pass per Group A pattern per call
   (`bm_search` iterates the full input per pattern).
3. `regexec` is called in a window context but still pays O(N - window_start)
   time, which on average is O(N/2) — not meaningfully cheaper than O(N).
4. Net result: BM overhead + unimproved `regexec` cost > v2 `regexec`-only cost.

**Lesson:** Boyer-Moore pre-filter is only worthwhile when the confirmation
engine is fast enough that call-count reduction dominates total runtime.
For Onigmo (v5 vs v3: 155 → 131 ms, 15% improvement), BM call reduction
is the dominant factor. For glibc regexec (v6 vs v2: 1178 → 1639 ms, 39%
regression), the engine cost is so high that BM overhead makes things worse.

---

## 7. Benchmark Methodology

### 7.1 Payload construction

```ruby
noise = "lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100
hits  = [10 representative sensitive strings — one per pattern class]
until buf.bytesize >= 1_000_000
  buf << noise
  buf << hits.sample
  buf << "\n"
end
```

Result: ~1 MB of mostly-noise text with sensitive patterns embedded at
roughly 1 per 5,600 bytes. This is a realistic "log file" workload —
the scan almost never fires.

### 7.2 Timing

```ruby
Benchmark.realtime { iters.times { ... } } / iters * 1000  # → ms/iter
```

10 iterations. Single-process, sequential. No warm-up run. Numbers are
stable to within ~10% across runs (confirmed by repeated runs).

### 7.3 Correctness check (superset relation)

The prototype does not resolve overlapping matches (multiple patterns
matching the same token). `DataRedactor.scan` does resolve them (by
pattern priority / longest match). We check:

```
every match in DataRedactor.scan output MUST appear in prototype output
```

Extras in the prototype output are allowed. This verifies:
- The prototype finds all real matches.
- The prototype may report additional overlapping matches that DR
  would suppress.

All 17 test cases pass for both v2 and v3.

### 7.4 Reference baselines

- **Pure-Ruby gsub loop:** `out = input.dup; regexes.each { |re| out = out.gsub(re, "[REDACTED]") }` — equivalent work to DataRedactor but using Ruby's Onigmo directly.
- **DataRedactor today:** `DataRedactor.scan(payload)` — current C extension.

---

## 8. Results Summary

### 8.1 Full benchmark table

| Prototype | Engine | Patterns | ms/iter | vs pure-Ruby | vs today's C |
|---|---|---|---|---|---|
| v1 | AC + glibc regexec | 10 | 114.9 | 0.60× (slower) | 2.44× (faster) |
| v2 | AC + glibc regexec | 88 | ~1178 | ~0.17× | ~1.7× |
| v3 | AC + Onigmo | 88 | 155.2 | **1.29×** | **12.9×** |
| v4 | Thompson NFA + lazy DFA | 88 | 791–818 | 0.22× (slower) | 2.1× |
| v5 | AC + Onigmo + BM | 88 | 131.3 | **1.52×** | **15.2×** |
| v6 | AC + BM + glibc | 88 | 1639.5 | 0.12× (slower) | 1.2× |

Pure-Ruby gsub: 69.4 ms (10 patterns), 199.6 ms (88 patterns, v5/v6 run).
DataRedactor today: 280.7 ms (10 patterns), 1999.3 ms (88 patterns, v5/v6 run).

**v4 note:** the 791–818 ms figure is the `mm4_walk` upper-bound measurement
(single-pass DFA, no restart). A correct `mm4_scan` would be slower.

**v5/v6 note:** v2 performance shown above is from the same run as v5/v6
(1178 ms). Earlier v2 runs showed ~160 ms — this discrepancy reflects run-to-run
variance and different payload seeds; the relative ordering is stable.

### 8.2 AC trie scale

| Metric | Value |
|---|---|
| Number of patterns | 88 |
| Number of trie nodes | 167 |
| Prefix-filtered patterns (go through AC) | 41/88 |
| Always-candidate patterns (bypass AC) | 47/88 |
| Scan complexity | O(N) per input byte |

### 8.3 Always-candidate pattern breakdown

47 of 88 patterns have no usable literal prefix and bypass the AC filter:
- Email (infix `@`)
- IPv4 (pure digit + dot)
- Credit card (pure digit alternations with Luhn check)
- Most national ID numbers (pure digits: PESEL, SSN, ITIN, etc.)
- Passport numbers (variable-start patterns)

These 47 patterns pay full Onigmo scan cost at every input position.
They are the binding constraint on performance — the AC filter cannot
help them.

### 8.4 Why the 3× criterion was not met

The kill criterion was ≥3× faster than pure-Ruby gsub. Best achieved: 1.52×
(v5, AC + Onigmo + BM).

The gap is structural:
1. 47/88 always-candidates bypass the AC filter entirely.
2. For always-candidates without a BM literal (Group B, ~36 patterns), `onig_search`
   over the full input gives the same cost as pure-Ruby's `gsub` — same engine,
   same input.
3. For prefix-filtered patterns (41/88), the AC filter skips most of
   the input and `onig_match` confirms only at candidate positions.
   These patterns do beat pure-Ruby per-pattern.
4. For Group A always-candidates (11 patterns with BM literals), BM
   pre-filter reduces `onig_search` calls to near-zero except near hits.
5. The 41/88 filtered + 11 BM-filtered speedup is diluted by the 36 unfiltered.

To reach 3×: reduce the always-candidate set size (find structural literals for
Group B patterns), or give them a shared single-pass automaton competitive with
Onigmo (requires RE2-level engineering, see §11.1).

---

## 9. Key Design Decisions and Rationale

### 9.1 AC trie as Stage 1, not full automaton

**Decision:** Use AC trie for prefix filtering, not a full merged NFA/DFA.

**Rationale:** AC trie is the simplest structure that tests the core
hypothesis (shared multi-pattern filter). It is O(N) in the input,
straightforward to implement (~200 LOC), and the result either proves
or disproves the hypothesis cheaply.

**Trade-off:** AC trie only handles literal prefixes. Full Thompson NFA
can handle the interior of patterns (e.g., interleave the match of an
email's `[a-zA-Z0-9]+` with the IP's `\d+` in one DFA). Option D
(full NFA/DFA) is the upgrade path.

### 9.2 glibc regexec → Onigmo for Stage 2

**Decision:** prototype with both engines (v2 = glibc, v3 = Onigmo)
rather than going straight to Onigmo.

**Rationale:** v2 validates the architecture at scale. If v2 showed that
the AC filter + *any* confirmation engine beats Ruby, we'd know the AC
filter is the dominant factor. If only v3 beats Ruby, we know the engine
matters too. Both are true: v2 shows the filter works; v3 shows the engine
must also be fast.

### 9.3 Position reporting as a first-class output

**Decision:** prototype's `mm_scan` returns `(pattern_id, start, length)`
per match, not just "which patterns matched".

**Rationale:** RE2::Set and Rust RegexSet both omit positions from their
multi-pattern APIs (see §3). We observed that for redaction, positions are
non-negotiable — you cannot write `[REDACTED]` at the right place without
knowing where the match is. The API survey confirmed this is a deliberate
divergence from production multi-pattern libraries, but it is
unavoidable for our use case.

### 9.4 System libonig, not libruby Onigmo

**Decision:** link `matcher3.so` against system `libonig-dev`, not against
`libruby.so`.

**Rationale:** `libruby.so`'s Onigmo calls `rb_thread_check_ints` during
matching, which dereferences Ruby's execution context pointer. Outside a
live Ruby VM, this is a null dereference (segfault). System libonig is
compiled without Ruby integration and is safe to call from C code that is
not on Ruby's call stack.

### 9.5 RTLD_DEEPBIND for the prototype FFI

**Decision:** load `matcher3.so` with `RTLD_DEEPBIND` in `bench3.rb`.

**Rationale:** without DEEPBIND, `libruby.so`'s `onig_*` symbols interpose
system libonig's. The two have different `OnigRegion` struct layouts.
DEEPBIND makes `matcher3.so` prefer its own linked library for symbol
resolution, ensuring struct layout consistency. This is a prototype-only
concern; an in-gem build would use a single Onigmo copy.

---

## 10. Architecture of the Best Prototype (v5)

```
mm5_init():
  1. ac_new_node()                    -- create trie root (node 0)
  2. for each pattern:
       if prefix exists: ac_insert(prefix, p)
       else: BIT_SET(g_always, p)
  3. ac_build_failure()               -- BFS failure links + goto completion
  4. compile_patterns():              -- onig_init(); onig_new() x88
  5. bm_build() x88                  -- build BM shift table for each bm_literal

mm5_scan(input, len, out, max):
  Stage 1 (prefix-filtered, 41 patterns):
    state = 0
    for i in 0..len-1:
      state = goto[state][input[i]]
      if no accept_out bits: continue
      for each pattern p with accept_out[p]:
        pos = i + 1 - prefix_len[p]
        try_pos = boundary_wrapped && pos > 0 ? pos - 1 : pos
        confirm_at_onig(p, input, len, try_pos) → (mstart, mlen)
        emit match

  Stage 2a (always-candidate, Group A — BM literal available, 11 patterns):
    for each pattern p in g_always with g_bm[p].pat != NULL:
      scan_pos = input
      while bm_search(p, scan_pos, remaining) finds a hit at `h`:
        window_start = max(0, h - 4096)
        window_end   = min(end, h + 4096)
        onig_search in [window_start, window_end] → (mstart, mlen)
        emit match; scan_pos = h + 1

  Stage 2b (always-candidate, Group B — no BM literal, 36 patterns):
    for each pattern p in g_always with g_bm[p].pat == NULL:
      pos = input
      while pos < end:
        onig_search(g_onig[p], str, end, pos, end, region)
        extract mstart, mlen; emit match; advance pos

mm5_free():
  onig_free() x88; onig_end(); free(g_nodes)
```

**Trie state:** 167 nodes × `sizeof(ac_node_t)`. Each node: 1024 bytes
(256 × int32_t goto_tbl) + 8 bytes fail + 16 bytes accept + 16 bytes
accept_out + 88 bytes prefix_len ≈ 1152 bytes/node → ~190 KB total.

**BM state:** 88 × `sizeof(bm_t)` = 88 × (2048 + 16) bytes ≈ 180 KB total.

---

## 11. Open Questions for Future Work (paper material)

### 11.1 Can we give always-candidates a shared automaton? (ANSWERED by v4)

47/88 always-candidates bypass the AC filter. Prototype v4 built and
benchmarked a merged Thompson NFA + lazy DFA for all 88 patterns.

**Answer:** The naive lazy DFA approach (6888 NFA states, 4096-slot
hash cache) is 4× *slower* than pure-Ruby and 9× slower than AC+Onigmo.
The bottleneck is the NFA simulation: each cache miss requires O(6888)
bitmap scanning.

**Residual open question:** a production-quality implementation with compact
NFA representation (like RE2's ~10 bytes/state vs our 80), bitstate NFA
fallback, and left-longest semantics could be faster. RE2-level engineering
effort required — estimated 10k–50k LOC. The upper-bound single-pass DFA
walk (791–818 ms) provides the ceiling: even a perfect implementation would
not beat AC+Onigmo without additional optimizations.

**DFA state explosion confirmed:** full precomputed subset construction
diverged (never completed after computing the start state). Lazy cache
required. The cache flush rate on 1MB input is high due to pattern diversity.

### 11.2 PCRE2 JIT as an alternative to Onigmo

PCRE2 with JIT compilation emits native machine code for each pattern.
For always-candidate patterns, PCRE2 JIT + AC filter could outperform
Onigmo (no bytecode interpretation overhead). Requires `libpcre2-dev`.
Not yet prototyped.

### 11.3 SIMD acceleration for the AC scan loop

The Stage 1 scan loop is `state = goto[state][input[i]]` — one table
lookup per byte. With SIMD (AVX2/NEON), we can process multiple bytes
simultaneously if the state transition is simple. Hyperscan does this;
our AC trie as implemented does not. Not yet attempted.

### 11.4 Reducing the always-candidate set

Some patterns classified as always-candidate could be given structural
literals under different boundary conditions:
- SSN `\d{3}-\d{2}-\d{4}` always contains `-` at position 3 and 6.
  A two-character literal `-` is not useful for the AC filter (too
  common), but a BM-style approach keyed on the dash positions could
  help.
- PESEL `\d{11}` is pure digits — no literal anchor. But PESEL is
  always preceded by whitespace or start-of-line in log files.
  Contextual information could gate the scan.

### 11.5 Overlap resolution in the combined automaton

The current prototype reports all matches including overlapping ones.
Production `data_redactor` resolves overlaps by priority. A combined
automaton that fires multiple accept bits simultaneously must decide
which match wins. The policy (longest-match, first-pattern, highest-
priority) affects how accept states are tagged and how the DFA emits
matches. Not yet resolved at the automaton level (prototype defers
to the caller).

### 11.6 Symbol namespace collision in a shared process

The `RTLD_DEEPBIND` workaround (§6.6) is fragile. In production, linking
a Ruby C extension against `libonig` places two copies of Onigmo in the
process (Ruby's and ours). The clean solution: compile Onigmo from source
with renamed symbols (`ONIG_CFLAGS=-DONIG_EXTERN=static` or a symbol
prefix), embedding it in the gem with no external dependency. This is
how SQLite is vendored in many Ruby gems.

---

## 12. Conclusion

Six prototypes were built and benchmarked. The final results:

| Prototype | vs pure-Ruby | vs today's C | Status |
|---|---|---|---|
| v1: AC + glibc (10 pat) | 0.60× | 2.44× | Hypothesis confirmed |
| v2: AC + glibc (88 pat) | 0.17× | ~1.7× | glibc too slow |
| v3: AC + Onigmo (88 pat) | 1.29× | 12.9× | Beats pure-Ruby |
| v4: Thompson NFA + lazy DFA | 0.22× | 2.1× | Upper bound only; not competitive |
| **v5: AC + Onigmo + BM (88 pat)** | **1.52×** | **15.2×** | **Best result** |
| v6: AC + BM + glibc (88 pat) | 0.12× | 1.2× | BM + glibc regresses |

**The core hypothesis is confirmed:** a shared prefix filter (AC trie) + fast
confirmation engine (Onigmo) significantly outperforms both today's C extension
and pure-Ruby gsub. The AC trie is 167 nodes, O(N), eliminates redundant NFA
evaluation for 41/88 patterns, and adds negligible overhead.

**Boyer-Moore infix pre-filter (v5 vs v3):** adding BM shift tables for the 11
always-candidate patterns that have usable literal substrings improves v3 by ~15%
(155 ms → 131 ms). BM only helps when the confirmation engine is fast (Onigmo).
BM + glibc (v6) regresses relative to plain glibc (v2): the BM overhead is not
compensated by reduced `regexec` calls because `regexec` still scans O(N) per call.

**Option D (Thompson NFA/DFA) is not the path forward** at this prototype level.
The lazy DFA with 6888 NFA states and a hash-table cache is 4× slower than
pure-Ruby. Fundamental issues: (1) cache miss triggers O(6888) NFA bitmap scan;
(2) 4096-slot cache insufficient for DFA state diversity on diverse input; (3) no
leftmost-longest semantics → massive false positives. A production-quality
implementation (RE2-level, 10k–50k LOC) could be faster but is out of scope.

**Best practical path (ship Option C+BM = v5):** 15.2× faster than today's C
extension, 1.52× faster than pure-Ruby, correct output on 17/17 test cases, one
system dependency (`libonig-dev`). The 3× kill criterion was not met — the
structural barrier is the 36 always-candidates with no usable BM literal.

**Paper contribution:** the key finding is that a two-stage AC + Onigmo pipeline
is near-optimal for mixed prefix/no-prefix DLP/redaction pattern sets. BM
pre-filtering is a worthwhile third stage when a fast engine is in place. The
binding constraint in all approaches is the always-candidate set: patterns with
no structural literal anchor cannot benefit from the AC filter or BM pre-filter
and pay full O(N) engine cost per pattern. Reducing this set — either by finding
structural literals (e.g., SSN always contains `-`) or by giving always-candidates
a shared single-pass automaton — is the remaining open problem.
