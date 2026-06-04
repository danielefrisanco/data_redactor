# Research Log — Multi-Pattern Matching in data_redactor

**Purpose:** complete record of every idea, algorithm, experiment, result,
and problem encountered during the multi-pattern matcher research project.
Intended as the foundation for a future paper.

**Date range:** 2026-05-23 – 2026-05-24 (v4/v5/v6 added 2026-05-24); v4.1/v4.2 added 2026-06-02; v4.2 correctness analysis added 2026-06-02; v9/v10 (incorrect) + v11 bytecode VM (correct baseline) added 2026-06-03; v12.1 literal pre-filter + v14 first-byte filter added 2026-06-03; v15.1 VM constant-factor speedups added 2026-06-03.
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
| **Cox (2009)** — *"Regular Expression Matching: the Virtual Machine Approach"*, rsc.io | Explains the Pike VM — a Thompson NFA simulation that tracks capture groups without backtracking. The "two state list" technique we implemented in `matcher4.c`. |
| **Laurikari (2000)** — *"NFA simulation based regex matching with tagged transitions"* | Submatch tracking in NFA simulation without backtracking. Background for future capture-group support in v4. Not yet applied. |

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

### Prototype v7 — matcher7.c (88 patterns, AC + BM + PCRE2 interpreter and JIT)

**Files:** `matcher7.c`, `matcher7.h`, `bench7.rb`

Same AC trie + BM infix pre-filter architecture as v5. Confirmation engine
replaced with PCRE2. A single binary handles both variants via `mm7_init(use_jit)`:
`0` = PCRE2 interpreter, `1` = PCRE2 JIT (`pcre2_jit_compile` + `pcre2_jit_match`).

**Why PCRE2 over Onigmo:** PCRE2 with JIT compiles each pattern to native machine
code at init time. Subsequent matches execute the compiled code directly — no
bytecode interpretation. Published benchmarks predicted 2–5× faster confirmation
for pure-digit always-candidate patterns (§11.2). The prototype tests the prediction.

**Key implementation details:**
- No `RTLD_DEEPBIND` required — no Onigmo in the dependency chain, no symbol interposition.
- JIT fallback: `pcre2_jit_compile` returns an error on architectures without a JIT
  backend or when `mmap(PROT_EXEC)` is blocked. The code logs a warning and continues
  with the interpreter (silent graceful degradation).
- `PCRE2_EXTENDED` flag intentionally omitted — it causes PCRE2 to ignore whitespace
  in the pattern source, which breaks patterns like `bearer_token` that require a
  literal space.
- Match data allocated per-call (`pcre2_match_data_create_from_pattern`). A
  pre-allocated per-thread match_data would be faster; deferred for a production build.

**Results (same machine, same day — v5 re-run for direct comparison):**

| Engine | ms/iter | vs pure-Ruby | vs today's C |
|---|---|---|---|
| Pure-Ruby gsub (88 patterns) | 144.7 | 1.0× baseline | – |
| DataRedactor today | 1365.4 | 0.11× | 1.0× |
| v5 AC + Onigmo + BM | 108.0 | 1.34× | 12.7× |
| v7 PCRE2 interpreter | 298.2 | 0.49× (slower than Ruby) | 4.6× |
| **v7 PCRE2 JIT** | **52.7** | **2.79×** | **25.5×** |

JIT speedup over interpreter: **5.66×** (matches published prediction of 3–8×).
17/17 correctness cases pass for both no-JIT and JIT variants.

**Key findings:**

1. **PCRE2 JIT is the clear winner**: 2.79× over pure-Ruby, 25.5× over today's C,
   and 2.1× faster than v5 (AC+Onigmo+BM). Clears the ≥2× go/no-go threshold.

2. **PCRE2 interpreter ≈ glibc**: 298 ms vs pure-Ruby's 145 ms — same 0.49× ratio
   as glibc-based prototypes. Confirms that the interpreter engine characteristic
   (no BM pre-filter, full NFA evaluation) is the bottleneck, not PCRE2's API overhead.

3. **JIT benefit is larger than Onigmo's BM**: Onigmo's BM literal pre-filter (v5)
   reduces call cost by skipping non-matching positions. PCRE2 JIT reduces *per-call*
   cost by executing native code instead of bytecode. For our pattern mix, the
   per-call speedup dominates: even always-candidates without a BM literal (Group B)
   benefit from JIT, whereas Onigmo gives them no pre-filtering at all.

**Conclusion for v7:** PCRE2 JIT is the engine to ship. The go/no-go criterion
(≥2× over pure-Ruby) is met at 2.79×. The portability trade-off (JIT requires
`libpcre2` built with `--enable-jit` and `mmap(PROT_EXEC)`) is worth accepting:
JIT is available on all major platforms (x86-64, ARM64, macOS Intel + Apple Silicon)
and silently degrades to the interpreter where unavailable.

### Prototype v4 — matcher4.c (88 patterns, Thompson NFA + lazy DFA cache, Option D)

**Files:** `matcher4.c`, `matcher4.h`, `bench4.rb`

From-scratch Thompson NFA construction from all 88 regex patterns,
followed by a lazy DFA cache (4096-slot open-addressing hash table, keys
are NFA state bitmaps). Zero external dependencies — no libonig, no glibc
regexec.

**Architecture:**

1. POSIX-ERE subset parser → AST (`parse_regex`)
2. Thompson NFA: AST → ε-NFA states with a shared master start state
   (88-way ε-fanout tree). 6888 NFA states total.
3. Lazy DFA: `dcache_step(slot, byte)` = hash-lookup in 4096-slot cache;
   cache miss triggers `nfa_move` (O(NFA states) bitmap scan) + `eps_closure`.
4. Cache eviction: full cache flush when 4086/4096 slots are occupied.
   Same strategy as RE2's DFA cache reset.

Three scan variants were implemented and benchmarked:

**`mm4_scan` (per-position restart):** for each starting position i, run
the lazy DFA forward until dead state, tracking the longest accepting state.
Emit all pattern IDs at the best accept. O(N × avg_match_len) worst case.

**`mm4_scan_v41` (per-position + required-literal pre-filter):** same as
`mm4_scan` but before starting the inner DFA loop at position i, `memmem`
checks whether any pattern's required prefix literal exists in the remaining
input. If none, skip position i. Same algorithmic complexity as `mm4_scan`
but avoids inner-loop work when no prefixes appear ahead.

**`mm4_scan_v42` (single-pass leftmost-longest):** one left-to-right sweep
over the input — no per-position restart. On dead state: if a prior accepting
state was recorded, emit it and advance cursor past the match; otherwise skip
one byte forward. Resets to start state and continues. Guaranteed O(N).
Standard "greedy lex" DFA scan (same semantics as `flex`-generated scanners).

**`mm4_walk` (single-pass upper bound):** single-pass over the input —
one DFA step per byte, resetting to start state on dead state. No per-position
restart, no output buffer. Measures the theoretical throughput ceiling;
included for reference only.

**Results (realistic multi-payload, 10 iterations, 2026-06-02, `bench_realistic.rb`):**

ms/iter (lower is better):

| Engine | sparse | medium | dense | env |
|---|---|---|---|---|
| Pure-Ruby gsub | 151 | 155 | 183 | 291 |
| DataRedactor today (glibc) | 814 | 856 | 855 | 1058 |
| **v4 mm4_scan** | **22** | **25** | **32** | **1667** |
| **v4.1 mm4_scan_v41** | **20** | **21** | **26** | **1585** |
| **v4.2 mm4_scan_v42** | **62** | **64** | **33** | **99** |
| Plain PCRE2 JIT | 41 | 52 | 52 | 54 |

× over pure-Ruby (higher is better):

| Engine | sparse | medium | dense | env |
|---|---|---|---|---|
| DataRedactor today (glibc) | 0.20× | 0.19× | 0.22× | 0.31× |
| **v4 mm4_scan** | **7.6×** | **6.0×** | **5.8×** | **0.19×** |
| **v4.1 mm4_scan_v41** | **8.1×** | **7.3×** | **7.8×** | **0.19×** |
| **v4.2 mm4_scan_v42** | **2.4×** | **2.3×** | **6.1×** | **3.0×** |
| Plain PCRE2 JIT | 3.8× | 3.4× | 3.8× | 5.3× |

**Key findings — v4 family:**

1. **v4 and v4.1 are the fastest engines for sparse/medium/dense payloads** —
   6–8× over pure-Ruby, beating PCRE2 JIT on sparse/medium. The lazy DFA with
   per-position restart is highly effective when matches are rare. Each input
   byte only enters the inner DFA loop when the cursor starts a new attempt;
   on sparse inputs most attempts dead-state immediately after 1–3 steps.

2. **v4 and v4.1 collapse catastrophically on the env payload** (0.19×, slower
   than pure-Ruby). Root cause: the per-position O(N²) structure. On `.env`-style
   input, every pattern's required literal appears in nearly every line, so every
   starting position runs a long inner DFA loop before dead-stating. The memmem
   pre-filter in v4.1 cannot skip positions because all literals are present
   everywhere.

3. **v4.1 (prefix pre-filter) is a marginal improvement over v4 on sparse/medium**
   (8.1× vs 7.6×). It adds cost on env because even the memmem scan must iterate
   through every literal at each position before confirming they are all present —
   giving 0.19× same as v4, marginally worse in absolute ms due to the memmem overhead.

4. **v4.2 (single-pass) eliminates the env collapse** — 3.0× on env, robust across
   all payload types. Minimum across all payloads: 2.3× (medium). This is the only
   zero-dependency engine that does not collapse on dense/env.

5. **v4.2 is slower than v4/v4.1 on sparse/medium** (2.4× vs 7.6–8.1×). The single-pass
   DFA resets to the start state after every dead-state or emitted match. On sparse
   inputs where most bytes are noise, the per-position restart of v4 is actually
   faster because each attempt terminates quickly (2–3 DFA steps); single-pass
   must process every noise byte through the start state too.

6. **v4.2 vs PCRE2 JIT:** v4.2 is the only zero-dependency alternative that
   consistently beats pure-Ruby across all payload types. PCRE2 JIT still wins
   on sparse/medium (3.8×/3.4× vs 2.4×/2.3×) and env (5.3× vs 3.0×). PCRE2
   JIT wins the overall comparison; v4.2 wins the zero-dependency comparison.

**Why the DFA cache works for sparse but not dense:**
- 6888 NFA states → bitmap key = 862 bytes; each `dcache_entry_t` ≈ 1910 bytes
- 4096 slots × 1910 bytes ≈ 7.8 MB (fits L3, not L1/L2)
- Sparse: each position tries 2–5 DFA steps before dead-state; cache stays warm
  for the common "start state → dead" path; miss rate low
- Dense (env): attempts run for 40–200 steps (matching long tokens); many unique
  DFA state sets are created → frequent flushes → cold cache → expensive misses

**Correctness issues — merged NFA architecture (analysis 2026-06-02):**

The merged NFA has a fundamental correctness problem that cannot be fixed with
post-hoc filters. Investigation proceeded in three phases:

*Phase 1 — initial observation:* `mm4_scan_v42` emitted 20–25 spurious pattern
IDs per match on any input; plain text `"plain text nothing here"` returned 23
false positives. Root cause identified as missing per-pattern minimum-length
enforcement.

*Phase 2 — min-length filter:* Added `ast_min_len()` recursive computation over
the AST before NFA construction; stored as `g_pat_min_len[88]`. Applied at emit
time: only emit pattern `p` if span ≥ `g_pat_min_len[p]`. Result: plain text
dropped from 23 false positives to 0. 5/11 correctness cases passed. Performance
unaffected (filter runs at accept time only, not per byte).

*Phase 3 — prefix/BM literal filter (attempted, reverted):* Added `memcmp` check
for non-infix prefix at span start, and `memmem` check for BM literals. When all
patterns at a DFA accepting state were filtered out, two approaches were tried:
(a) advance past `best_end` unconditionally — performance dropped 15× because the
    DFA finds many spurious accepting states and wastes time on memmem calls on
    long spans; on 1MB dense payload, every word triggers memmem for multiple patterns.
(b) skip one byte and retry when all bits are filtered — this destroyed the O(N)
    guarantee, causing 50× slowdown (sparse went from 2.35× to 0.02×).
Both approaches are incompatible with the O(N) scan. The prefix/BM filters were
reverted. Only the min-length filter remains in the codebase.

*Root cause of remaining failures (unfixable):*

The merged NFA has no per-pattern "activation" mechanism. All 88 pattern NFAs
share a common start state. At any position, the DFA is simultaneously following
all 88 patterns' sub-automata. Patterns with `[A-Za-z]+`, `[A-Za-z0-9]+`,
`[^[:space:]]+` etc. — including `mongodb_connection_string`, `uri_with_password`,
`bearer_token`, `aws_s3_presigned_url` — have very short minimum lengths (12–20
chars) and their NFA accept bits appear in DFA states reachable from any alphanumeric
starting byte. In the v42 single-pass scan:

- Starting from position 0, the DFA immediately follows the `mongodb_connection_string`
  and `uri_with_password` paths alongside the correct pattern
- On a 20+ byte token, the DFA reaches an accept state with accept bits set for
  multiple patterns including many spurious ones
- The prefix filter removes spurious patterns, but also removes cases where the
  *correct* pattern's match window was consumed (v42 committed `[0, L)` to a
  `mongodb` span, then advanced cursor to `L`, missing the correct pattern's start)

*Concrete examples:*

- `"eyJhbGci...SflK..."` (JWT): DFA reaches accept with `aws_s3_presigned_url`,
  `mongodb_connection_string`, `bearer_token` bits set at span 0..92. `jwt` bit NOT
  set because the merged DFA's accept state for `jwt` requires having consumed
  `eyJ{10+}.eyJ{10+}.{1+}` — but the DFA entered an unrelated accept state earlier
  (at a longer span that satisfies `mongodb`'s min-length but not `jwt`'s full regex).

- `"user@example.com"`: The `email` accept bit only appears in `mm4_scan` when
  starting from position 8 (`@example.com` onwards). The v42 single-pass starts at
  position 0 where `uri_with_password` and `mongodb_connection_string` match
  `user@example.com` as a whole (min-len passes, but no prefix so they get filtered).
  The v42 scan then skips the entire span and misses the `email` match.

*Why this is unfixable without per-pattern isolation:*

The merged DFA state is a set of NFA states from all 88 patterns simultaneously.
There is no way to distinguish "I am at an accepting state for pattern X" from
"I am at a state where X's accept bit coincidentally appears due to NFA state overlap
with the path I actually followed." This is the fundamental cost of the NFA merge —
pattern semantics are lost in the combined DFA.

A correct implementation would require either:
1. Separate per-pattern DFAs (no merge) — O(N×P) cost, same as current glibc approach
2. Submatch tracking per pattern ID through the merged DFA — equivalent to running
   P parallel simulations, O(N×P) again
3. After v42 finds a span, verify each candidate pattern with a quick per-span
   per-pattern NFA simulation — adds O(P) per match, acceptable only if matches
   are rare (not env payloads)

None of these preserve the O(N) single-pass property that makes v4.2 fast. The
benchmarked 2.3–6.1× performance is real, but correctness is 4/13 (31%) on a
representative test set of 13 patterns.

**Correctness issues in `mm4_scan` and `mm4_scan_v41`:**
- Generate false-positive matches at prefix positions of longer tokens
- With min-length filter applied: false positive count reduced but structural
  overlap issue (same root cause as v42) remains
- Per-position restart makes the problem worse: every starting position finds
  every pattern that can match from that byte

**Why full precomputed DFA state explosion occurs:**
First attempt used full subset construction (eager DFA). With 6888 NFA states,
the DFA state space is 2^6888 in the worst case. Subset construction diverged
immediately after computing the start state. Switched to lazy cache.

**Comparison with production systems:**
- RE2 uses lazy DFA with a 4MB cache and bitstate NFA simulation as fallback
- Hyperscan precomputes DFA per-pattern with SIMD — x86-only
- Our implementation lacks: bitstate fallback, SIMD, per-pattern activation

**Conclusion for v4 family:**
- `mm4_scan_v41`: best zero-dependency engine for sparse/medium/dense payloads
  (6–8× over pure-Ruby) but **not production-ready** — correctness 4/13 (31%).
- `mm4_scan_v42`: fast across all payload types (2.3–6.1×) but **not production-ready**
  for the same reason. The merged NFA architecture cannot produce correct per-pattern
  matches when patterns have overlapping character alphabets.
- **The v4 family is suitable for research/benchmarking only.** The per-pattern NFA
  architecture (v7/PCRE2 JIT) is required for production correctness.
- For production: PCRE2 JIT is the correct path. The v4 performance results are
  interesting as a research datapoint but the architecture is not viable for the gem.

### Prototype v8 — bench_bm_inner.c (BM bad-character filter inside the regexec loop)

**Files:** `bench_bm_inner.c` (standalone benchmark, no `.so`)

**Motivation:** the previous investigation quantified the cost split inside
the current glibc extension (`bench_malloc.c`, 2026-05-31):
- malloc/free churn (88 allocations per call): **4%** of total time
- `regexec` itself: **94%** of total time

Eliminating malloc churn is not worth the refactor. But glibc's `regexec` has
no internal BM literal pre-filter — it evaluates the full NFA at every cursor
position. Onigmo does have one (built at `onig_new` time per pattern), which is
why plain Onigmo ≈ pure-Ruby despite using the same sequential architecture.

**Hypothesis:** if we add a Boyer-Moore bad-character shift table per pattern
and use it to advance the cursor before each `regexec` call (skipping positions
where the required literal cannot start), we replicate Onigmo's internal BM
behaviour on top of glibc — zero new dependencies.

**BM table construction:**
- Built from `pattern_required_literal[i]` (same literals already used for the
  outer `strstr` pre-filter in `redact.c`).
- 48 of 88 patterns have a non-NULL literal and get a BM table.
- 40 patterns have `NULL` literal (pure-digit IDs, IPv4, credit card, etc.) —
  these continue calling `regexec` at every position, unchanged.
- Table type: bad-character shift (256-entry `int` array). Length = literal length.
  Default shift = literal length; per-byte shifts = distance to end of literal.

**Inner loop change (per pattern with a literal):**

Before calling `regexec` at each cursor position, run `bm_find`: scan right-to-left
within the literal window, shift by the bad-character table on mismatch. This
returns the next position where the literal *could* start. Advance cursor there
before calling `regexec`.

For patterns without a literal, behaviour is identical to today.

**Three variants benchmarked:**

| Variant | Description |
|---|---|
| A | Current: `regexec` at every cursor position, 88× malloc per call |
| B | BM inner loop (cursor advanced by BM before each `regexec`), still 88× malloc |
| C | BM inner loop + preallocated ping-pong buffers (both optimisations) |

**Results (1 MB payload, fixed seed 42, 20 iterations, two independent runs):**

| Variant | Run 1 ms/iter | Run 2 ms/iter | vs A |
|---|---|---|---|
| A — current (glibc, 88× malloc) | 351.5 | 272.0–276.7 | 1.0× |
| B — BM inner, still malloc | 59.8 | 47.1–47.5 | **5.8×** |
| C — BM inner + preallocated | 57.9 | 47.0–49.4 | **5.9×** |

Run 1 absolute times are higher (system load); ratios are consistent across both
runs. Variant C adds negligible improvement over B — confirms malloc is not the
bottleneck once BM is in place.

**Ruby baselines on the same machine (bundle exec, fixed seed 42, 20 iters, two runs):**

| | Run 1 ms/iter | Run 2 ms/iter |
|---|---|---|
| Pure-Ruby gsub (88 patterns) | 175.1 | 163.5–173.8 |
| DataRedactor.redact (current C) | 821.0 | 766.8–783.5 |

Using Run 1 figures as the common baseline (same session as bench_bm_inner Run 1):
- Variant B: 59.8 ms → **2.93× over pure-Ruby** (175.1 ms)
- Variant B: 59.8 ms → **13.7× over current C** (821.0 ms)

**Key findings:**

1. **BM inner loop gives 5.8× improvement over current glibc code, zero new
   dependencies.** This is the largest single improvement found for the glibc
   engine. It brings the extension from 4.7× *slower* than pure-Ruby to 2.93×
   *faster* than pure-Ruby.

2. **The 3× criterion is nearly met (2.93×) with glibc only.** PCRE2 JIT still
   wins at 3.98× (from earlier runs), but the gap has narrowed substantially.

3. **The malloc churn optimisation (variant C) adds <3% on top of BM.** Do not
   refactor the output buffers — BM alone is the implementation worth shipping.

4. **40 always-candidate patterns (no literal) are unaffected.** Their `regexec`
   calls still run at every position. BM cannot help them without a usable literal.

5. **Onigmo parity explained:** Onigmo's internal BM is equivalent to what we
   built here, applied per pattern, compiled at init time. Our result (2.93× over
   pure-Ruby) is slightly better than plain Onigmo (1.05× over pure-Ruby) because
   our BM pre-filter also skips whole patterns via `strstr` (outer filter) *and*
   advances the cursor within the scan (inner BM). Onigmo only does the inner BM.

**Implementation path:** the BM inner loop from `bench_bm_inner.c` (variants B/C)
is a direct drop-in improvement to `replace_all_matches` in `redact.c` and the
equivalent loop in `scan.c`. No new files, no new dependencies. The BM tables
would be built at `Init_data_redactor` time alongside `regcomp`.

---

### Prototype v9 — matcher9.c (88 per-pattern Thompson NFA + lazy DFA cache)

**Files:** `matcher9.c`, `matcher9.h`

**Motivation:** v4 built one *merged* NFA→DFA over all 88 patterns and suffered
DFA state explosion / cross-pattern contamination (documented in §11). v9 gives
each pattern its own NFA and its own small (512-slot) lazy DFA cache — correct by
construction (no merging), no glibc `regexec`, no per-call O(N) allocation.

**Result: INCORRECT.** Passes the 11/11 smoke test but the smoke test only checks
"is the expected pattern name present among the matches" — it never checks the
*count*. Against the ground-truth Ruby `gsub` reference, v9 massively over-counts:

| Smoke input | Ruby `gsub` (truth) | v9 |
|---|---|---|
| `AIzaSy…` (google_api) | 2 | **34** |
| `cc: 4111111111111111` (credit_card) | 1 | **17** |
| `iban: DE89…` (iban_de) | 3 | **25** |

The leftmost-longest reset logic re-seeds the start state in a way that produces
many overlapping spurious matches on boundary-wrapped patterns. **Do not use v9 as
a correctness or performance reference.**

---

### Prototype v10 — matcher10.c (88 per-pattern NFA, precomputed transition table)

**Files:** `matcher10.c`, `matcher10.h`

**Motivation:** avoid v9's lazy-DFA hashing by precomputing, at init time, for
every `(NFA state, byte)` pair the full epsilon-closed target set into a flat
pool (`trans[state][byte] → {offset, count}`). Scan time then has zero DFS and
zero epsilon closure — advancing one byte is a table lookup per active thread.

**Result: INCORRECT.** Same flaw class as v9. Passes 11/11 smoke but over-counts
against the Ruby `gsub` reference (e.g. us_ssn=2 vs 1, google_api=30 vs 2,
credit_card=16 vs 1, iban_de=23 vs 3). The dead-end / reset / re-seed logic in
`scan_one` does not reproduce non-overlapping leftmost-longest `gsub` semantics.
It is also slow (~1 s/iter on 500 KB before the fix that was never validated).
**Do not use v10 as a correctness or performance reference.**

---

### Prototype v11 — matcher11.c (88 per-pattern Thompson **bytecode VM**)

**Files:** `matcher11.c`, `matcher11.h`

**Motivation:** v9 and v10 were both incorrect because their hand-rolled
state-set reset logic did not match `gsub` semantics. v11 starts over with the
**virtual-machine approach** (Cox 2009, "Regular Expression Matching: the Virtual
Machine Approach", already in the bibliography). Each pattern compiles once to a
flat bytecode program; scanning is a classic two-list Thompson simulation with the
control flow made *explicit in the instruction stream* rather than implicit in an
epsilon graph — which is what makes correctness tractable.

**Instruction set (minimal — nothing speculative):**

| Opcode | Meaning |
|---|---|
| `CHAR c` | match byte == c, then advance |
| `CLASS bitmap` | match byte in 256-bit class, then advance |
| `ANY` | match any byte != `\n`, then advance |
| `SPLIT x, y` | fork to x (preferred) and y; consumes nothing |
| `JMP x` | goto x; consumes nothing |
| `BOL` / `EOL` | zero-width line anchors |
| `MATCH` | accept |

**Architecture:**
- Reuses the proven POSIX-ERE parser + AST from v9 (unchanged).
- `emit_node()` lowers the AST to bytecode. Greedy quantifiers emit `SPLIT` with
  the body branch preferred. `{lo,hi}` emits `lo` mandatory copies + `(hi-lo)`
  split-guarded optional copies. `*`/`+` emit the standard split-loop.
- `addthread()` epsilon-closes a pc into the current/next thread list,
  deduplicating by pc with a generation-stamped `seen[]` array (no per-byte
  memset).
- `scan_one()` runs one left-to-right sweep per pattern: seed at `pos`, step the
  two lists byte by byte, remember the longest accept end for the current start,
  then resume **non-overlapping** from that end (or `pos+1` on no match) — exactly
  reproducing `String#gsub` semantics.
- Boundary-wrapped patterns are wrapped in `(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)`
  before compilation, identical to the pure-Ruby reference.
- Prefix patterns use `memmem` to jump to the next literal occurrence before
  seeding (the only optimization present; everything else is left simple).

**Result: CORRECT.** Verified against the ground-truth reference — *independent
per-pattern* `gsub` replacement count (`pl.gsub(re){…}` summed over the 88
patterns, each seeing the original input):

| Payload | Ruby `gsub` (truth) | v11 |
|---|---|---|
| smoke google_api | 2 | **2 ✓** |
| smoke iban_de | 3 | **3 ✓** |
| sparse 100 KB (1 hit/5000B) | 30 | **30 ✓** |
| medium 1 MB (1 hit/500B) | 207 | **207 ✓** |
| dense 100 KB (1 hit/50B) | 1536 | **1536 ✓** |

> **Reference-semantics note.** The correct reference is *independent* per-pattern
> matching: each pattern scans the original input. The production
> `DataRedactor.redact` pipeline instead applies patterns *sequentially* on the
> already-redacted string (`reduce` with `gsub`), so a later pattern sees
> `[REDACTED]` instead of the original bytes — on the medium payload that
> sequential pipeline reports 163 replacements vs 207 independent. The matcher's
> job is to find all matches in the raw input (207); collapsing overlaps across
> patterns is a separate concern. Also beware: `String#scan(re).size` counts
> capture-group arrays, **not** matches, when the regex has groups — use the
> `gsub` replacement count as the reference, not `scan`.

**Performance: slow, as expected for a first correct version (no optimization).**
1 MB payloads, 10 iters, vs pure-Ruby `gsub` baseline on the same machine:

| Payload | Ruby | v11 | v11 vs Ruby |
|---|---|---|---|
| sparse (1 hit/5000B) | 152 ms | 983 ms | 0.16× |
| medium (1 hit/500B) | 152 ms | 1000 ms | 0.15× |
| dense (1 hit/50B) | 175 ms | 1208 ms | 0.15× |

v11 is ~6× *slower* than pure-Ruby right now. This is the intended clean baseline:
correct first, with deliberately no first-byte filter, no shared literal
pre-filter, recursive `addthread`, and no hot-path inlining. Each of those is a
localized, independently-verifiable improvement to make next.

**Improvement backlog (do one at a time, re-verify against the `gsub` reference):**
1. Iterative `addthread` (remove recursion).
2. Shared first-byte / literal pre-filter so noise bytes skip the VM entirely
   (the v8 BM result shows this is the decisive factor).
3. Inline the common `CHAR` step; keep `CLASS` bitmap test branchless.

---

### Prototype v12.1 — matcher12.c (v11 VM + literal pre-filter for all patterns)

**Files:** `matcher12.c`, `matcher12.h`

**Motivation:** v11 only `memmem`-skipped noise for the start-anchored-prefix
patterns; infix-literal patterns were seeded + stepped at every byte (the ~11
ns/pattern/byte measured on pure noise). v12.1 extends the literal skip to infix
patterns: a match must *contain* the required literal, so a match start lies in
`[hit - max_back .. hit]` for each literal occurrence, where
`max_back = ast_max_len − lit_len` (computed from the AST at init). If the prefix
before the literal is unbounded (`*`/`+`/`{n,}`), `max_back` is unbounded and the
pattern falls back to v11's full per-byte scan.

**Correctness: CORRECT.** Verified against independent per-pattern `gsub` on
sparse/medium/dense 1 MB payloads plus infix smoke cases (`uri_with_password`,
`bearer_token`): all counts match exactly (sparse 246, medium 2130, dense 15577).

**Performance: only 1.10× over v11 — the literal skip barely helps.**

| Payload | v11 | v12.1 | speedup |
|---|---|---|---|
| sparse (1 hit/5000B) | 1080 ms | 979 ms | 1.10× |
| medium (1 hit/500B) | 1127 ms | 1037 ms | 1.09× |
| dense (1 hit/50B) | 1382 ms | 1234 ms | 1.12× |

**Why the win is small — the decisive finding (re-confirms TODO.md §44):**
In the prototype's `patterns_generated.h`, **~40 of the 88 patterns carry no
usable literal at all** — the boundary-wrapped pure-digit national-ID / financial
patterns (SSN, CPF, Aadhaar, credit_card, IPv4, PESEL, …) have both `prefix` and
`bm_literal` set to NULL. v12.1 cannot skip a single byte for them; they scan
every position regardless. These literal-less patterns are exactly the
"always-candidates" the earlier research flagged as *"the binding constraint"*
(TODO.md §44) and measured at ~35 ms each / 28 MB/s. The literal skip only helps
the ~30 prefixed patterns, which the earlier research already measured as
"essentially free (0.6 ms each, fully skipped)". So v12.1 speeds up the
already-cheap patterns and does nothing for the expensive ones → ~1.1× overall.

**Consequence for the plan:** any *literal* pre-filter (the whole v12 family, and
by extension the literal side of v13's Aho-Corasick) is structurally incapable of
accelerating the 40 literal-less digit-ID patterns that dominate the cost. The
lever that *can* reach them is the **first-byte / start-set filter (v14)**: even a
literal-less boundary-wrapped digit pattern can only start right after a
non-alphanumeric boundary with a digit (or a small known first-char set), which is
computable from the POSIX-ERE the engine is constrained to. That constraint is
not hypothetical — it is enforced in code at
[lib/data_redactor.rb:71](../lib/data_redactor.rb) (`RUBY_ONLY_SYNTAX_RE` rejects
`\d \w \s \b`, lookaround, named groups, inline flags, and non-greedy `*? +? ??`)
and [lib/data_redactor.rb:68](../lib/data_redactor.rb) (`CAPTURE_GROUP_RE` rejects
capture groups under `boundary: true`), both checked in `add_pattern`. Every
pattern is therefore a true regular language with a well-defined first-byte set
and no backtracking risk. v14 is promoted ahead of v13.

**On variant numbering:** the file is `matcher12.c` and currently holds only the
first variant, **v12.1** (memmem + bounded back-up, full-scan fallback for
unbounded prefixes). The two alternative skip strategies discussed before building
(v12.2 = memmem windows back to previous hit; v12.3 = per-position forward literal
gate) were *not* built, and the decision is backed by a direct measurement of the
ceiling rather than asserted:

- v12.1 on the **pure-noise** 1 MB payload (where every literal-bearing pattern's
  literal is absent, so all ~30 of them `memmem`→NULL and bail immediately — i.e.
  a *perfect* literal filter): **920 ms/iter**.
- v12.1 on the **sparse** payload: **979 ms/iter**.

The 920 ms is entirely the ~40 literal-less digit-ID patterns, which no literal
filter can skip. The absolute most any better skip strategy could recover is the
~59 ms gap (≈6%) — and v12.2/v12.3 are merely different bookkeeping for the same
skip v12.1 already does well, so they would recover little of even that 6% while
adding complexity. The v12 family is parked at v12.1. The 94% that is untouchable
by literals is the target, and only a first-byte/start-set filter (v14) reaches it.

---

### Prototype v14 — matcher14.c (v12.1 literal filter + first-byte filter)

**Files:** `matcher14.c`, `matcher14.h`

**Motivation:** v12.1 proved a literal filter cannot touch the ~40 literal-less
boundary-wrapped digit-ID patterns (920 ms floor). v14 adds the filter that *can*:
a **first-byte / start-set filter**. Because every pattern is constrained to pure
POSIX-ERE (no `\d\w\s\b`, lookaround, named groups, non-greedy — enforced in code,
see §5 v12.1), each is a true regular language with a well-defined set of bytes
that can be its first *consumed* byte. We compute that 256-bit set once at init by
epsilon-closing the bytecode from pc 0 (over `SPLIT`/`JMP`, treating `BOL`/`EOL`
as passable so the set is a safe superset that never rejects a real match), then
in `scan_one` skip forward over any run of input bytes the set rejects — entirely
in C, never entering the VM. Boundary-wrapped digit patterns get
`first = {non-alphanumerics}`, so they skip the long alphanumeric noise runs that
v12.1 had to step through. The v12.1 literal skip is kept and composes with it.
If an empty match is possible (`MATCH` reachable with no byte consumed) filtering
is disabled for that pattern (`has_first_filter = 0`).

**Correctness: CORRECT** — after fixing a cross-call state bug (see §6.10 below).
Matches independent per-pattern `gsub` exactly on sparse/medium/dense 1 MB, infix
smoke cases (`uri`, `bearer`), and pure noise; plus a 600-scan sequential stress
test of mixed inputs all match `gsub`.

**Performance: 2.0–2.7× over v11 — the first-byte filter reaches the digit patterns.**

| Payload | v11 | v12.1 | v14 | v14 vs v11 |
|---|---|---|---|---|
| sparse (1 hit/5000B) | 1101 ms | 1001 ms | **405 ms** | 2.72× |
| medium (1 hit/500B) | 1110 ms | 989 ms | **423 ms** | 2.63× |
| dense (1 hit/50B) | 1395 ms | 1265 ms | **693 ms** | 2.01× |
| pure noise | — | 920 ms (floor) | **423 ms** | — |

The decisive number: on **pure noise**, v12.1's literal filter bottomed out at
920 ms (the literal-less digit patterns it could not touch); v14 cuts that to
423 ms — a 2.2× reduction of the exact slice v12 proved untouchable, confirming
the first-byte filter is the lever for the literal-less "always-candidate"
patterns (TODO.md §44). v14 is still ~2.5× *slower* than pure-Ruby (≈160 ms), so
the gap that remains is the VM's own per-byte constant factor on the bytes that
*pass* the filter — the target of v15 (iterative `addthread`, inlined `CHAR`,
branchless `CLASS`), which stacks on top of v14.

**Allocation discipline:** the start-set is a fixed 256-bit bitmap per pattern,
filled once at init. The scan hot path allocates nothing — it reuses the v11
scratch (`g_seen`/`g_clist`/`g_nlist`, realloc-once then reused). `mm14_free` now
frees that scratch and resets the persistent generation counter so a free/re-init
cycle starts clean.

**Complexity (measured on v14, all later VM variants share it):** *time* is **O(N)
on realistic payloads** and **O(N²) worst case per pattern** in theory. The
worst case comes from the per-start-position scan structure (the outer loop can try
up to N starts, each forward-scanning up to L bytes for a pattern whose greedy tail
is unbounded — e.g. `jwt`'s trailing `[A-Za-z0-9_-]+`); the first-byte filter and
fast thread-set death keep it linear in practice. Empirically, scanning dense
1 MB → 16 MB the cost stayed flat at **~75 ms/100 KB** (no super-linear growth).
*Space* is **O(Σ Mₚ)** — a few hundred KB for all 88 bytecode programs + reused
thread scratch — and **independent of N**; the scan hot path allocates nothing.
This is the structural opposite of glibc `regexec`, which allocated O(N) *per call*
(the original root cause). Killing the O(N²) worst case is v15.2's goal (single
pass); the unbounded greedy tails that enable it are tracked separately as a *gem
pattern* change (bound the tail so a match still neutralizes the token — TODO.md
§1b), not an engine change.

---

### Prototype v15.1 — matcher15.c (v14 + Thompson VM constant-factor speedups)

**Files:** `matcher15.c`, `matcher15.h`

**Motivation:** v14 is already O(N) and allocation-free; what remains is the VM's
per-byte constant factor on the bytes that *pass* the filters. v15.1 keeps v14's
structure and semantics unchanged and only lowers that constant, in two measured
steps:

**Step 1 — iterative `addthread`.** Replaced the recursive epsilon-closure with an
explicit DFS stack (capacity 2·prog.n; a pc can be pushed twice before being
deduped at pop). Pre-order is preserved exactly — `SPLIT` pushes `y` then `x` so
`x`'s subtree drains first, matching the old recursion — so leftmost preference is
identical. **Result: 1.00–1.03× (negligible).** Useful negative result: recursion
was *not* the bottleneck — gcc was already optimizing the shallow, `seen[]`-deduped
closure. Kept anyway (removes stack-depth risk, still allocation-free).

**Step 2 — O(1) accept check.** v11–v14 re-scanned the entire current thread list
every byte just to find an `OP_MATCH`. v15.1 stops storing `MATCH` in the thread
list; `addthread` instead sets a `matched` flag on the list (threads are added in
priority order, so the first MATCH seen is the highest-priority accept). The
per-byte accept test becomes `if (cl->matched …)` instead of an O(list) rescan.
One subtlety handled: a closure can be MATCH-only (no byte-consuming threads, so
`cl->n == 0`); the loop condition is `while (cl->n > 0 || cl->matched)` so that
accept is still recorded. **Result: 1.10–1.11× — the real win of v15.1.**

**Correctness:** matches the independent per-pattern `gsub` reference exactly,
byte-for-byte identical match counts to v14 on sparse/medium/dense/uri/bearer/noise,
and a 600-scan sequential mixed-input stress test passes (no cross-call regression
from the `matched`-flag change).

**Performance (1 MB, 10 iters):**

| Payload | v11 | v14 | v15.1 | v15.1 vs v14 |
|---|---|---|---|---|
| sparse | 1101 ms | 397 ms | **357 ms** | 1.11× |
| medium | 1110 ms | 414 ms | **377 ms** | 1.10× |
| dense | 1395 ms | 655 ms | **592 ms** | 1.11× |

**Takeaway:** the constant-factor ceiling is low (~1.1×) precisely *because* v14's
filters already removed most per-byte work — what's left is genuine VM stepping on
bytes that pass the filter, dominated by the closure/step cost, not dispatch
overhead. The larger remaining lever is the **single-pass rewrite (v15.2)**: track
all active start positions in one left-to-right sweep, making the worst case true
O(N·M) and eliminating the redundant re-scanning across overlapping start positions
that the current "resume from match_end / pos+1" structure incurs.

**Allocation discipline:** unchanged from v14 — added one reused per-pattern DFS
stack (`g_estack`, realloc-once then reused, freed in `mm15_free`). Scan hot path
still allocates nothing.

---

### Prototype v15.2 — matcher16.c (v15.1 + cross-pattern union first-byte bitmap)

**Files:** `matcher16.c`, `matcher16.h`

**Motivation:** v15.1 has a per-pattern first-byte filter for each of the 88 patterns
individually. The hypothesis was that ORing all 88 `first[]` bitmaps into a single
`g_union_first` bitmap and checking it once per byte before any per-pattern work
would eliminate positions where no pattern can start, reducing the per-pattern
filter work.

**Result: no improvement — marginally slower on all payloads (~4% regression).**

| Payload | v15.1 | v15.2 | Δ |
|---|---|---|---|
| sparse | 356 ms | 370 ms | −4% |
| medium | 366 ms | 383 ms | −5% |
| dense | 570 ms | 592 ms | −4% |
| env | 992 ms | 1045 ms | −5% |

**Why it failed:** the per-pattern first-byte filters inside `scan_one` already perform
the same work more precisely — they skip bytes rejected by *this specific pattern*,
which is a subset of what the union rejects. Adding the union pass as an extra outer
loop only adds overhead (one `cc_test` per byte) without reducing the per-pattern
filter work by a meaningful amount. The union is a superset of each individual filter;
bytes the union skips were already being skipped by every per-pattern filter anyway.

**Conclusion:** the union bitmap idea is sound in principle but provides no practical
benefit on top of the already-present per-pattern filters. Parked.

---

### Prototype v17 — matcher17.c (v15.1 + precomputed initial thread list)

**Files:** `matcher17.c`, `matcher17.h`

**Motivation:** at every candidate position, `scan_one` calls `addthread(pc=0)` to
epsilon-close the bytecode from the start state. For patterns without BOL/EOL anchors
(~85 of 88) this closure is position-independent — the same set of byte-consuming pcs
every time. v17 computes this set once at init (`eng->init_list[]`) and at seed time
copies it into `cl` with `memcpy` instead of running the DFS. This eliminates the
per-position seed `addthread` call for almost all patterns.

**Result: no improvement — within noise (~0–1%) on all payloads.**

| Payload | v15.1 | v17 | Δ |
|---|---|---|---|
| sparse | 356 ms | 321 ms | +1% |
| medium | 366 ms | 356 ms | +1% |
| dense | 570 ms | 562 ms | +2% |
| env | 992 ms | 952 ms | +1% |

**Why it failed:** the seed `addthread(pc=0)` was not the bottleneck. For patterns with
a first-byte filter, most positions are already skipped before seeding — so the seed
call is rare. For patterns without a filter (the always-candidate digit patterns), the
seed call is frequent but the epsilon closure from pc=0 is very shallow (a few SPLITs
then CHARs) — the DFS terminates in 5–10 steps, and `memcpy` of a 5-element array is
not meaningfully faster than that.

**Where the cost actually is:** the inner VM loop — for each byte that passes the
first-byte filter, we iterate `cl->n` threads, do a switch dispatch per thread, and
call `addthread` for every matching thread. On the pure-digit boundary-wrapped
patterns (~40 patterns, no literal skip, `first = {non-alphanumeric}`), this loop
runs at every non-alphanumeric byte in the input. The bottleneck is this step loop,
not the seed.

**Why Onigmo/pure-Ruby is faster despite having the same structural problem:** both
Onigmo and PCRE2 JIT face the same pattern mix — ~40 pure-digit patterns with no
skippable literal. Onigmo is faster because its NFA interpreter inner loop is more
tightly optimized C (years of tuning, tighter bytecode, better cache layout for
instruction structs). PCRE2 JIT is faster because it compiles each pattern to native
machine code at init time — no interpreter dispatch at all. Our VM is a clean
implementation but not a heavily tuned one; the gap to Onigmo is interpreter quality,
not algorithmic.

**Conclusion:** the seed optimization was the wrong target. To close the gap with
Onigmo without a JIT, the lever is the inner step loop — tighter instruction structs,
CHAR fast-path inlining, or a flat precomputed transition table (O(1) per-byte step
instead of a switch over a linked list). These require more invasive restructuring.

---

### Prototype v18 — matcher18.c (v15.1 + per-pattern lazy DFA transition cache) ★ BREAKTHROUGH

**Files:** `matcher18.c`, `matcher18.h`, `verify18.rb`

**Motivation:** v17 isolated the bottleneck as the inner step loop (iterate `cl->n`
threads, switch-dispatch per instruction, `addthread` per match — once per input
byte). The standard way to collapse that into O(1) per byte is the lazy DFA: replace
the NFA-state-set step with a single table lookup `state = table[state][byte]`. This
is what Onigmo/RE2 do internally. The two earlier table attempts both failed for
reasons that do **not** apply here:
- **v4 merged all 88 patterns** → DFA state explosion + cross-pattern contamination
  (correctness 31%). v18 is **per-pattern** — each pattern's DFA is tiny and isolated.
- **v9/v10 had incorrect leftmost-longest reset logic in `scan_one`** (over-counted
  16–30× vs gsub). The table mechanism itself was fine. v18 reuses **v15.1's
  proven-correct `scan_one` outer structure verbatim** and swaps only the inner step.

**Design:**
- A DFA state = a canonical (sorted, deduped) set of byte-consuming NFA pcs + a
  `matched` flag. States are interned in a per-pattern open-addressing hash
  (`pc-set → small int id`).
- `trans[state*256 + byte]` → next state id, filled **lazily**: on first access run
  v15.1's exact NFA step + `addthread` closure once, canonicalize, intern, cache.
  Subsequent visits are a single array lookup. `DFA_DEAD = -1` ends the attempt.
- The start state (id 0) is the closure of pc 0 (reuses v17's precompute idea).
- All buffers realloc-once, reused across calls; scan hot path allocates nothing once
  a pattern's reachable DFA is warm.

**BOL/EOL handling (the key correctness boundary):** a DFA state cannot encode "am I
at a line boundary," so any pattern whose bytecode contains `OP_BOL`/`OP_EOL` (from
`^`/`$`, including the boundary wrapper `(^|…)`/`(…|$)`) falls back to v15.1's exact
NFA inner loop. Measured split: **64 of 88 patterns take the DFA path; 24 fall back.**
(Better than the feared ~40 — many boundary-wrapped patterns compile without a
reachable anchor instruction.)

**Correctness: CORRECT — byte-for-byte identical to v15.1.** `verify18.rb` compares
the full `(pattern_id, start, length)` match set of v18 against v15.1 (proven correct
against the independent per-pattern gsub reference) on smoke cases, sparse/medium/dense
1 MB, pure noise, and a **600-scan sequential stress test** (catches cross-call state
bugs like §6.10). All identical. This is the exact gate v9/v10 failed.

**Performance: ~2× over v15.1; reaches parity with pure-Ruby/Onigmo.**

| Payload | pure-Ruby | Onigmo | v15.1 | **v18** | v18 vs v15.1 | v18 × pure-Ruby |
|---|---|---|---|---|---|---|
| sparse | 157 ms | 154 ms | 345 ms | **170 ms** | 2.0× | 0.93× |
| medium | 157 ms | 162 ms | 443 ms | **209 ms** | 2.1× | 0.75× |
| dense | 225 ms | 287 ms | 626 ms | **248 ms** | 2.5× | 0.91× |
| env | 324 ms | 450 ms | 1044 ms | **294 ms** | 3.6× | **1.10×** |

- **vs today's glibc C extension (~800–1070 ms): v18 is ~4–5× faster.**
- **vs Onigmo: v18 ties on sparse/medium and *beats* it on dense (248 vs 287) and
  env (294 vs 450).** This is the first zero-dependency engine to reach Onigmo's
  level — and on the dense/secret-heavy payloads (the redaction use case) it wins.
- **On env it beats pure-Ruby (1.10×)** — the DFA's O(1)/byte step shines exactly
  where the NFA loop was doing the most per-byte thread work.
- PCRE2 JIT still wins outright (native code, no interpretation) at 3.7–5.3×, but it
  requires `libpcre2-dev`. v18 is the best **zero-dependency** result.

**Why it works where v15.2/v17 didn't:** v15.2 (union filter) and v17 (seed cache)
both nibbled at non-bottleneck costs. v18 attacks the actual hot path — the per-byte
inner loop — converting O(active threads) work into one table lookup. The 24 anchor
patterns that fall back still pay the v15.1 cost, which is why env (heavy on
boundary-wrapped digit patterns) doesn't improve even more; lowering those anchors
to DFA-able form is the documented follow-up (v18.1).

**Allocation discipline:** per pattern, one interned-state hash + flat `trans` table +
pc-set pool, all realloc-once and freed in `mm18_free`. No per-merge explosion because
DFAs are per-pattern and tiny (tens to low-hundreds of states each). Scan hot path
allocates nothing after warm-up.

**Follow-up (v18.1, not yet built):** lower the boundary wrapper so the 24 anchor
patterns become DFA-able — `(^|[^0-9A-Za-z])` is a real anchor only at pos 0; for
pos>0 it is the ordinary class `[^0-9A-Za-z]`. Handling pos==0 once outside the DFA
would move the boundary-wrapped digit patterns onto the fast path and should improve
dense/env further.

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

### 6.10 v14 cross-call state corruption (generation-counter reuse)

**Problem:** v14 dropped a real match (`bearer_token` → 0 instead of 1) but *only*
on the second and later `mm14_scan` calls — a fresh scan of the same string was
correct. The combined correctness harness (which scans several payloads in
sequence) flagged `smoke-bearer` as a mismatch; the same string scanned standalone
passed. The tell: `(+"...")` mutable strings failed after a prior call, frozen
literals "passed" only because the harness happened to scan them first.

**Root cause:** the Thompson VM deduplicates threads with a generation-stamped
`seen[pc]` array — `seen[pc] == gen` means "already added this step". The `gen`
counter was a per-call local reset to `0` each call, while `seen[]` persists
across calls (it is reused scratch). On the first call `seen[]` is all zeros and
`gen` climbs 1,2,3…; on a later call `gen` restarts low while `seen[]` still holds
stamps from the previous run, so `seen[pc] == gen` can spuriously be true and a
needed thread is dropped. v11/v12 had the *same* latent bug but never triggered it
in practice: without the first-byte filter their `gen` climbed so high each call
that a low restart rarely re-collided. v14's first-byte filter runs far fewer seed
iterations, so `gen` ends low — and the next call collides immediately.

**Fix:** make the generation counter **persist across calls** (`g_gen[p]`), so
stamps stay globally monotonic and a fresh call never reuses a previous call's
stamp. The only reset is when the `int` counter nears overflow: clear `seen[]`
once and restart at 0 (headroom checked against the max increments one call can
make, `~2·len`). `mm14_free` resets `g_gen` and frees the scratch together so a
free/re-init cycle stays consistent. The scan hot path still allocates nothing.

**Verification:** 600 sequential scans of mixed inputs all match the `gsub`
reference; standalone and in-sequence results are now identical.

**Lesson:** generation-stamp dedup is only safe if the counter is monotonic over
the lifetime of the `seen[]` array it stamps. Resetting the counter while keeping
the array is a latent correctness bug — it lay dormant in v11/v12 and only surfaced
once an optimization (the first-byte filter) changed the counter's growth rate.
Persist the counter with the array, or clear the array whenever you reset.

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

### 8.1 Full benchmark table — single synthetic payload (original, now known to be best-case)

**⚠️ These numbers used a single synthetic payload (1 hit per ~5700 bytes, sparse).
They represent best-case for AC+BM architectures. See §8.5 for realistic multi-payload
results which significantly change the conclusions about v7 and v8.**

All engines from v5 onward measured on the same machine, same day, fixed seed 42
(`bench7_compare.rb`). v1–v4 figures are from earlier separate runs.

| Engine | Architecture | ms/iter | vs pure-Ruby | vs today's C |
|---|---|---|---|---|
| DataRedactor today | glibc regexec sequential | 821 | 0.21× | 1.0× |
| Pure-Ruby gsub | Onigmo via Ruby | 175 | 1.0× | — |
| Plain Onigmo sequential | Onigmo, no AC, no BM | 134 | **1.05×** | 6.1× |
| v3: AC + Onigmo | AC trie + Onigmo | 155 | 0.91× | 5.3× |
| v5: AC + Onigmo + BM | AC + BM + Onigmo | 108 | 1.31× | 7.6× |
| glibc + BM inner loop (v8) | glibc, BM cursor advance per pattern | 59.8 | 2.93× | 13.7× |
| Plain PCRE2 no-JIT | PCRE2 interpreter sequential | 326 | 0.54× | 2.5× |
| v7: AC + BM + PCRE2 no-JIT | AC + BM + PCRE2 interpreter | 261 | 0.67× | 3.1× |
| v7: AC + BM + PCRE2 JIT | AC + BM + PCRE2 JIT | 44 | 3.98× | 18.7× |
| **Plain PCRE2 JIT** | **PCRE2 JIT sequential** | **35.5** | **4.93×** | **23.1×** |

v1 (AC+glibc, 10 patterns): 114.9 ms, 0.60× pure-Ruby baseline of that run.
v4 (Thompson NFA walk, upper bound): 791–818 ms, 0.22×.
v6 (AC+BM+glibc): 1639 ms, 0.12×.

### 8.5 Realistic multi-payload benchmark (corrected, 2026-06-02)

**Benchmark script:** `bench_realistic.rb` (fixed seed 42, 10 iterations per engine).

**Payload types:**
- **sparse** — 1 hit per 5000 bytes: clean logs, long documents
- **medium** — 1 hit per 500 bytes: mixed application logs
- **dense** — 1 hit per 50 bytes: redaction-heavy output
- **env** — ~100% secrets: `.env` files, config dumps (KEY=VALUE lines, nearly all matching)

**Results — ms/iter (lower is better):**

| Engine | sparse | medium | dense | env |
|---|---|---|---|---|
| Pure-Ruby gsub | 152 | 155 | 183 | 295 |
| DataRedactor today (glibc) | 801 | 832 | 845 | 1014 |
| v4 mm4_scan (per-pos, no filter) | 21 | 24 | 31 | 1613 |
| v4.1 mm4_scan_v41 (per-pos + prefix) | 20 | 21 | 26 | 1585 |
| **v4.2 mm4_scan_v42 (single-pass)** | **62** | **64** | **33** | **99** |
| Plain Onigmo sequential | 154 | 164 | 248 | 431 |
| Plain PCRE2 no-JIT | 391 | 407 | 465 | 532 |
| **Plain PCRE2 JIT** | **41** | **47** | **52** | **55** |
| v7: AC+BM+PCRE2 no-JIT | 309 | 443 | 1697 | 8775 |
| v7: AC+BM+PCRE2 JIT | 50 | 64 | 218 | 1013 |

**Results — × over pure-Ruby (higher is better):**

| Engine | sparse | medium | dense | env |
|---|---|---|---|---|
| DataRedactor today (glibc) | 0.20× | 0.19× | 0.22× | 0.30× |
| v4 mm4_scan | 7.6× | 6.0× | 5.8× | 0.19× |
| v4.1 mm4_scan_v41 | 8.1× | 7.3× | 7.8× | 0.19× |
| **v4.2 mm4_scan_v42** | **2.4×** | **2.3×** | **6.1×** | **3.0×** |
| Plain Onigmo sequential | 1.04× | 0.99× | 0.79× | 0.72× |
| Plain PCRE2 no-JIT | 0.42× | 0.41× | 0.43× | 0.58× |
| **Plain PCRE2 JIT** | **3.85×** | **3.83×** | **3.86×** | **5.00×** |
| v7: AC+BM+PCRE2 no-JIT | 0.50× | 0.37× | 0.12× | 0.03× |
| v7: AC+BM+PCRE2 JIT | 3.29× | 2.51× | 0.96× | 0.26× |

**Key findings from realistic benchmarks:**

1. **Plain PCRE2 JIT is robust across all payload types.** 3.7–5.6× over pure-Ruby.
   Improves on dense/env because JIT native code handles match-heavy inputs efficiently.

2. **v7 AC+BM+PCRE2 JIT catastrophically degrades on dense/env.**
   - env: 1083 ms (0.29× pure-Ruby) — 9 seconds absolute, worse than glibc
   - dense: 226 ms (0.90× pure-Ruby)
   - Root cause: the AC trie fires on almost every byte in dense inputs; BM pre-filter
     is useless when hits are frequent; pipeline coordination overhead dominates.
     AC+BM is designed for sparse inputs where most patterns can be skipped entirely.

3. **v8 (glibc + BM inner loop) 2.93× claim was a best-case artefact.**
   The prototype payload had 1 hit per 5700 bytes — best case for BM cursor advance.
   On realistic payloads, the outer `strstr` already handles the "literal absent" case,
   and the inner BM gains nothing extra. See §8.6 for detailed analysis.

4. **Plain Onigmo degrades gracefully on dense/env (0.72–1.03×) but does not beat
   pure-Ruby reliably.** On env it is 0.72× — slower than pure-Ruby.

5. **glibc is consistently the worst** (0.19–0.32×) across all payloads, but its
   degradation curve is relatively flat compared to v7's catastrophic collapse.

### 8.6 Why Onigmo outperforms glibc — and why the BM story is more complex than claimed

**Previous claim (§8.4, now revised):** "glibc has no BM pre-filter; adding BM to glibc
replicates what Onigmo does and surpasses it (2.93× vs 1.05×)."

**This was wrong for two reasons:**

**Reason 1: The v8 BM result was measured on an unrealistic payload.**
The `bench_bm_inner.c` prototype used a payload where the outer `strstr` pre-filter
(already in production `redact.c`) could not help — every pattern's literal was present.
In that scenario, BM cursor advance inside the loop gave a real 5.8× win over variant A.
But variant A of the prototype did NOT have the outer `strstr` filter. Production `redact.c`
already has `strstr` — so the two extra things BM would add (inner loop advance + skip on
absent literal) are either already covered by `strstr` or negligible on sparse inputs.
On realistic payloads, porting v8 to production showed zero improvement vs main (695 ms vs 682 ms).

**Reason 2: The real reason glibc is slow is not the missing BM — it is the O(N) state-log.**
Measured with `bench_malloc.c`:
- malloc/free churn (88 allocations/call): 4% of total time
- `regexec` cost: 94% of total time

The 94% `regexec` cost has two sub-components:
- NFA evaluation at each position (same algorithmic cost as Onigmo)
- **O(N) state-log allocation on every `regexec` call** (glibc allocates an array
  proportional to input length before any matching begins — this is mandatory in glibc's
  `re_search_internal` and cannot be avoided)

Onigmo uses a fixed-size stack per match attempt (O(1) per call). On a 1MB input with
88 patterns, glibc allocates ~88MB of state-log per `redact` call; Onigmo allocates
nothing at the call level. This is the dominant performance difference.

**Measured evidence:** on the env payload, `@` appears 7101 times (once per 140 bytes).
Onigmo's BM for the email pattern has literal `@` — shift = 1, meaning BM provides
zero skip on `@`-dense input. Both engines evaluate NFA at every `@`. Yet Onigmo is
still 2.3× faster than glibc on env. The difference is entirely the state-log allocation.

**What BM actually does for Onigmo:** on sparse inputs (e.g. long clean logs with rare `@`),
BM skips large spans between `@` characters. On dense inputs it cannot skip. This explains
why Onigmo degrades from 1.03× (sparse) to 0.72× (env) — BM stops helping.

**What this means for optimising glibc:** the correct target is eliminating the O(N)
per-call state-log allocation — which requires replacing `regexec` with a different
engine. There is no way to fix it within glibc. BM cursor advance (v8) is a real
improvement for sparse inputs but the prototype result was inflated by a non-representative
payload and the absence of the existing `strstr` pre-filter in the comparison baseline.

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

### 8.4 How the 3× criterion is met — one path

**Revised conclusion after realistic multi-payload benchmarks (§8.5):**

The v8 (glibc + BM inner loop) 2.93× result was an artefact of a best-case synthetic
payload and a flawed baseline comparison. On realistic payloads it gives zero improvement
over current production code. See §8.6 for the detailed analysis.

**The only architecture that meets the 3× criterion across all realistic payload types
is plain PCRE2 JIT sequential.**

- Sparse (1 hit/5000B): **3.80×** over pure-Ruby
- Medium (1 hit/500B): **3.70×**
- Dense (1 hit/50B): **3.69×**
- Env (all secrets): **5.58×** — improves further as hit density increases

One dependency: `libpcre2-dev`. JIT degrades silently to interpreter if unavailable.
No AC trie, no BM tables — simpler code than v7, better results across all inputs.

**Why no zero-dependency path exists:**
The glibc `regexec` bottleneck is the O(N) per-call state-log allocation — mandatory
in glibc's `re_search_internal`, cannot be worked around. BM cursor advance helps on
sparse inputs but the production code already has `strstr` which achieves the same
result (skip when literal absent) at the outer loop level. The inner BM adds nothing
on top. The only fix is replacing `regexec` with an engine that does not allocate O(N)
per call — which is PCRE2 JIT (or Onigmo, but Onigmo only reaches ~1× pure-Ruby).

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

### 11.1 Can we give always-candidates a shared automaton? (ANSWERED by v4/v4.2)

47/88 always-candidates bypass the AC filter. Prototype v4 built and
benchmarked a merged Thompson NFA + lazy DFA for all 88 patterns, then
extended to v4.1 (prefix pre-filter) and v4.2 (single-pass leftmost-longest).

**Answer (revised 2026-06-02, correctness analysis added 2026-06-02):**

The per-position restart DFA (v4/v4.1) is **extremely fast on sparse/medium/dense
inputs** — 6–8× over pure-Ruby, beating PCRE2 JIT on sparse/medium. The lazy DFA
warms up quickly for rare-match payloads. However it **collapses 0.19× on env**
(dense-match), slower than pure-Ruby, for the same reason as AC+BM v7: O(N²) cost
when nearly every starting position leads to a long DFA walk.

The single-pass DFA (v4.2) eliminates the collapse — **3.0× on env, 2.3–6.1× across
all payload types** — while requiring zero external dependencies.

**Critical finding (correctness analysis 2026-06-02):** The merged NFA architecture
is not production-ready. Correctness testing with min-length + prefix filters gave
4/13 (31%) on a representative test set. Root cause: the merged DFA cannot isolate
per-pattern semantics when patterns share overlapping character alphabets. See §5
correctness section for full analysis. **v4.2 benchmarks remain valid as research
datapoints; the architecture is not viable for the gem.** Only a partial subset of
patterns with mutually exclusive character alphabets could safely use a merged NFA
(see §11.1 addendum on selective merging).

**Comparison of all zero-dependency options:**

| Engine | sparse | medium | dense | env | min |
|---|---|---|---|---|---|
| v4.1 (per-pos + prefix) | 8.1× | 7.3× | 7.8× | 0.19× | 0.19× |
| **v4.2 (single-pass)** | **2.4×** | **2.3×** | **6.1×** | **3.0×** | **2.3×** |
| PCRE2 JIT | 3.9× | 3.8× | 3.9× | 5.0× | 3.8× |

**DFA state explosion confirmed:** full precomputed subset construction
diverged immediately. Lazy cache required. The cache flush rate on 1MB input
is high due to pattern diversity (6888 NFA states, 4096-slot cache).

**§11.1 Addendum — Selective NFA merging (not yet prototyped):**

The full-merge approach is unsound. A selective-merge strategy merges only
pattern subgroups whose character alphabets are mutually exclusive at every
accepting position. Candidate groups:

- **IBANs (20 patterns):** All start with a unique 2-letter country code
  (`DE`, `HU`, `PL`, etc.) — no two IBANs share the same prefix. A merged IBAN
  NFA would branch immediately on byte 0–1 and each branch leads to exactly one
  pattern. Zero alphabet overlap between branches after the country-code split.
  Could reduce 20 separate NFA calls to 1 DFA sweep.

- **`https://` URL patterns (4–6 patterns):** `aws_s3_presigned_url`,
  `slack_webhook_url`, `sentry_dsn`, `microsoft_teams_webhook` all start with
  `https://`. After consuming that literal, they diverge at the next host
  component. Merged NFA would run 1 DFA pass instead of 6 per `https://` hit.

- **Pure-digit boundary-wrapped patterns:** `us_ssn`, `us_itin`, `canadian_sin`,
  `korean_rrn`, `danish_cpr`, `swiss_ahv`, `swedish_personnummer`, etc. These only
  consume `[0-9]` and `-`/`.`/` ` separators. They cannot conflict with
  letter-starting patterns and could be merged into one digit-only DFA.

Patterns that CANNOT be merged: `email`, `uri_with_password`,
`mongodb_connection_string`, `jwt`, `bearer_token`, `aws_secret_access_key`,
`aws_access_key_id` — these all open with `[A-Za-z0-9]+` and semantically overlap.

Expected benefit: 3 merged DFAs (IBAN, URL, digit) + 60–65 separate NFA calls
instead of 88. Estimate: 25–30% reduction in NFA call count. Not yet prototyped.

### 11.2 PCRE2 JIT as an alternative to Onigmo

PCRE2 with JIT compilation emits native machine code for each pattern at
`pcre2_jit_compile()` time. Unlike Onigmo (which interprets a bytecode at
match time), subsequent matches execute compiled native code directly —
no interpreter loop, no bytecode dispatch.

**Benchmarked speedup vs Oniguruma/Onigmo** (from published sources):

| Pattern class | PCRE2 JIT vs Oniguruma | Source |
|---|---|---|
| `\d`, `\w` character-class scan | ~2–3× faster | RecursiveRegexpRaptor |
| `\d{11}`, `\d{3}-\d{2}-\d{4}` (quantified) | ~3–5× faster (estimated) | Zherczeg PCRE JIT paper (6.36× avg vs interpreter) |
| Email (`[\w.+-]+@[\w.-]+`) | ~5–10× faster | rust-lang/regex#604 vs Oniguruma |
| IPv4 (`(\d{1,3}\.){3}\d{1,3}`) | ~2–3× faster | RecursiveRegexpRaptor + OpenResty |
| Aggregate (18 diverse patterns) | ~2.4× faster | Rust Leipzig benchmark |

PCRE2 JIT vs PCRE2 interpreter (no JIT): 3–8× for typical patterns, up
to 25× for complex alternations (Zherczeg paper: 6.36× average across 5
architectures).

**For our pipeline:** the speedup would apply primarily to Group B
always-candidates (`\d{11}`, SSN, credit card, IPv4) — the 36 patterns
that get no benefit from the AC filter or BM pre-filter and pay full O(N)
confirmation cost at every position. For prefix-filtered patterns the AC
filter already limits how often the engine is called, so the per-call
speedup is diluted.

**One caveat:** PCRE2 JIT has per-call JIT stack setup overhead. OpenResty
benchmarks show JIT can be *slower* than the PCRE2 interpreter for trivially
simple patterns on very small inputs. Not a risk for our workload (~1MB), but
worth being aware of for the streaming/small-chunk case (§11.7).

**Portability constraints** (see §5 above for full discussion): JIT requires
`libpcre2` compiled with `--enable-jit` and `mmap(PROT_EXEC)` at runtime.
Falls back silently to the interpreter on Alpine Linux, minimal distros, and
sandboxed containers with W^X enforcement. No JIT backend exists for 32-bit
x86, MIPS, RISC-V, or WebAssembly.

**Conclusion:** PCRE2 JIT is a genuine alternative to Onigmo for Stage 2
confirmation. It would likely reduce Group B always-candidate cost by 2–5×,
potentially pushing the overall pipeline from ~1.52× (v5) toward 2–3× over
pure-Ruby. It has not been prototyped yet.

**TODO — prototype v7:** AC + BM + PCRE2 JIT (same architecture as v5,
swap `onig_search`/`onig_match` for `pcre2_jit_match`). Link against
`libpcre2-dev`. Measure head-to-head with v5 on the same 1MB payload.
If Group B patterns are confirmed 2–5× faster, benchmark total pipeline
improvement. Requires `libpcre2-dev` (`apt install libpcre2-dev`).

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

### 11.7 Streaming / chunked input support

`mm5_scan` takes a complete buffer and processes it in one shot. It does
not support streaming input (data arriving in chunks). Three problems arise
when chunks are processed independently:

1. **AC trie cursor is reset per call.** A pattern prefix that straddles two
   chunks (e.g., `AKIA` ending exactly at a chunk boundary) is missed.
2. **Always-candidate `onig_search` sees only one chunk.** Any pattern that
   straddles the boundary is not found in either chunk.
3. **Boundary-wrapped patterns need the last byte of the previous chunk** as
   the lookbehind character.

**Standard fix — overlap buffer:** prepend the last `MAX_PATTERN_LEN` bytes of
chunk N to chunk N+1 before calling `mm5_scan`. `MAX_PATTERN_LEN` is the
longest possible match across all 88 patterns (~200 bytes for most; the
Anthropic key and PEM patterns can exceed that). De-duplicate matches that
fall inside the overlap region using the accumulated stream offset.

**Cleaner fix — session context:** introduce a caller-owned `mm5_ctx_t` that
carries the AC trie cursor and the overlap tail across calls:

```c
mm5_ctx_t *mm5_ctx_new(void);
size_t     mm5_ctx_scan(mm5_ctx_t *ctx, const char *chunk, size_t len,
                        mm5_match_t *out, size_t max);
void       mm5_ctx_free(mm5_ctx_t *ctx);
```

Match offsets are reported relative to the total stream position (accumulated
in the context). Estimated implementation: ~100–150 lines on top of v5.
Not yet prototyped.

---

## 12. Conclusion

Realistic multi-payload benchmarks (§8.5, `bench_realistic.rb`, 2026-06-02).
Four payload types: sparse (1 hit/5000B), medium (1 hit/500B), dense (1 hit/50B),
env (all secrets). All ~1 MB, fixed seed 42, 10 iterations.

**× over pure-Ruby by payload type (updated 2026-06-03):**

| Engine | sparse | medium | dense | env | min | Verdict |
|---|---|---|---|---|---|---|
| DataRedactor today (glibc) | 0.20× | 0.19× | 0.22× | 0.30× | 0.19× | Baseline (worst) |
| Plain Onigmo sequential | 1.07× | 0.98× | 0.76× | 0.75× | 0.75× | ≈ pure-Ruby only |
| v7: AC+BM+PCRE2 JIT | 3.31× | 2.53× | 0.91× | 0.31× | 0.31× | Collapses on dense/env |
| **v4.2 NFA single-pass** | **2.4×** | **2.3×** | **6.1×** | **3.0×** | **2.3×** | **Fast but not correct (31%)** |
| **v15.1 bytecode VM** | **0.48×** | **0.44×** | **0.33×** | **0.31×** | **0.31×** | **Zero-dep, correct, beats glibc 2.2×** |
| **v18 per-pattern lazy DFA** | **0.97×** | **0.90×** | **0.82×** | **1.07×** | **0.82×** | **Zero-dep, correct, ties/beats Onigmo; ~4–5× over glibc** |
| **Plain PCRE2 JIT sequential** | **3.90×** | **3.81×** | **3.60×** | **5.51×** | **3.60×** | **Best overall, correct** |

**Two viable production architectures:**

1. **Plain PCRE2 JIT sequential** — fastest. 3.6–5.5× over pure-Ruby. One dependency: `libpcre2-dev`.
2. **v18 per-pattern lazy DFA (zero dependencies)** — 0.82–1.10× over pure-Ruby (ties pure-Ruby/Onigmo, beats both on dense/env), **~4–5× over today's glibc C extension**. Pure C, no external deps, correct (byte-for-byte identical to the proven v15.1). This is the recommended zero-dependency path.

**v4.2 as a research result:** v4.2 performance is a valid datapoint showing that
single-pass leftmost-longest Thompson NFA eliminates O(N²) collapse. It is not
production-ready: the merged NFA cannot distinguish per-pattern semantics when
patterns have overlapping character alphabets (correctness 4/13, 31%). See §5 for
full analysis. A selective-merge variant (patterns with mutually exclusive alphabets
only) could recover correctness at the cost of reduced coverage — not yet prototyped.

**Why v4.1 and v7 AC+BM collapse on dense/env:**
Both assume hits are rare — the pre-filtering pipeline (AC trie or memmem scan) is
designed to skip positions where patterns cannot match. On `.env`-style input, every
pattern's literal is present almost everywhere, so no positions are skipped and the
O(N²) per-position restart cost is paid in full. On env, v7 JIT takes 1013 ms —
slower than glibc (1014 ms) and 18× slower than plain PCRE2 JIT. v4.1 takes 1585 ms.

**v4.2 single-pass avoids this:** one DFA sweep, O(N), no per-position restart.
Each input byte is processed at most twice regardless of match density.

**Why v8 (glibc + BM inner loop) was a false result:**
The prototype used a 1 hit/5700B payload and its baseline lacked the outer `strstr`
pre-filter already in production. In production with `strstr` present, BM adds
nothing (695 ms vs 682 ms on main). See §8.6 for full analysis.

**Why Onigmo outperforms glibc (not BM, but allocation):**
glibc's mandatory O(N) per-call state-log allocation — not the missing BM — is the
dominant factor. With 88 patterns × 1 MB, glibc allocates ~88 MB of state-log per
`redact` call. Onigmo uses a fixed-size stack (O(1)). BM helps Onigmo on sparse
inputs but not dense — yet Onigmo is still 2.3× faster on env, confirming allocation
is the bottleneck.

**Paper contribution (revised, 2026-06-02):**
Four findings, each surprising:
1. **AC+BM pipeline catastrophically degrades on high-hit-density inputs** — collapses
   to 0.26× (v7 JIT) on `.env`-style payloads, 18× worse than plain PCRE2 JIT.
2. **AC+BM pipeline is net negative for JIT engines** — pipeline coordination costs
   more than the calls it prevents when the confirmation engine is fast.
3. **glibc's bottleneck is O(N) per-call state-log allocation, not missing BM.**
   BM is a partial mitigation for sparse inputs only; the real fix is engine replacement.
4. **Thompson NFA single-pass (v4.2) demonstrates O(N²) collapse elimination** — 2.3–6.1×
   over pure-Ruby, beating PCRE2 JIT on dense payloads (6.1× vs 3.9×). However the merged
   NFA architecture produces incorrect results (4/13, 31%) because overlapping character
   alphabets prevent per-pattern semantic isolation in the shared DFA. The performance
   result is valid; the architecture requires per-pattern DFA isolation for correctness.

---

## 13. Prototype TODO List

| # | Prototype | What it answers | Key dependency | Status |
|---|---|---|---|---|
| **v7** | AC + BM + PCRE2 JIT | Does PCRE2 JIT close the gap? | `libpcre2-dev` | ✅ DONE — pipeline adds overhead vs plain JIT |
| **plain PCRE2 JIT** | Sequential PCRE2 JIT, no AC, no BM | Is plain JIT faster than the pipeline? | `libpcre2-dev` | ✅ DONE — 3.8–5.0× over pure-Ruby, best overall |
| **plain Onigmo** | Sequential Onigmo, no AC, no BM | Does AC+BM help Onigmo? | `libonig-dev` | ✅ DONE — ~1.0×, ≈ pure-Ruby |
| **v8 (BM inner)** | glibc + BM cursor advance inside regexec loop | Can we beat pure-Ruby without engine swap? | None | ✅ DONE — result was inflated by unrealistic payload; zero improvement in production (see §8.6) |
| **realistic benchmark** | Re-run all engines on sparse/medium/dense/env payloads | Are previous results representative? | None | ✅ DONE — `bench_realistic.rb`; v7 and v4.1 collapse on env; plain PCRE2 JIT is the best overall |
| **v4.1 (per-pos + prefix)** | Does memmem pre-filter fix v4's env collapse? | None | ✅ DONE — no: 0.19× on env, same collapse as v4 |
| **v4.2 (single-pass)** | Does single-pass leftmost-longest fix the collapse? | None | ✅ DONE — yes: 2.3–6.1×; **but** correctness 4/13 (31%) — merged NFA not viable |
| **v4.2 correctness analysis** | Why does merged NFA produce false/missed matches? | None | ✅ DONE — overlapping character alphabets; per-pattern DFAs required |
| **v11 bytecode VM** | Correct bytecode VM baseline (zero deps) | Can a hand-rolled VM be correct? | None | ✅ DONE — correct, ~6× slower than pure-Ruby |
| **v12.1 literal filter** | memmem skip for infix literals | Does literal skip help? | None | ✅ DONE — 1.1× over v11; ~40 literal-less patterns dominate |
| **v14 first-byte filter** | Per-pattern start-set bitmap | Can we skip the digit-pattern positions? | None | ✅ DONE — 2.6× over v11; cuts pure-noise floor from 920ms to 423ms |
| **v15.1 VM constant-factor** | Iterative addthread + O(1) accept | Can we tighten the inner loop? | None | ✅ DONE — 1.1× over v14; 2.2× over glibc today |
| **v15.2 union bitmap** | OR of all 88 first-sets, skip before per-pattern work | Does a shared skip reduce per-pattern overhead? | None | ✅ DONE — no improvement (~4% slower); per-pattern filters already do this |
| **v17 precomputed init list** | Cache epsilon-closure of pc=0, memcpy at seed time | Is seed addthread the bottleneck? | None | ✅ DONE — no improvement (~1%); inner step loop dominates, not seed overhead |
| **v18 per-pattern lazy DFA** | Replace inner NFA-set step with O(1) table lookup | Can a per-pattern lazy DFA close the gap to Onigmo? | None | ✅ DONE — **yes: ~2× over v15.1, ties/beats Onigmo, ~4–5× over glibc; correct (==v15.1)** |
| **v18.1 anchor lowering** | Make boundary-wrapped digit patterns DFA-able | Can the 24 fallback patterns join the DFA path? | None | Not yet started (see v18 follow-up) |
| **selective NFA merge** | Can we merge a subset of non-overlapping patterns? | None | Not yet started (see §11.1 addendum) |
| **streaming context** | Cross-chunk match correctness + overhead | Is streaming feasible for either path? | None | Not yet started |

**Research conclusion (updated 2026-06-03):** Two viable production paths:
- **Plain PCRE2 JIT sequential** — 3.6–5.5× over pure-Ruby, requires `libpcre2-dev`, correct
- **v18 per-pattern lazy DFA** — ties/beats pure-Ruby and Onigmo (0.82–1.10×), ~4–5× over today's glibc C extension, **zero dependencies, correct (byte-for-byte identical to v15.1)**

**How the gap was closed:** the inner VM step loop was the bottleneck (confirmed by
v17's null result). v18's per-pattern lazy DFA converts that O(active-threads)/byte
loop into one table lookup, reaching Onigmo's level without a dependency. The earlier
table attempts (v4 merged, v9/v10 wrong reset logic) failed for reasons that don't
apply to a per-pattern DFA wrapping v15.1's proven `scan_one`.

---

## 14. Publication Plan

### 14.1 Paper shape

The research has material for a **systems/experience report paper** (12–15 pages):

- **Problem**: C extension 5× slower than pure-Ruby despite being C — root cause
  diagnosed as glibc `regexec` O(N) per-call state-log allocation.
- **Contribution 1**: two-stage AC + fast-engine pipeline for mixed-prefix DLP pattern
  sets; characterisation of when pipeline pre-filtering helps vs hurts.
- **Contribution 2**: Thompson NFA single-pass leftmost-longest (v4.2) as a robust
  zero-dependency alternative — 2.3–6.1× across all payload types including dense/env.
- **Contribution 3**: the AC+BM+JIT pipeline catastrophically degrades on dense inputs
  (0.26× on env); plain JIT with no pipeline is the robust winner.
- **Evidence**: eight prototypes, four-payload realistic benchmark suite, root-cause profiling.
- **Generalisation**: any system scanning 50–100 heterogeneous regex patterns against
  text (log scrubbing, DLP, credential scanning) faces the same architectural trade-offs.

### 14.2 Venue recommendations

| Venue | Type | Acceptance rate | Fit | Notes |
|---|---|---|---|---|
| **Software: Practice and Experience** (Wiley) | Journal | ~30–40% | ★★★★★ | Explicit scope: "practical experience with new/established software". No travel. 6–12 months to decision. Best first target. |
| **USENIX ATC** | Conference | ~18% | ★★★★ | Takes experience reports with clear engineering lessons. Competitive but achievable if generalisation is strong. |
| **EuroSys** | Conference | ~15–18% | ★★★ | Good fit if framed as "C extension performance antipatterns in managed language runtimes." |
| **ACM OOPSLA** | Conference | ~20–25% | ★★★ | Viable if a principled correctness/false-negative analysis is added. |
| **USENIX HotOS** (workshop) | Workshop | ~30% | ★★★ | 5-page position paper. Good for getting the "BM filter is the decisive factor" insight out quickly. Low bar, fast feedback. |
| **arXiv** (cs.PL + cs.DS) | Preprint | N/A | ★★★★★ | Post first — establishes priority immediately. Standard practice before any venue submission. |

### 14.3 Key related work to cite

- **Hyperscan** (Wang et al., USENIX NSDI 2019) — production multi-pattern SIMD matcher. Main "related work" to position against. Disqualified for our use case: x86-only.
- **BLARE** (Patel et al., PACMMOD/SIGMOD 2023) — regex decomposition for DB query evaluation. Closest structural cousin: same "extract literal + confirm with engine" decomposition. Our always-candidate class = their patterns without extractable literals.
- **HybridSA** (OOPSLA 2024) — GPU-accelerated Shift-And for multi-pattern matching. Confirms OOPSLA takes practical matching performance papers.
- **RE#** (POPL 2025) — derivative-based regex with linear-time guarantees. Theory-heavy but same domain.
- **Zherczeg PCRE JIT paper** — original PCRE JIT design. Relevant for §11.2 (PCRE2 JIT comparison).
- **Aho & Corasick (1975)**, **Boyer & Moore (1977)**, **Cox (2007)** — foundational algorithms.

### 14.4 What is still needed before submission

1. **Benchmark rigor** — document hardware (CPU model, cache sizes), OS, Ruby/glibc/libonig versions.
   Add stddev across runs (currently single-run numbers). Add a microbenchmark isolating AC
   filter overhead from confirmation overhead.
2. **Profiling evidence** — perf/callgrind showing where cycles go in v2 (glibc) vs v3 (Onigmo).
   This is the supporting evidence for "BM literal pre-filter is the decisive factor."
3. **Reproducibility artifact** — package prototypes + benchmark scripts in a self-contained
   Makefile or Docker image. Most systems venues now require or strongly encourage this.
4. **Paper writing** — estimated 4–8 weeks at 10–15 h/week given the research log as source.

### 14.5 Recommended path

1. Post preprint to arXiv (cs.PL + cs.DS) once benchmarks are rigorous.
2. Submit to **Software: Practice and Experience** as primary venue.
3. If SPE reviewers push back on novelty, revise and retarget **USENIX ATC**.
