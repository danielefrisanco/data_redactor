# Standalone multi-pattern matcher — design notes

**Status:** design, not yet implemented. The `data_redactor` Ruby gem's C engine
currently uses glibc POSIX `regex.h`, which is O(N²) for the gem's access
pattern (many patterns × one input, called in a loop). This document specs the
standalone C library that would replace it.

**Date:** 2026-05-23. Author: working through it with Claude during a
performance investigation.

---

## Why a separate library, not embedded code

The combined-matcher core is **gem-agnostic** — it compiles N regex patterns
into one merged automaton, walks input once, emits `(pattern-id, start, end)`
match events. Nothing about that is Ruby-specific.

Reasons to spin it off rather than nest it in `data_redactor/ext/`:

1. **Reuse.** The planned Erlang/Elixir port of `data_redactor` (see TODO
   "Possible Erlang/Elixir port") would need the same matcher. Sharing a
   single C core via a NIF avoids two implementations drifting.
2. **Other consumers.** Any log scrubber, DLP tool, or PII-detection pipeline
   in any language could link it. The category is well-defined.
3. **Maintainability in isolation.** Its own tests, its own fuzzing harness
   (regex engines need *aggressive* fuzzing — a bug is a wrong match, which
   for redaction is a leaked secret), its own release cadence.
4. **Size.** A correct implementation is roughly 1500–3000 lines of C. Mixed
   into the gem it dwarfs the gem itself.
5. **License clarity.** As a standalone library it can pick its own license
   (MIT to match the gem) and be vendored or dynamically linked.

## The problem this library solves

Given:
- A fixed set of `N` regular expressions (typically dozens to low hundreds).
- A stream or buffer of bytes.

Find: every match of any of the N patterns, **with the pattern id of which
pattern matched**, in **O(input_length)** total time and **O(automaton_size)**
space.

The existing landscape:
- **glibc/PCRE/Onigmo** — single-pattern engines. Calling them N times per
  input is O(N × input × per-call-setup) — what we have today.
- **RE2** (Google, BSD, C++) — single-pattern, linear-time. Still N calls.
- **Hyperscan** (Intel, BSD, C) — exactly the right shape, but **x86-only**
  (SSE/AVX intrinsics) → not portable to ARM. Disqualifying for a Ruby gem
  shipping on Apple Silicon / Graviton.
- **Aho-Corasick** — multi-pattern but **literals only**, no regex.

So: a portable, zero-dep, multi-pattern, regex-subset C library is a gap.

## Scope — what regex features must be supported

Drawn from the 88 patterns in `data_redactor`'s `ext/data_redactor/patterns.c`.
The library is a **regex subset**, not a full PCRE replacement.

Required:
- Literal bytes
- Character classes: `[abc]`, `[a-z]`, `[A-Z0-9]`, `[^abc]` (negated)
- POSIX bracket classes: `[[:alpha:]]`, `[[:digit:]]`, `[[:alnum:]]`, `[[:space:]]`
- Alternation: `a|b|c`
- Concatenation: `ab`
- Grouping: `(ab|cd)`
- Quantifiers: `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}` (bounded — important for
  the linear-time guarantee; see "Time complexity" below)
- Anchors: `^`, `$` (line / string)
- Escapes: `\.`, `\\`, `\(`, `\[`, etc.

**Explicitly NOT supported** (and rejected at compile time with a clear error):
- Backreferences (`\1`) — not regular, exponential worst case.
- Lookaround (`(?=...)`, `(?!...)`) — not regular.
- Non-greedy quantifiers (`*?`, `+?`) — possible to support but rarely needed
  for tokenized data; defer until asked.
- Unicode property escapes (`\p{L}`) — defer; UTF-8 byte-level matching covers
  the cases we care about (the gem is byte-oriented today).
- Named groups, conditionals, recursion.

This is roughly the POSIX ERE subset *minus* a few features, which is what
`data_redactor`'s patterns already use.

## API sketch (C)

Opaque handle, two-phase usage (compile once, match many):

```c
typedef struct mm_matcher mm_matcher;
typedef struct mm_compile_error {
    int    pattern_index;   /* which input pattern failed, -1 for general */
    size_t offset;          /* byte offset into that pattern's source     */
    char   message[128];    /* human-readable error                        */
} mm_compile_error;

/*
 * Compile a set of patterns into one matcher. Patterns are POSIX-ERE-subset
 * source strings (see "Scope" in design doc). pattern_ids[i] is the integer
 * tag the matcher will report when patterns[i] matches; the caller picks
 * the namespace (commonly 0..n-1 indexed).
 *
 * Returns NULL on compile error; *err is filled in.
 */
mm_matcher *mm_compile(const char *const *patterns,
                       const int   *pattern_ids,
                       size_t       n_patterns,
                       mm_compile_error *err);

void mm_free(mm_matcher *m);

/*
 * Match event delivered to the caller's callback. Offsets are byte positions
 * in the input passed to mm_scan; length is byte length of the match.
 */
typedef struct mm_match {
    int    pattern_id;
    size_t start;
    size_t length;
} mm_match;

/*
 * Walk `input` once, calling `cb` for each match. `userdata` is passed through.
 * Returns the number of matches emitted, or (size_t)-1 on error.
 *
 * Match ordering: emitted in input-position order (sorted by start, ties broken
 * by longer match first — see "Overlap resolution" below).
 *
 * Streaming variant (separate fn): mm_scan_chunk lets callers feed chunks; the
 * matcher holds state across calls to handle matches straddling boundaries.
 */
typedef void (*mm_match_cb)(const mm_match *m, void *userdata);

size_t mm_scan(const mm_matcher *m,
               const char *input, size_t input_len,
               mm_match_cb cb, void *userdata);
```

The matcher is **thread-safe for reading** (`mm_scan` on the same compiled
matcher from multiple threads); compile and free are not concurrent with scans.

## Algorithm — how it achieves linear time

### Compile phase

1. **Parse** each input pattern into an AST (recursive descent over the regex
   syntax above).
2. **Thompson's construction** — convert each AST into an NFA fragment.
3. **Merge** all N NFAs into one combined NFA: a single start state with
   epsilon transitions into each pattern's NFA fragment. Each accept state is
   tagged with its `pattern_id`.
4. **Subset construction** (NFA → DFA): build the deterministic equivalent.
   States are sets of NFA states; transitions are on input bytes. Accept states
   carry the set of pattern_ids that accept there (more than one if multiple
   patterns can match at the same position).
5. **DFA minimization** (Hopcroft's algorithm) — optional but cheap; cuts
   state-table size significantly for redundant patterns.

DFA size is bounded by 2^(total NFA states) in the worst case, but for the
character-class-heavy patterns in `data_redactor` (each pattern is small;
common prefixes share states) realistic size is in the low thousands of
states, fitting comfortably in L2 cache.

### Match phase

Single loop over input bytes:

```
state = dfa.start
for i in 0..input_len:
    state = dfa.transition[state][input[i]]
    if state is accept:
        for pid in state.pattern_ids:
            emit_potential_match(pid, start_of_current_run, i+1)
```

Each byte does one table lookup → **O(input_length) total, period.** No
backtracking, no per-call setup, no allocation in the hot loop.

The interesting question is *which* match to emit when multiple are possible —
see overlap resolution below.

### Time complexity guarantees

Linear in input length, **provided** the regex doesn't contain unbounded
ambiguous repetition that requires NFA simulation (which is why the scope
above bans backreferences and lookaround — they break the regular property).

Memory is O(DFA_states × alphabet_size) for the transition table. For 256-byte
alphabet (raw bytes, UTF-8-safe by byte) and a few thousand states, that's a
few MB — acceptable for a one-time cost held in the compiled matcher.

## Overlap resolution — DECIDED 2026-05-23

**Policy: longest match wins, tied lengths broken by pattern-id (lower index
wins).** Locked in via Prep 2 (see
[`pattern_subset_audit.md`](pattern_subset_audit.md) sibling and
[`combined_matcher_plan.md`](combined_matcher_plan.md)). Spec coverage is in
`spec/data_redactor_spec.rb` under the "overlap resolution" describe blocks
— both today's pattern-id-priority behaviour AND the post-1.0 longest-match
behaviour are written as specs, with the latter marked `pending` until the
matcher ships.

### Why longest-match-wins, not pattern-id priority

The previous draft of this doc recommended pattern-id priority (today's
implicit behaviour). Prep 2's empirical investigation revealed a class of
cases where pattern-id priority **leaks secrets**:

> Input: `AKIAIOSFODNN7EXAMPLEAAAAAAAAAAAAAAAAAAAA` (40 alphanum bytes).
>
> - Pattern-id priority (today): `aws_access_key_id` (idx 14) wins, redacts
>   the leading 20 chars, **leaves the trailing 20 unredacted**.
> - Longest-match: `aws_secret_access_key` (idx 15, 40 chars) wins, the
>   whole span is redacted.

For a redaction gem the correct failure mode when uncertain is "redact
more, not less." The pattern-id semantic is also an *accidental* outcome of
sequential pattern execution — no one designed it; it fell out of the
implementation. Adopting longest-match aligns with Onigmo, PCRE, RE2, and
Hyperscan's standard semantics.

### Worked example

Input: `AKIAIOSFODNN7EXAMPLEAAAAAAAAAAAAAAAAAAAA` (40 chars).

| Match candidate | Start | Length | Pattern id |
|---|---|---|---|
| `AKIAIOSFODNN7EXAMPLE` | 0 | 20 | 14 (`aws_access_key_id`) |
| `AKIAIOSFODNN7EXAMPLEAAAAAAAAAAAAAAAAAAAA` | 0 | 40 | 15 (`aws_secret_access_key`) |

Longest match (40) wins. `redact` emits one `[REDACTED]` covering the
whole input.

Input: `id 85121612345 end` (11-digit span at offset 3).

| Match candidate | Start | Length | Pattern id |
|---|---|---|---|
| `85121612345` | 3 | 11 | 81 (`polish_pesel`) |
| `85121612345` | 3 | 11 | 82 (`belgian_national_number`) |
| `85121612345` | 3 | 11 | 83 (`norwegian_fodselsnummer`) |
| `85121612345` | 3 | 11 | 87 (`polish_pesel_2`) |

All four candidates are the same length. Tiebreak by pattern-id: index 81
wins, so `polish_pesel` is reported. Matches today's behaviour.

### Compatibility implications

This **is a behaviour change** from today. Concrete consequences:

- **Major version bump.** The combined-matcher PR ships as `1.0.0` (already
  planned per `combined_matcher_plan.md`). The overlap-policy change is
  called out prominently in the CHANGELOG.
- **`scan` API unchanged.** Still returns `matches: [...]`. The set of
  matches reported may differ from today (one longer match instead of
  multiple shorter overlapping ones).
- **Custom patterns inherit the policy.** No new flag — the policy is the
  matcher's, applies uniformly.

### Reporting all overlaps (optional)

For `scan`-style introspection use cases, the underlying matcher API can
optionally report **all** overlapping matches in input-position order, with
the consumer (in our case the `redact`/`scan` Ruby layer) choosing what
to do with them. Today's `scan` would just keep emitting the
longest-wins-with-id-tiebreak selection; a future `scan_all` could expose
the full set. Out of scope for the 1.0 matcher; design space left open.

## Why a combined automaton is structurally better — the prefix-sharing win

Beyond the asymptotic "O(N) one pass instead of O(N×P) for P patterns,"
combining patterns into one automaton **shares work across patterns with
common prefixes** (or any common subgraph after DFA minimisation).

Example with three Github token patterns:

```
github_pat_fine_grained:  github_pat_[0-9a-zA-Z_]{82}
github_classic_pat:       ghp_[0-9a-zA-Z]{36}
github_oauth_token:       gho_[0-9a-zA-Z]{36}
```

Three separate `regexec` calls each read `g` then `h` independently — 3
byte comparisons of `g`, 3 of `h`, total 6. The combined NFA goes:

```
start ──g──> Sx ──h──> Sy ──┬── i ──> github_pat_fine_grained branch
                            ├── p ──> github_classic_pat branch
                            └── o ──> github_oauth_token branch
```

The `g` and `h` bytes are inspected **once** for all three patterns at this
position. With 88 patterns the savings compound:

- Every IBAN starts with two uppercase letters → the `[A-Z][A-Z]`
  recognition is shared across 18 patterns.
- Stripe / SendGrid / GitLab / Github tokens etc. share initial-character
  classes that collapse to a single transition.
- After DFA minimisation, common *suffixes* (e.g. trailing alphanum runs of
  fixed length) merge too.

This isn't a separate optimisation we'd add — it falls out of
NFA-merging + subset construction + Hopcroft minimisation, all standard
Thompson-construction steps. The "we don't check the same byte twice" win
is the structural payoff for building the combined automaton in the first
place, not an extra trick.

## Streaming / chunk-boundary handling

The streaming API (`mm_scan_chunk`) carries DFA state across calls. A match
that starts in chunk A and ends in chunk B is still detected correctly because
the DFA state at the end of A *is* the partial-match state going into B.

**This solves the same problem as TODO item #8 (Streaming API) and as the
chunking approach (option G) in TODO's Performance section** — they all need
the same "partial-match state carries across boundaries" property, which is
exactly what a DFA gives you for free.

What it cannot do: detect a match starting inside a region the caller already
flushed. Callers must hold the bytes of any in-progress match until it
completes — the API should report `partial_match_active` or similar so the
caller knows when it's safe to discard buffered input. Simple ring-buffer
pattern.

## Boundary-wrapped patterns

`data_redactor` wraps generic patterns with `(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)`
to avoid matching inside other tokens. The new library should:

- Support this wrapping natively (or via a per-pattern flag) so callers don't
  have to materialize the wrapper in the source string. Cleaner API and the
  DFA can optimize the wrapper.
- Report the *core* span (the inner group), not the boundary chars — same
  semantics as `replace_all_matches` today.

## Testing strategy

A regex engine is a security-critical component. Testing must be aggressive:

1. **Spec-equivalence harness.** Run `data_redactor`'s 231-spec suite with the
   gem swapped to use the new matcher; output must be byte-identical to the
   `regex.h` version.
2. **Property testing.** Generate random patterns and random inputs; compare
   our match set against PCRE / glibc / RE2 as oracles. Mismatches = bugs.
3. **Fuzzing.** AFL / libFuzzer on both the compile and match entry points.
   Targets: parser crashes, compile-time UB, scan-time UB, state explosion
   on adversarial patterns.
4. **Performance regression tests.** A small benchmark suite that fails CI if
   matching speed regresses past a threshold (the whole point of the library
   is being fast).
5. **Sanitizers.** ASan + UBSan on every CI build.

## Repository layout (when spun off)

```
multi-matcher/        (or similar — naming TBD)
├── include/
│   └── multi_matcher.h    public API
├── src/
│   ├── parser.c           regex source → AST
│   ├── nfa.c              AST → NFA (Thompson's)
│   ├── dfa.c              NFA → DFA (subset construction)
│   ├── minimize.c         DFA minimization (Hopcroft)
│   ├── scan.c             match loop
│   └── streaming.c        chunk-boundary state
├── tests/
│   ├── unit/              per-stage unit tests
│   ├── conformance/       PCRE/RE2-oracle comparison
│   └── fuzz/              AFL/libFuzzer harnesses
├── bench/
│   ├── compile.c          compile-time benchmarks
│   └── scan.c             scan-time benchmarks
├── examples/
│   └── data_redactor.c    show integration
├── Makefile
├── README.md
└── LICENSE                MIT
```

Pure C99, no external dependencies, builds with any modern `gcc`/`clang`.
Provide both static and shared library targets.

## Integration into `data_redactor`

Once the library exists:

1. Add as a git submodule under `ext/multi_matcher/` and update `extconf.rb`
   to compile both. (Or vendor as a tarball — submodules are friction for gem
   builders.)
2. Replace `redact.c`'s per-pattern loop with one `mm_scan` call per `redact`
   invocation. Build the compiled matcher once at `Init_data_redactor` time
   from the 88 pattern sources (already exposed via `BUILTIN_PATTERN_SOURCES`,
   added in this same investigation 2026-05-23).
3. Rewrite the placeholder-substitution logic to walk the input + match events
   in tandem and stream into the output buffer. Much simpler than today's
   per-pattern working buffer.
4. `scan.c` becomes trivial: `mm_scan` already reports `(pattern_id, start,
   length)` events — exactly what `scan` needs to return.
5. Custom patterns: re-compile the matcher when `add_pattern`/`remove_pattern`
   is called. This is a small perf hit on registration but eliminates the
   custom-pattern loop entirely from the hot path.

Bumps a major version (`1.0.0`) because the engine is replaced, but the public
Ruby API stays identical.

## Open questions to resolve before coding starts

1. ~~Overlap resolution policy~~ — **DECIDED 2026-05-23** (Prep 2):
   longest-match wins, tied lengths broken by pattern-id. See the
   "Overlap resolution" section above.
2. **DFA state explosion limit** — what's the largest combined automaton we
   tolerate before refusing to compile? (Practical limit, not theoretical.)
3. **Streaming partial-match buffering** — should the library buffer
   internally or push the responsibility to the caller? Memory vs ergonomics
   trade-off.
4. **UTF-8 awareness** — keep byte-oriented (current `data_redactor` model)
   or upgrade to codepoint-aware character classes? Byte-oriented is simpler
   and matches today's behaviour exactly.
5. **License of borrowed algorithms** — Thompson, Hopcroft, subset
   construction are textbook; no license issues. But if we crib parser code
   from somewhere, check the license.
6. **Naming.** `multi_matcher`, `multimatch`, `regset`, something else?
