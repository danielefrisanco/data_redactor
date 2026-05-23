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

## Overlap resolution (the hard design question)

When multiple patterns match overlapping spans — e.g. on the input `AKIA...`,
both `aws_access_key_id` (specific) and a generic 20-alphanum pattern would
match the same bytes — *which one wins?*

`data_redactor` today resolves this by **sequential pattern execution in
specific→generic order**: after pattern `i` replaces a match with `[REDACTED]`,
pattern `i+1` sees the modified buffer and can't re-match the same span.
This is implicit in the pattern array ordering (see `patterns.c`).

The combined matcher walks once and sees all matches simultaneously. We need
an explicit policy. Options:

1. **Longest match wins.** Standard regex engine behaviour. Simple, predictable,
   but doesn't capture the "specific over generic" semantics — a 20-char generic
   pattern would beat the 20-char `AKIA...` because they're the same length and
   tie-breaking is undefined.
2. **Priority by pattern_id.** The caller orders patterns; lower id wins ties.
   Maps cleanly to today's specific→generic array order. **Recommended.**
3. **Longest match, tie-broken by priority.** Combines (1) and (2).
   Recommended if we want the "longest" intuition preserved.
4. **Emit all overlapping matches, let the caller resolve.** Most flexible,
   pushes complexity to the caller. Useful for `scan` (which wants to report
   everything); wrong for `redact` (which needs to pick one).

The library should support **policy (3) by default** with a flag to choose
between policies, and `mm_scan` should expose match events in a consistent
order (sorted by start, then by priority). Then `redact` picks the first
non-overlapping set; `scan` reports them all.

This is the *single most important design decision* and needs prototyping
against the gem's existing spec suite (which encodes the specific→generic
expectations).

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

1. **Overlap resolution policy** — decide between policies (2) and (3) above
   with prototype evidence against the spec suite.
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
