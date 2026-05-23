# Matcher API Survey — RE2::Set & Rust RegexSet

**Prep 4 of the combined-matcher project** (see
[`combined_matcher_plan.md`](combined_matcher_plan.md)). Pure research —
read the two most-cited production multi-pattern regex APIs and figure
out what to copy, adapt, or reject when designing
[`standalone_matcher_design.md`](standalone_matcher_design.md)'s C API.

**Date:** 2026-05-23.

## RE2::Set (Google, C++)

**Source:** [re2/set.h](https://raw.githubusercontent.com/google/re2/main/re2/set.h).
Two-phase API — add patterns, compile, match many times.

```cpp
class RE2::Set {
public:
  // Add and Compile are not callable concurrently with Match.
  Set(const RE2::Options& options, RE2::Anchor anchor);

  // Returns the pattern's 0-based index, or -1 on parse error.
  // Errors do not increment the index.
  int Add(absl::string_view pattern, std::string* error);

  // Must be called before Match. Returns false on memory exhaustion.
  // Add() must NOT be called again after Compile().
  bool Compile();

  // Returns true if at least one pattern matched.
  // *v receives the indices of matching patterns (unsorted!).
  bool Match(absl::string_view text, std::vector<int>* v) const;

  // Same as above but populates error_info when DFA execution fails.
  bool Match(absl::string_view text, std::vector<int>* v,
             ErrorInfo* error_info) const;

  int Size() const;
};
```

### What RE2::Set reports

**Which patterns matched** — not where, not how many times, not which is
longest. The docstring is explicit: callers who need positions must
"compile each pattern in the set independently and scan the same haystack
a second time with those independently compiled patterns."

### Known issues (from prior session research)

- **Memory blowup:** RE2::Set's DFA state cache can hit 2 GB at only
  ~30 patterns
  ([Russ Cox notes](https://swtch.com/~rsc/regexp/regexp3.html)). For a
  redaction gem with 88 short, prefix-heavy patterns this likely stays
  manageable, but worth measuring during Phase 2.
- **Two-phase rebuild:** `Add()` after `Compile()` is forbidden, so adding a
  custom pattern after init means rebuilding the whole set. Acceptable
  if registration is rare (it is — typically at boot).

## Rust RegexSet (`regex` crate)

**Source:** [`regex::RegexSet`](https://docs.rs/regex/latest/regex/struct.RegexSet.html).
Single-phase — compile from an iterator, then match.

```rust
pub fn new<I, S>(exprs: I) -> Result<RegexSet, Error>
where S: AsRef<str>, I: IntoIterator<Item = S>

pub fn is_match(&self, haystack: &str) -> bool
pub fn matches(&self, haystack: &str) -> SetMatches      // -> { indices: Vec<usize> }

pub fn is_match_at(&self, haystack: &str, start: usize) -> bool
pub fn matches_at(&self, haystack: &str, start: usize) -> SetMatches

pub fn len(&self) -> usize
pub fn is_empty(&self) -> bool
pub fn patterns(&self) -> &[String]
```

### What Rust RegexSet reports

**Which patterns matched** — same as RE2::Set. Explicitly documented as
unable to extract `Match` or `Captures` objects; for positions, "compile
each pattern in the set independently and scan the exact same haystack
a second time." Same trade-off, same workaround.

### Other notes

- `O(m × n)` worst-case in `m` patterns × `n` haystack length. Confirms
  the theoretical claim.
- Patterns are unanchored by default. Anchors (`^`, `\A`, `$`, `\z`)
  supported when explicit.
- No `Add` after construction — you build a new `RegexSet` if patterns
  change. Different from RE2::Set's two-phase model.
- Returns an iterable `SetMatches` rather than a callback / generator.

## What both APIs share

1. **They report only "which patterns matched", not where.** This is the
   single biggest API limitation, and it's *the same* in both — strong
   signal that there's a real reason (extracting position info from a
   merged automaton is hard; both libraries punt to "rerun the matching
   pattern individually to get position").
2. **They don't resolve overlap for the caller.** They report the SET of
   matching pattern IDs; what to do when multiple patterns match the same
   region is the caller's problem.
3. **Compile is up-front and immutable.** Add-after-compile is either
   forbidden (RE2) or impossible (Rust). Aligns with our use case where
   88 built-ins compile at gem load and custom patterns recompile the
   set on `add_pattern`.

## What we'll adopt, adapt, or reject

### Adopt

- **Two-phase compile-then-match model.** Matches our access pattern
  (compile once at `Init_data_redactor`; reuse for the process lifetime).
- **Immutable matcher after compile.** Custom-pattern changes rebuild
  the whole matcher — small perf hit on `add_pattern`, zero perf hit on
  the hot path. Same trade-off both libraries made.
- **Bytes/UTF-8 boundary on the input.** Match offsets in bytes, not
  codepoints. Both APIs do this; aligns with what `data_redactor`'s C
  layer already does.

### Adapt

- **Report positions, not just "which matched".** Both surveyed APIs
  punt on this and tell callers to rerun individual patterns. **We
  CAN'T do that** — `data_redactor.redact` needs to know *where* each
  match is to write `[REDACTED]` at the right place, and `data_redactor.scan`
  promises `{ start:, length: }` offsets to users. So our API must
  surface `(pattern_id, start, length)` per match. This is the most
  important deviation from RE2/Rust precedent.
  - How both libraries actually do this internally: the underlying DFA
    knows match positions; they just don't expose them in the high-level
    API to keep the implementation room open. We'd expose them.
  - Likely cost: a small per-match book-keeping overhead during the
    DFA walk to record start offsets. Acceptable.
- **Single API, not two.** RE2::Set has `Match(text, *v)` and
  `Match(text, *v, *error_info)`; Rust has `is_match` / `matches` /
  `is_match_at` / `matches_at`. Our consumer (the gem's C layer) wants
  exactly one entry point that returns `(pattern_id, start, length)`
  events. Callback-based:
  ```c
  size_t mm_scan(const mm_matcher *m, const char *input, size_t len,
                 void (*cb)(const mm_match *, void *userdata),
                 void *userdata);
  ```
  Matches our existing C-API style and avoids forcing the caller to
  allocate a result vector. Already in `standalone_matcher_design.md`'s
  API sketch — confirmed by this survey.

### Reject

- **"Which patterns matched" without positions.** Insufficient for our
  use case as noted above.
- **Mutable Add() after Compile() (RE2's model).** Adds complexity for
  a use case we don't have — patterns change at gem-init only.
- **Iterator-returning `matches()` (Rust's model).** Less ergonomic
  than a callback in C. The callback also lets the caller terminate
  early if they only care about one match.

## Updates to `standalone_matcher_design.md`

After this survey, the existing API sketch in the design doc holds up:

```c
size_t mm_scan(const mm_matcher *m,
               const char *input, size_t input_len,
               mm_match_cb cb, void *userdata);
```

— callback-based, reports `(pattern_id, start, length)` per match. The
survey confirms this is the right shape for our use case and that the
"don't expose positions" simplification both reference APIs took is **not
applicable to us**.

No changes needed to the design doc from this survey — the API sketch
already reflects the correct trade-offs. The survey is recorded here so
the design rationale is traceable: we deliberately chose to expose
positions because RE2/Rust's reasons for hiding them don't apply.

## What this survey did NOT cover

- **Hyperscan's API** — already covered in
  [`standalone_matcher_design.md`](standalone_matcher_design.md) as
  option F (x86-only, disqualified by ARM portability).
- **PCRE2's `pcre2_jit_match_with_match_data_create_from_pattern`** —
  not a multi-pattern API.
- **Aho-Corasick libraries** (`libahocorasick`, Rust `aho-corasick`) —
  literals only; our patterns are full regex, so the API style isn't
  comparable.

## Conclusion

Both surveyed APIs converge on the same model:
**compile a set of patterns once, match many times, return the set of
matching pattern IDs without position info.** Our API copies the
compile-once shape but diverges on position reporting — we *need*
positions to wire the matcher into `redact` and `scan`, and the underlying
DFA already knows them, so exposing them costs essentially nothing.

No changes to the design doc required. Survey complete.
