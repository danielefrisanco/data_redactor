# Multi-Matcher Prototype Plan (Kill-Criterion Experiment)

> **Purpose.** Validate the combined-matcher hypothesis cheaply before
> committing to Phase 1+2 of [`combined_matcher_plan.md`](combined_matcher_plan.md).
> Per that plan's risk-mitigation section:
>
> > "Concrete kill criterion before Phase 2 starts: a quick prototype
> > with 10 patterns must beat the equivalent 10-pattern Ruby `gsub` by
> > ≥3× on a 1 MB log. If it doesn't, the architecture is wrong and
> > we either pivot to option H (Onigmo) or stop."

**Date:** 2026-05-23. **Branch:** `feat/matcher-prototype-v1` (after this plan
PR merges).

## Hypothesis

If we filter input positions through a *single shared structure* (an
Aho-Corasick trie of pattern prefixes) and only invoke `regexec` at
candidate positions, we beat 88-separate-`regexec` calls by ≥3× on a
1MB log of representative patterns. **This is the core hypothesis behind
Phases 1+2.** If it fails on 10 patterns, it'll fail on 88.

## Approach — Aho-Corasick prefix trie + `regexec` confirmation

Two-stage matching:

1. **Filter stage.** Build a trie of literal prefixes (e.g. `sk_live_`,
   `https://hooks.slack.com/`, `AKIA`, `eyJ`) — one trie shared across
   all 10 patterns. Walk the input once; at each position, the trie
   reports which patterns *might* start here based on prefix.

2. **Confirm stage.** For each filter hit, run the full `regexec` of
   the candidate pattern(s) anchored at that position. If it matches,
   we have a real match.

This mirrors what Onigmo does internally with its `bm_search` →
NFA-match pipeline, except we share the filter across all patterns
(Onigmo runs per-pattern).

**Why Aho-Corasick rather than simpler first-byte / Boyer-Moore?**

- First-byte filter is too coarse — half the alphabet appears as
  pattern start, so filter hit rate is too high.
- Boyer-Moore is per-pattern; we want one shared structure.
- Aho-Corasick is the canonical multi-pattern literal-prefix matcher;
  building one is a few hundred lines of C.

**What if Aho-Corasick alone isn't enough to hit 3×?** Increment the
approach: extend the trie deeper, or replace it with a full Thompson
NFA. Per CLAUDE.md "build for now, not for hypothetical futures" —
start with the simplest thing that tests the hypothesis.

## The 10 patterns

Chosen to exercise different feature mixes:

| # | Pattern name | Literal prefix | Why chosen |
|---|---|---|---|
| 1 | `aws_access_key_id` | `A` then alternation (`A3T`, `AKIA`, `ABIA`, ...) | Multi-prefix alternation |
| 2 | `email` | (none — `@` is an infix) | Generic, very common, no useful prefix |
| 3 | `ipv4` | (none — pure digits + dots) | Worst case for prefix filter; tests fallback |
| 4 | `credit_card` | (none — pure digit alternation) | Same as above, different shape |
| 5 | `slack_webhook_url` | `https://hooks.slack.com/services/` | Long literal prefix (~32 bytes) |
| 6 | `stripe_secret_key` | `sk_live_` | Short literal prefix (8 bytes) |
| 7 | `iban_de` | `DE` | 2-byte uppercase prefix |
| 8 | `polish_pesel` | (none — pure 11 digits) | Boundary-wrapped digits |
| 9 | `pem_private_key` | `-----BEGIN ` | Long literal shared with #10 |
| 10 | `gpg_private_key` | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | Same `-----BEGIN ` prefix as #9 — tests shared-prefix savings |

For patterns with no literal prefix (#2, #3, #4, #8): they're added to
the trie as "always-candidate at every position" — equivalent to today's
behavior. The filter helps the *other* 6 patterns; these run everywhere
regardless.

## Directory layout

```
prototypes/
  multi_matcher_v1/
    README.md                  # what this is, how to run, what we learned
    matcher.c                  # the Aho-Corasick trie + match driver
    matcher.h                  # public interface for the Ruby FFI bridge
    Makefile                   # standalone build (no extconf.rb wiring)
    bench.rb                   # Ruby driver: builds the matcher via FFI,
                               #   runs benchmark against pure-Ruby gsub
```

**Not** added to `extconf.rb`. **Not** packaged in the gem. The prototype
is a one-off experiment that lives in the repo forever as a historical
artifact recording what we tried and what we measured. Adds zero
dependencies for end users.

## Implementation slices

Each slice ends with a runnable thing — easy to abandon if a slice
reveals the approach won't work.

### Slice 1 — Aho-Corasick trie of literal prefixes (C, ~150 LOC)

- `struct ac_node` with goto/failure pointers and an "accepting" set
- `ac_build(patterns, n_patterns)` returns a built automaton
- `ac_scan(input, len, cb)` walks the input once, calls `cb(pattern_id,
  pos)` at each prefix match
- Test in isolation with `main()` in `matcher.c` (printf the matches).

### Slice 2 — `regexec` confirmation on each candidate (C, ~50 LOC)

- For each `(pattern_id, pos)` from the trie, run the pattern's full
  `regex_t` anchored at `pos`. POSIX has no anchor flag, but we can
  pass `input + pos` and check `m.rm_so == 0`.
- Collect confirmed matches into a result vector.

### Slice 3 — Ruby FFI binding (Ruby, ~30 LOC)

- `bench.rb` uses `Fiddle` (stdlib, no new gems) to call into the
  compiled `libmatcher.so`.
- Compile via the `Makefile` (`make matcher.so`).
- Verify correctness against `DataRedactor.scan` for the 10 patterns —
  the prototype must report the same matches the existing engine does.
  Spec-equivalence even at this stage.

### Slice 4 — Benchmark (Ruby, ~40 LOC)

- Run the 10 patterns through:
  - **Pure-Ruby `gsub` loop** (the same baseline `vs_pure_ruby.rb` uses,
    filtered to the 10 patterns).
  - **Today's C engine** filtered to the 10 patterns via `only:`.
  - **The prototype** via FFI.
- 1MB log payload. Report ips and ratio. **Verdict: ≥3× faster than
  pure-Ruby → green light Phase 1+2.**

## Out of scope for this prototype

Deliberately not building:

- **Thompson NFA / subset construction** — the actual matcher in
  Phase 2. The prototype validates whether the approach class works;
  Phase 2 builds the production version.
- **Custom-pattern support** — fixed 10 patterns hard-coded.
- **Boundary-wrapper logic** — the 10 patterns we picked don't include
  any boundary-wrapped ones (we deliberately chose `polish_pesel`'s
  pure-digit form to keep it simple; in production it's boundary-wrapped,
  but for the prototype we use it as-is and accept some false-positive
  noise that doesn't affect the speed measurement).
- **Multibyte awareness** — byte-oriented like the rest of the gem.
- **Overlap resolution** — the prototype reports raw matches; the
  benchmark only checks "same matches found," not order/resolution.

## Success / pivot criteria

- **≥3× faster than pure-Ruby `gsub` on the 1MB log:** kill criterion
  passed → start Phase 1.
- **2-3× faster:** marginal. Try one increment (deeper trie or
  Thompson NFA). If still marginal, default to **option H (use Onigmo)**
  as the pragmatic stopgap and document why E was deferred.
- **<2× faster, or slower:** the approach class is wrong. Either H
  (Onigmo) or accept the 3-5× slowdown documented in the README. Phase
  1+2 are cancelled; the matcher-prep work still has value (overlap
  policy specs document intent, benchmarks remain).

## Time budget

Strict cap of **2 days of focused work** for the whole prototype +
benchmark + verdict. If we're not done in 2 days, the approach is more
complicated than expected → revisit, simplify, or pivot.

## What this prototype does NOT prove

- Phase 2 production code will be 3× faster too (it'll be different code,
  different bugs, different optimisations).
- The combined matcher will work for all 88 patterns (some patterns may
  expose edge cases the 10 don't).
- The matcher will fit in memory (DFA state explosion is still a risk —
  see `standalone_matcher_design.md` "DFA state explosion limit").

These are Phase 2 concerns, not kill-criterion concerns. The prototype
answers one question: *can a shared-prefix filter give us a 3× win on
representative input?* If yes, we have evidence to commit to Phase 2.
If no, we don't.
