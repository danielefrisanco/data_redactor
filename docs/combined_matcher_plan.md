# Combined Matcher — Execution Plan

> **Companion to** [`standalone_matcher_design.md`](standalone_matcher_design.md).
> That doc describes **what** to build. This doc describes **how and in
> what order**, including prep work, branch structure, and review milestones.

**Date:** 2026-05-23. **Status:** approved, not yet started.

---

## Context — why this exists

The May 2026 performance investigation (see `TODO.md` "Performance" section)
shipped two optimisations to `data_redactor`'s C engine: a `strstr` literal
pre-filter (option B) and chunked input (option G). Net effect: 25-30%
faster across all sizes and linear scaling restored, but the C extension is
**still 3-5× slower than pure-Ruby `gsub`** at every size we measured.

The remaining gap is structural — glibc's POSIX `regexec` lacks the
Boyer-Moore literal pre-filter that Ruby's Onigmo engine has built in, and
allocates O(input-length) state per call. No amount of optimisation around
the engine's existing API can close that gap.

**The only options that can actually beat Ruby** are options I (streaming
position-by-position match) and E (a combined automaton walking all
patterns simultaneously). I is the *algorithmic skeleton* of E — same outer
loop, different inner step. This plan treats them as one project in two
phases.

## Prior art — this isn't novel work

Confirmed from public sources (search 2026-05-23):

- **[Thompson 1968](https://www.oilshell.org/archive/Thompson-1968.pdf)** — the original `grep` paper describes exactly this technique. The CS is 57 years old.
- **[RE2::Set](https://github.com/google/re2)** (Google, BSD) — multi-pattern API, linear-time guaranteed. Known issue: DFA state cache hits 2GB at only ~30 patterns ([Russ Cox notes](https://swtch.com/~rsc/regexp/regexp3.html)).
- **[Hyperscan](https://www.usenix.org/system/files/nsdi19-wang-xiang.pdf)** (Intel, BSD) — production multi-pattern engine, claims 10.3× over RE2. x86-only.
- **Rust [`RegexSet`](https://docs.rs/regex/latest/regex/struct.RegexSet.html)** — battle-tested, well-documented API.
- **[RE# paper](https://arxiv.org/pdf/2407.20479)** — modern derivative-based approach with intersection/complement.

We're re-implementing a well-understood category. The risk is execution, not novelty.

## Project shape — one project, two phases

**Phase 1: streaming-match skeleton.** Build the outer loop — walk input
once, at each position try patterns until one matches, emit `[REDACTED]`,
advance past the match. **Inner step initially uses 88 sequential `regexec`
calls** (one per pattern). This is provably correct but slow.

- Validates the *structure*: integration into `redact`/`scan`, overlap
  resolution, scan offset translation, custom-pattern injection, the
  235 specs still pass byte-identical to today.
- Performance is roughly the current state — possibly modestly better
  because we skip past matches and don't re-scan.
- **Not shipped on its own.** It's the substrate Phase 2 builds on.

**Phase 2: combined automaton.** Replace the inner step with a single
NFA/DFA constructed from all 88 patterns merged via Thompson's construction
(see `standalone_matcher_design.md` Part "Algorithm"). One state transition
per input byte instead of 88 `regexec` probes.

- This is where the actual speed comes from.
- **Shipped together with Phase 1** as a single major-version release, only
  once benchmarks confirm it beats Ruby decisively.

The phasing isolates *correctness* (Phase 1) from *performance* (Phase 2).
Bugs in the combined automaton are caught by the spec suite that the
Phase 1 skeleton already passes.

## Repository layout — build in-repo, extract later

Per the 2026-05-23 decision: implementation lives in `ext/data_redactor/`
throughout both phases. Library extraction to a standalone repo (the
"spinoff" idea in `standalone_matcher_design.md`) is a separate decision,
deferred until after Phase 2 ships and the design is proven.

Rationale: less upfront friction, faster iteration, can validate the design
on real specs without setting up cross-repo tooling. Extraction is harder
than it looks but not impossible; if the Elixir port ever happens, that's
the natural forcing function.

## Prep work — four small PRs before any matcher code

Each prep PR is independent, small, and lands incremental value. They can
land in any order (no inter-dependencies), but the recommended order below
maximises information for the matcher design.

### Prep 1 — Audit our 88 patterns against the regex subset

**Branch:** `feat/audit-pattern-subset`. **Estimated size:** ~1-2 hours.

Walk every entry in `ext/data_redactor/patterns.c` and verify it uses only
the regex features the combined matcher will support (per
`standalone_matcher_design.md` "Scope"). Catches surprises early — if any
pattern uses something we plan to exclude (backreferences, lookaround,
non-greedy), we either expand scope or rewrite the pattern.

**Deliverables:**
- A short markdown table in `docs/pattern_subset_audit.md` listing each
  pattern, the features it uses, and pass/fail against the planned subset.
- If any patterns fail: a rewrite or a scope decision documented in the
  table.

**Acceptance:** all 88 patterns pass; 235 specs green.

### Prep 2 — Lock down overlap-resolution policy

**Branch:** `feat/overlap-policy-specs`. **Estimated size:** ~half day.

Today the gem's overlap behaviour is *implicit* — patterns run in
specific→generic order on a working buffer that's been modified by earlier
patterns, so by the time a generic pattern runs, the specific ones have
already replaced their text. The combined matcher sees all matches
simultaneously, so we need an *explicit* policy.

The design doc lists candidate policies:
1. Longest match wins.
2. Priority by pattern_id (matches today's sequential ordering).
3. Longest match, tie-broken by priority.

**Deliverables:**
- Add explicit spec coverage for known overlap cases — at minimum: `AKIA`
  (20-char alphanum prefix) vs the generic 20-char alphanum pattern;
  `email` (contains a `.com` that the IPv4 dot-pattern almost matches);
  `credit_card` (digits that overlap national-ID digit patterns).
- The new specs document the *expected* behaviour with today's engine.
- Add a doc paragraph in `docs/standalone_matcher_design.md` declaring
  which policy reproduces that behaviour, with a worked example.

**Acceptance:** new overlap specs pass against today's engine and will
serve as the oracle for the combined matcher's overlap-resolution code.

### Prep 3 — Add an isolated matcher benchmark

**Branch:** `feat/isolated-matcher-bench`. **Estimated size:** ~1-2 hours.

`benchmark/vs_pure_ruby.rb` measures the whole `redact` pipeline. During
matcher development we want to measure *just the matcher*: same patterns,
identical inputs, no surrounding placeholder substitution or buffer
management.

**Deliverables:**
- `benchmark/matcher_isolated.rb` — runs both the current 88-regexec loop
  and (once it exists) the combined matcher on a corpus of strings;
  reports per-input time. Initially compares against pure-Ruby `gsub` so
  the file is useful immediately.
- Short README entry in `benchmark/README.md` explaining what it isolates.

**Acceptance:** script runs cleanly and produces stable numbers across
runs (variance < 10%).

### Prep 4 — Survey RE2::Set and Rust's RegexSet APIs

**Branch:** `feat/matcher-api-survey`. **Estimated size:** ~half day.

Before designing our own C API in detail, read the public APIs and
post-mortems of two production implementations. This is *research*, not
code — but it should produce a written artifact so the survey isn't
re-done from scratch later.

**Deliverables:**
- `docs/matcher_api_survey.md` — for each of RE2::Set and Rust's
  `RegexSet`: their compile API, match API, what they report (one match
  vs all matches vs which patterns matched), how they handle overlaps,
  what their known issues are.
- A short "what we'll adopt / adapt / reject" section at the end.

**Acceptance:** the survey doc exists; `standalone_matcher_design.md` is
updated where the survey changes any design decision.

## Phase 1 — streaming-match skeleton

**Branch:** `feat/combined-matcher-phase1` (off main, after prep PRs).

**Approximate scope:** medium. Most of the work is refactoring `redact.c`
and `scan.c` around a new outer loop while preserving the 235-spec
behaviour and adding the new overlap specs from Prep 2.

**Deliverables:**
- New `streaming_match.c` / `.h` with the position-by-position loop.
- `redact.c` and `scan.c` refactored to use it (or replaced — TBD during
  detailed design).
- The inner "find best match at position P" function calls all 88
  `regexec`'s sequentially for now. Encapsulated behind a clear interface
  that Phase 2 will swap out.
- All 235 existing specs + Prep 2's overlap specs pass.
- `benchmark/matcher_isolated.rb` numbers committed in the PR description
  (likely similar to today's, possibly slightly worse — that's fine).

**Not shipped to users.** Phase 1 lands on `main` only because Phase 2 will
build on it; users see no behavioural change. If Phase 1 turns out to be
the wrong abstraction, we revert it before Phase 2 lands.

## Phase 2 — combined automaton

**Branch:** `feat/combined-matcher-phase2` (off `feat/combined-matcher-phase1`
after it merges).

**Approximate scope:** large. Multi-week. Real C compiler/state-machine
work.

**Deliverables (per `standalone_matcher_design.md`):**
- Regex parser (recursive descent over the supported subset).
- Thompson's construction → NFA fragments per pattern.
- NFA merging via single start state + epsilon transitions, with
  pattern-id tagging on accept states.
- Subset construction → DFA.
- Hopcroft minimisation (optional but cheap).
- Replace Phase 1's inner step with a single DFA lookup.
- Aggressive testing: spec-equivalence harness against the existing
  engine, property tests comparing against PCRE/RE2 as oracles, AFL fuzz
  harness on both compile and match entry points.
- `benchmark/vs_pure_ruby.rb` numbers in the PR description showing the
  C extension finally beating pure-Ruby `gsub`.

**Shipped as a major version release** (`1.0.0` per semver — the engine
is replaced even though the public Ruby API is unchanged). CHANGELOG
documents the engine swap and the new performance characteristics.

## Branch sequence summary

```
main
 ├── feat/audit-pattern-subset           ──┐
 ├── feat/overlap-policy-specs           ──┤  Independent prep PRs.
 ├── feat/isolated-matcher-bench         ──┤  Any order.
 └── feat/matcher-api-survey             ──┘

(after all 4 prep PRs merge)

main
 └── feat/combined-matcher-phase1
      └── feat/combined-matcher-phase2
           └── (1.0.0 release)
```

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| **DFA state explosion** at our pattern count | Stay on NFA simulation initially; build lazy DFA only if NFA proves too slow. RE2 hits 2GB at ~30 patterns, but our 88 patterns are short and prefix-heavy — likely much smaller. Validate during Phase 2 design with a state-count probe before committing to full DFA. |
| **Overlap policy mismatch** with today's behaviour | Prep 2 produces an explicit spec suite locking in today's behaviour *before* the matcher is built; matcher must pass it. |
| **Multi-week effort stalls** | Phase 1 is shippable scaffolding on its own — even if Phase 2 stalls, Phase 1's refactor is reusable and the spec suite is better. |
| **Bug in custom regex engine = security bug** | (a) Spec-equivalence harness against the existing engine; (b) property tests against PCRE/RE2 as oracles; (c) AFL fuzzing on compile and match; (d) ASan/UBSan on every CI build. All three layers, none optional. |
| **Performance fails to beat Ruby anyway** | Concrete kill criterion before Phase 2 starts: a quick prototype with 10 patterns must beat the equivalent 10-pattern Ruby gsub by ≥3× on a 1 MB log. If it doesn't, the architecture is wrong and we either pivot to option H (Onigmo) or stop. |
| **Onigmo would have been fine** | Document the trade-off in the Phase 2 PR description: Onigmo gets us to parity for free but is MRI-only. If H later turns out to be sufficient for the gem's actual users, we can ship that as a stopgap during Phase 2 without invalidating Phase 2's existence. |

## Open questions to resolve during prep

These get answered by the prep PRs and inform the Phase 1/2 design:

1. **Which overlap policy** — answered by Prep 2.
2. **What regex features must the parser support** — answered by Prep 1.
3. **What API shape** — informed by Prep 4 (RE2::Set vs RegexSet
   trade-offs). Final answer in Phase 1 design.
4. **NFA-simulation vs lazy-DFA vs full-DFA** — deferred to Phase 2
   design; preliminary call after Prep 1 (number of patterns + complexity
   estimate).
5. **Library spin-off timing** — deferred to *after* Phase 2 ships.

## What this plan deliberately does NOT include

- Option H (use Onigmo) — explicitly skipped per 2026-05-23 decision.
  Documented in `TODO.md` as a fallback if Phases 1+2 fail.
- Options C, D (REG_NOSUB, bound greedy quantifiers) — marginal wins on
  the wrong axis. Dead code once Phase 2 ships.
- Library extraction — deferred to after Phase 2 proves the design.
- Streaming API (TODO #8) — Phase 1's per-position loop is the right
  substrate but the public `redact_stream` API is a separate PR after
  Phase 2.
- README rewrite — the perf-disclosure entry stays as-is until Phase 2
  beats Ruby. Then it becomes a feature paragraph instead of a
  disclaimer.
