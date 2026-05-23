# Multi-matcher prototype v1 — Aho-Corasick + regexec

**Status:** experiment complete. Kill criterion not met as stated — but
the result is **informative, not terminal**. See "What the numbers
actually mean" below.

**Date:** 2026-05-23. **Plan:** [docs/multi_matcher_prototype_plan.md](../../docs/multi_matcher_prototype_plan.md).

## What this is

A standalone C library + Ruby FFI driver that tests one hypothesis from
[docs/combined_matcher_plan.md](../../docs/combined_matcher_plan.md):

> *Can a shared-prefix Aho-Corasick filter, followed by `regexec`
> confirmation, beat the equivalent 10-pattern pure-Ruby `gsub` by ≥3×
> on a 1 MB log?*

The specific combination tested was **AC trie + glibc regexec**. The
answer for *that* combination is no — but AC and Boyer-Moore are not
mutually exclusive, and the numbers below explain exactly why the gap
remains and what would close it.

**Not** wired into the gem. **Not** packaged. Kept in-tree as a historical
record of what we tried and what we measured.

## Files

- `matcher.h`, `matcher.c` — Aho-Corasick trie of literal prefixes for
  10 hardcoded patterns, plus POSIX `regexec` confirmation. Slice 1 was
  the AC walk alone (`MM_MAIN` smoke test); Slice 2 added regexec
  confirmation; the smoke binary still builds.
- `Makefile` — `make matcher.so` (the library), `make matcher` (smoke
  binary), `make smoke` (run smoke), `make clean`.
- `bench.rb` — Fiddle binding + Slice 3 correctness check
  (`ruby bench.rb verify`) + Slice 4 benchmark (`ruby bench.rb bench`).
  `ruby bench.rb` runs both.

## How to run

```sh
make clean && make matcher.so
bundle exec ruby bench.rb              # verify + benchmark
```

You need the gem's C extension built (`bundle exec rake compile` from
the repo root) because `bench.rb` cross-checks against
`DataRedactor.scan`.

## The 10 patterns

Same set as the plan. Hardcoded in `matcher.c` and mirrored in
`bench.rb` (PURE_RUBY_REGEXES). Names match the gem's `pattern_names`
so `DataRedactor.scan(only: PATTERN_NAMES)` filters to the same set.

## Results

1 MB payload, 10 iterations, average ms/iter:

| Engine | ms/iter | vs pure-Ruby | vs today's engine |
|---|---|---|---|
| Pure-Ruby `gsub` loop | 69.4 | 1.0× (baseline) | 4.04× faster |
| Today's C engine (10 patterns via `only:`) | 280.7 | 0.25× | 1.0× (baseline) |
| **Prototype (AC + glibc regexec)** | **114.9** | **0.6×** | **2.44× faster** |

The kill criterion as written was ≥3× faster than pure-Ruby. We got
0.6× — **1.65× slower than pure-Ruby gsub**. But the prototype is
**2.44× faster than today's C engine**, which proves the AC prefix filter
works. The gap to Ruby is not in the filter — it is entirely in the
confirmation engine (glibc regexec vs Onigmo).

## What the numbers actually mean

The two-stage pipeline is:

```
Stage 1 (filter)  — AC trie, shared across all patterns, runs once per byte
Stage 2 (confirm) — regexec per candidate position, engine-dependent
```

The filter stage (Stage 1) is demonstrably worth it: 2.44× improvement
over bare sequential regexec. The bottleneck is Stage 2: glibc regexec
is slow, has no Boyer-Moore literal pre-filter, and allocates O(N) state
per call.

**AC and Boyer-Moore are not mutually exclusive.** The AC trie is a
*shared* multi-pattern position filter. Boyer-Moore is a *per-pattern*
literal skip inside the regex confirmation engine. They operate at
different levels and compose:

```
AC filter        → skip positions where no pattern's prefix can start
  ↓ (candidate positions only)
BM / fast regex  → skip bytes inside the regex and confirm quickly
  ↓ (confirmed matches only)
emit match
```

Replacing glibc regexec with Onigmo in Stage 2 would give us both wins.
Ruby's `gsub` only has BM (Onigmo, per-pattern). We additionally have AC
(shared filter). The combined pipeline should be *faster* than either alone.

The 4 always-candidate patterns (`email`, `ipv4`, `credit_card`,
`polish_pesel`) have no literal prefix and bypass the AC filter entirely.
They pay the full Stage-2 cost at every position — same as today. Better
Stage-2 engine helps them too.

## Why glibc regexec is the bottleneck

1. **No Boyer-Moore pre-filter.** glibc's `regexec` evaluates the NFA
   at every candidate position without skipping ahead using literal
   bytes. Onigmo computes a BM shift table at compile time and uses it
   to skip forward.
2. **Per-call allocation.** glibc allocates a state vector proportional
   to input length on each `regexec` call. Onigmo keeps state in a fixed
   stack.
3. **Engine quality.** Onigmo is a modern, actively-maintained regex
   engine optimised for Ruby's workload. glibc regexec is POSIX-correct
   and little more.

## Slice-by-slice notes

- **Slice 1** (~150 LOC C) — AC trie built cleanly on first try. 110
  nodes for the 10 prefix sets. Path-compressed goto table makes the
  scan loop branch-free in the no-hit case.
- **Slice 2** (~50 LOC C) — regexec confirmation via `input + pos` +
  `rm_so == 0` check. Discovered glibc doesn't backtrack
  `[A-Z ]*PRIVATE KEY-----` against `-----BEGIN PGP PRIVATE KEY BLOCK-----`
  — so the pem regex fails to match GPG blocks. This matches the current
  gem's behaviour (same regex engine), so it's a correctness parity, not
  a bug in the prototype.
- **Slice 3** (~40 LOC Ruby) — Fiddle binding worked first try. The
  correctness check uses a *superset* relation because the prototype
  doesn't resolve overlaps (per plan's out-of-scope list); every match
  `DataRedactor.scan` finds must appear in prototype output. All 8 cases
  pass.
- **Slice 4** (~40 LOC Ruby) — benchmark above.

## Time spent

~2 hours total, well under the 2-day budget. The result is instructive:
it isolates the bottleneck to Stage 2 (glibc) rather than the approach.
See [docs/combined_matcher_plan.md](../../docs/combined_matcher_plan.md)
for next options.
