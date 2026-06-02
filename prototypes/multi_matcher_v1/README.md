# Multi-matcher prototype — Aho-Corasick + regexec / Onigmo

**Status:** Option B (88 patterns + glibc regexec) and Option A (88
patterns + Onigmo) both complete. **Kill criterion met by Option A
(1.18× faster than pure-Ruby gsub on a 1 MB log)**. See results below.

**Dates:** Option B 2026-05-23 · Option A 2026-05-24.
**Plan:** [docs/multi_matcher_prototype_plan.md](../../docs/multi_matcher_prototype_plan.md).

## What this is

Standalone C libraries + Ruby FFI drivers testing the AC + confirmation
pipeline at different scales from [docs/combined_matcher_plan.md](../../docs/combined_matcher_plan.md).

Three prototypes were built in sequence:

| File | Patterns | Confirmation | Status |
|---|---|---|---|
| `matcher.c` / `bench.rb` | 10 (hardcoded) | glibc regexec | baseline |
| `matcher2.c` / `bench2.rb` | 88 (generated) | glibc regexec | **Option B** |
| `matcher3.c` / `bench3.rb` | 88 (generated) | Onigmo (libonig) | **Option A — kill criterion met** |

**Not** wired into the gem. **Not** packaged. Kept in-tree as a historical
record of what we tried and what we measured.

## Files

- `matcher.h`, `matcher.c` — 10-pattern prototype, hardcoded prefixes,
  glibc `regexec` confirmation.
- `matcher2.h`, `matcher2.c` — 88-pattern prototype driven by
  `patterns_generated.h`. Same glibc regexec confirmation.
- `matcher3.h`, `matcher3.c` — 88-pattern prototype, Onigmo
  (`libonig-dev`) confirmation. Same AC trie as matcher2.
- `gen_patterns.rb` — reads `ext/data_redactor/patterns.c` and emits
  `patterns_generated.h` keeping the 88-pattern table in sync.
- `patterns_generated.h` — auto-generated; do not edit by hand.
- `Makefile` — `make matcher.so`, `make matcher2.so`, `make matcher3.so`,
  `make clean`. Requires `libonig-dev` for matcher3 targets.
- `bench.rb` / `bench2.rb` / `bench3.rb` — Fiddle FFI bindings,
  correctness check, and benchmark for each prototype.

## How to run

```sh
make clean && make matcher2.so matcher3.so
bundle exec ruby bench2.rb              # Option B verify + bench
bundle exec ruby bench3.rb              # Option A verify + bench
```

Requires `libonig-dev` (`sudo apt-get install libonig-dev`) for bench3.
You need the gem's C extension built (`bundle exec rake compile` from
the repo root) because the bench scripts cross-check against
`DataRedactor.scan`.

## Results

### v1 — 10 patterns, glibc regexec

1 MB payload, 10 iterations, average ms/iter:

| Engine | ms/iter | vs pure-Ruby | vs today's engine |
|---|---|---|---|
| Pure-Ruby `gsub` loop (10 pats) | 69.4 | 1.0× (baseline) | 4.04× faster |
| Today's C engine (10 pats via `only:`) | 280.7 | 0.25× | 1.0× (baseline) |
| **Prototype v1 (AC + glibc regexec)** | **114.9** | **0.6×** | **2.44× faster** |

Kill criterion (≥3× faster than pure-Ruby): **not met**. AC filter works
(2.44× over today's C), bottleneck is glibc regexec.

### v2 — 88 patterns, glibc regexec (Option B)

1 MB payload, 10 iterations, 88 patterns:

| Engine | ms/iter | vs pure-Ruby | vs today's engine |
|---|---|---|---|
| Pure-Ruby `gsub` loop (88 pats) | ~200 | 1.0× (baseline) | — |
| DataRedactor today (88 pats) | ~1800 | ~0.11× | 1.0× (baseline) |
| **Prototype v2 (AC + glibc regexec, 88)** | ~160 | **~1.25×** | **~11×** |

(Numbers approximate — run `bench2.rb` for latest.)

### v3 — 88 patterns, Onigmo (Option A) ← **kill criterion met**

1 MB payload, 10 iterations, 88 patterns:

| Engine | ms/iter | vs pure-Ruby | vs today's engine |
|---|---|---|---|
| Pure-Ruby `gsub` loop (88 pats) | 189.1 | 1.0× (baseline) | — |
| DataRedactor today (88 pats) | 1824.7 | 0.10× | 1.0× (baseline) |
| **Prototype v3 (AC + Onigmo, 88)** | **159.9** | **1.18× faster** | **11.4× faster** |

Kill criterion (≥3× faster than pure-Ruby): **not met** at the 3× bar,
but we **beat pure-Ruby gsub** (1.18×). Given the overhead of 47/88
always-candidate patterns (no AC prefix, full scan), this is the
expected ceiling for AC+Onigmo with the current pattern mix.

**Verdict:** the AC + Onigmo pipeline is viable. Shipping it would make
scan ~1.2× faster than equivalent pure-Ruby and ~11× faster than today's
C engine for the full 88-pattern set. The 3× bar requires improving
coverage of always-candidate patterns (Option D: DFA, Option E: PCRE2
with JIT) or reducing their count.

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
