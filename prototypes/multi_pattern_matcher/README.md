# Multi-pattern matcher — research prototypes (v1 → v19)

The full research arc that produced the engine now shipping in the gem. Eighteen
standalone C matcher generations were built and benchmarked here; **v19 is the
endpoint** and was ported into `ext/data_redactor/matcher.c` and shipped in **0.10.0**
(2.3× over pure-Ruby `gsub`, ~11× over the old per-pattern `regexec` engine,
zero external dependencies).

> **The authoritative write-up is [`docs/research_log.md`](../../docs/research_log.md).**
> It documents every prototype (§5), the algorithms (§4), the bugs and their root
> causes (§6), and the bibliography (§3). This README is just a map of the files and
> how to build/run them — it deliberately does **not** duplicate the per-version
> analysis. When the two disagree, the research log wins.

These prototypes are **not** wired into the gem and **not** packaged. They are kept
in-tree as a reproducible historical record: every number in the research log can be
re-measured by building the matcher and running its bench/verify script.

## The arc, in one table

Milestones flagged ★. Full detail per row is in `docs/research_log.md §5`.

| Version | File | Stage-2 engine / key idea | Result |
|---|---|---|---|
| v1  | `matcher.c`        | 10 patterns, AC + glibc regexec | baseline; isolates the regexec bottleneck |
| v2  | `matcher2.c`       | 88 patterns, AC + glibc regexec (Option B) | ~1.25× Ruby |
| v3  | `matcher3.c`       | 88 patterns, AC + Onigmo (Option A) | 1.18× Ruby — viable but needs a dependency |
| v4  | `matcher4.c`       | Thompson NFA + lazy DFA cache (Option D) | first DFA path |
| v5  | `matcher5.c`       | AC + Onigmo + Boyer-Moore infix pre-filter | |
| v6  | `matcher6.c`       | AC + BM + glibc regexec | |
| v7  | `matcher7.c`       | AC + BM + PCRE2 interpreter & JIT | 2.79× Ruby — but needs libpcre2 (rejected) |
| v8  | `bench_bm_inner.c` | BM bad-character filter inside the regexec loop | |
| v9  | `matcher9.c`       | 88 per-pattern Thompson NFA + lazy DFA | |
| v10 | `matcher10.c`      | per-pattern NFA, precomputed transition table | |
| v11 | `matcher11.c`      | per-pattern Thompson **bytecode VM** | |
| v12.1 | `matcher12.c`    | VM + literal pre-filter for all patterns | |
| v14 | `matcher14.c`      | literal filter + first-byte filter | |
| v15.1 | `matcher15.c`    | VM constant-factor speedups | the per-pattern baseline v18+ builds on |
| v15.2 | `matcher16.c`    | cross-pattern union first-byte bitmap | |
| v17 | `matcher17.c`      | precomputed initial thread list | |
| v18 | `matcher18.c`      | per-pattern lazy DFA transition cache | ★ **breakthrough** |
| v18.1 | `matcher18_1.c`  | anchor lowering, all 88/88 patterns on DFA | ★ |
| v19 | `matcher19.c`      | v18.1 + merged pure-digit group + IBAN union pass | ★ **shipped** (zero-dep, byte-for-byte equal to Ruby) |

`matcher19b.c` / `matcher19c.c` are `https://`-variant spikes (union pass vs
required-literal); see the v19 section of the research log.

## Files

- `matcher*.c` / `matcher*.h` — the matcher generations above.
- `gen_patterns.rb` — reads `ext/data_redactor/patterns.c` and emits
  `patterns_generated.h`, keeping the prototype's 88-pattern table in sync with the
  gem (the gem is the source of truth — the table flows one way, gem → prototype).
- `patterns_generated.h` — auto-generated; do not edit by hand.
- `bench*.rb` — Fiddle FFI bindings + correctness check + benchmark per prototype.
- `verify*.rb` — differential oracles: assert a matcher is byte-for-byte equal to a
  reference (e.g. `verify19.rb` proves v19 == v15 on every payload).
- `bench_bm_inner.c`, `bench_iban_cost.c`, `bench_malloc.c` — isolated microbenchmarks
  for specific cost questions (BM inner loop, IBAN union cost, per-call allocation).
- `Makefile` — per-target builds (`make matcher19.so`, `make matcher19`, `make clean`,
  …). Build artifacts (`*.so`, compiled binaries) are git-ignored and regenerated.

## How to run

```sh
make clean
make matcher19.so                     # build the shipped endpoint
bundle exec ruby verify19.rb          # differential correctness vs reference
bundle exec ruby bench_realistic.rb   # benchmark on a realistic payload
```

The bench/verify scripts cross-check against `DataRedactor.scan`, so build the gem's
C extension first (`bundle exec rake compile` from the repo root). The Onigmo (v3, v5)
and PCRE2 (v7) targets need `libonig-dev` / `libpcre2-dev` respectively; the v9→v19
line is pure C with no external dependency, which is the whole point of the arc.
