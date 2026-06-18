# TODO

Open work only. Completed items have been archived in [DONE.md](DONE.md); the
detailed record of every shipped change lives in [CHANGELOG.md](CHANGELOG.md).
Permanent design rationale is in the [Design decisions](#design-decisions)
section at the bottom (kept here, not in DONE.md — it's reference, not a task).

---

## Engine & correctness

### Bound greedy tails — remaining follow-ups
- **Optional / per-tag "redaction-for-privacy" mode** (low priority). Let a caller
  or per-tag policy force unbounded matching so *every* byte of an over-long token
  is redacted, not just the bounded 255-char prefix. Deferred: the v19 engine
  compiles one immutable shared table, so a per-call toggle needs two compiled
  copies per affected pattern; the benefit is marginal (a 255-cap already kills the
  token); it adds API surface nobody has asked for. If it ships, bake a per-tag
  policy at init rather than a per-call flag. Revisit only on a concrete request.
- **Re-examine the `jwt` regex.** 0.14.1 only capped the tail. Real JWT signature
  lengths are fixed per alg (HS256≈43, ES256≈86, RS256≈342) — could anchor lengths
  instead of the trailing quantifier (three base64url segments, `eyJ` anchor on
  each).

### Accepted divergence — rewrite-created/destroyed boundary
Two sensitive tokens that **directly abut with no separator** can diverge from the
old sequential-rewrite engine (~2% of adjacency-heavy synthetic inputs; irrelevant
in real, delimiter-separated text). **Decision: accept, do NOT model the rewrite.**
The longest-match-wins resolver (0.15.0) already fixes every case where one longer
pattern spans both tokens; the residual cases are only those where no single pattern
covers the join, and today's output there is itself a glibc-rewrite artifact. If a
future need arises, a bounded re-scan around each `[REDACTED]` edge would recover
byte-identical behaviour without a full multi-pass. (See the divergence ledger in
DONE.md.)

### Full per-call thread re-entrancy
`mm_scan` still mutates per-engine scan scratch (`iban_last_end`, `digit_last_end`,
DFA scratch). Phase 1 is safe only because MRI's GVL serialises C-extension calls.
Full re-entrancy needs the mutable scan scratch in a per-call context struct
(alloca/stack or caller-supplied). Prerequisite for releasing the GVL further or
supporting Ractors.

### Recover the ~3% small-input throughput
Lost to the per-thread-state indirection. Hoist the `thread_state()` generation
check out of the hot path / cache the `scan_state_t *` base; consider inlining. Low
priority (within run variance) but worth a pass before the paper's benchmark table.

### Widen the GVL-free region to custom patterns
Blocked on moving customs onto the v19 engine (multibyte-UTF-8-in-char-classes
parser work). Until then a payload that is both huge AND custom-heavy blocks during
its (rare) custom phase. Customs currently run on the glibc `regexec` path
specifically because `name_pattern` emits multibyte UTF-8 char classes (`[oOòóôõöø…]`)
that the byte-level v19 parser can't match — teaching the parser to treat a
multibyte sequence inside `[...]` as one alternative is the gating task.

### Release the GVL in `scan` too
`scan`'s event loop builds Ruby `VALUE` hashes throughout, so it can't release the
GVL without first separating the C match-collection pass from the `VALUE`-building
pass. Only if scan-heavy large inputs ever matter.

### Other deferred engine work
- **Custom patterns in selective merges** — pure-digit / IBAN-prefix customs won't
  join the group passes; handled per-pattern by glibc. Revisit if perf matters.
- **Streaming `mm_scan_chunk`** — scan across caller-managed chunks without
  buffering the full string in C. Not needed while callers buffer Ruby strings.
- **Hopcroft minimisation** of the lazy-DFA states — smaller transition tables,
  better cache behaviour on large pattern sets.
- **`pthread_rwlock_t`** for custom-pattern registration — only if registration
  ever becomes hot enough that the mutex's reader-exclusion shows up. Current
  contention is negligible; the simpler mutex stands. (An atomic copy-on-write
  snapshot is the other option — overkill until someone reports a real problem.)

---

## CI / testing

- **Fuzz / ASan CI harness** — the `OP_EOL` OOB read (already fixed) was found by
  ASan; a CI fuzz job would catch regressions. See
  `docs/standalone_matcher_design.md` risk table.
- **musl load-and-smoke CI matrix job** — the release build only cross-compiles; it
  never `require`s the gem on musl, which is how the `hvb {138,300}` > `RE_DUP_MAX`
  load-time bug shipped (fixed 0.10.1). A load-and-smoke step on `ruby:3.x-alpine`
  would catch this class. (The zero-alloc gate already runs under musl.)
- **Throughput-trend visualization over time** (optional) — the in-PR throughput
  gate keeps no history. If slow drift across many small PRs becomes a concern,
  layer `github-action-benchmark` on `gh-pages` to plot the ratio and post
  before/after PR comments. Nice-to-have, not blocking.

---

## Features (roadmap, not yet started)

### Checksum validation (#7)
Massive false-positive killer; apply only when the structural regex already
matched: Luhn (credit cards), mod-97 (IBANs), Italian Codice Fiscale check char,
Spanish DNI letter, Brazilian CPF/CNPJ, PESEL, CNP, etc. Probably an opt-in
per-call flag (`strict: true`) since validation costs CPU.

### Streaming API (#8)
`DataRedactor.redact_stream(input_io, output_io)`. Chunk boundaries can split a
match — needs an overlap/lookback window equal to the longest pattern. Solve
together with the engine's `mm_scan_chunk` item above.

### Value-level allowlist
`DataRedactor.redact(text, allow: [/example\.com/, "test@foo.com"])` — suppress
individual *matches* whose value is allowlisted, regardless of which pattern hit
them. Distinct from the shipped pattern-level `only:`/`except:`. Implement as a
per-match check after a match succeeds, or a post-filter on `scan`. Defer until
someone asks — `except: ["email"]` already covers the common case.

### Richer YAML key-name anchoring (separate pass)
Flat `key: value` YAML already ships. Not yet handled:
- Block scalars: `password: |` / `password: >` with the value on following indented
  lines (our value grammar stops at newline).
- Flow mappings: `{ password: secret, ... }` (terminator is `,`/`}`).
- `=>` (hashrocket) separator — only `=` and `:` shipped. Add if requested.

### Length-aware placeholder
- `placeholder: :length` → `[REDACTED:16]`
- `placeholder: :tagged_length` → `[REDACTED:CONTACT:16]`

`write_placeholder` already receives `match` + `match_len`; each mode is one
`sprintf` plus the Ruby symbol dispatch in `resolve_placeholder`.

### Rack `:env_logs` surface
Scrub `PATH_INFO` / `QUERY_STRING` for downstream access loggers. Deferred — needs
to wrap the upstream logger rather than mutate env, which has blocked the design.

### Possible Erlang / Elixir port
The C core is portable; the Ruby-specific layer is thin. Two shapes: a NIF
(`erl_nif.h`) wrapping the same engine as a Hex package `data_redactor_ex`, or pure
Elixir over `:re` (PCRE). Defer until the Ruby gem has real adoption and someone
asks. Cost: maintenance doubles, NIF segfaults crash the whole BEAM VM, separate CI
+ Hex publishing. Documented so the option isn't forgotten.

---

## Paper

Research log at `docs/research_log.md` is the source of truth (all prototype data,
benchmark methodology, root-cause analysis, related work, open questions).

1. Complete benchmark rigor: document hardware, OS, Ruby/glibc versions; add stddev
   across runs; add a microbenchmark isolating AC filter overhead from confirmation
   overhead.
2. Add profiling evidence (perf/callgrind): show where cycles go in v2 (glibc) vs v3
   (Onigmo) to support the "BM literal pre-filter is the decisive factor" claim.
3. Post preprint to **arXiv** (`cs.PL` + `cs.DS`) — establishes priority, no peer
   review.
4. Submit to **Software: Practice and Experience** (Wiley, Q2) as the primary venue
   (~6–12 months to decision, no conference travel).
5. If SPE pushes back on novelty: retarget **USENIX ATC** (experience report track).

**Shape:** systems/experience report, 12–15 pages. Core contribution: a two-stage
AC + fast-engine pipeline is near-optimal for mixed-prefix DLP pattern sets; the BM
pre-filter is a worthwhile third stage; always-candidates are the binding
constraint. Cite Hyperscan (NSDI 2019), BLARE (SIGMOD 2023), HybridSA (OOPSLA
2024). Estimated effort: 3–4 months part-time (10–15 h/week).

---

## Promotion (post-publish visibility)

- Submit to [The Ruby Toolbox](https://www.ruby-toolbox.com).
- Post to r/ruby and r/rails — ask for feedback, don't just sell it.
- Write a short DEV/Medium article: "Why I built a C-extension PII redactor for
  Ruby" (the C vs pure-Ruby angle is the hook).
- Announce on X / Mastodon with `#ruby` `#rails`.
- Submit to [Ruby Weekly](https://rubyweekly.com) and
  [Short Ruby Newsletter](https://newsletter.shortruby.com).
- Offer a 5-minute lightning talk at a local/virtual Ruby meetup.
- **Ongoing:** keep CHANGELOG current; respond to issues/PRs promptly; track
  RubyGems download stats.

---

## References

- https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- https://github.com/advanced-security/secret-scanning-custom-patterns
- https://github.com/gitleaks/gitleaks/tree/master

---

## Design decisions

Permanent record of choices made and why, so future contributors don't re-litigate
them. Add an entry when a non-obvious decision is made; remove one only when the
decision is reversed (and note the reversal in CHANGELOG).

### Regex engine: POSIX `regex.h`, not Onigmo / PCRE
- **Why:** ships with libc on Linux/macOS, zero extra dependency, fast enough, keeps
  the C small.
- **Cost:** no `\d`, `\s`, `\w`, `\b`, `(?:...)`, lookaround, non-greedy, named
  groups. Patterns must be POSIX ERE; we use a manual boundary wrapper
  (`(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)`) where word boundaries are needed.
- **Reversible?** Yes — could swap to Onigmo later if user patterns need richer
  syntax, at the cost of linking Ruby internals or PCRE.

### Pattern ordering: most-specific first, generic last
- **Why:** patterns run sequentially on a working buffer; an early broad pattern
  (e.g. 9-digit passport) can consume digits a later pattern (credit card) needs.
  Specific→generic + boundary-wrapping the generic ones prevents this.
- **Cost:** adding a pattern requires choosing the right tier.
- **Reversible?** Difficult — would require a different match-collection algorithm
  (find all matches, resolve overlaps, then replace). *(Partly realized by the v19
  engine's `mm_resolve`; see DONE.md.)*

### Tag system: 8 fixed bits + 1 reserved (`:custom`)
- **Why** (over free-form tags): no registry, no dynamic bit allocation, simple
  `int` mask, covers the obvious use cases. Free-form tags can be added later
  without breaking the API.
- **Cost:** users can't add arbitrary tags like `:internal_pii`; they get `:custom`
  for everything user-defined.
- **Reversible?** Yes — additive; free-form tags slot into bits 9–31.

### Custom patterns: strict validation, no Ruby-syntax translation
- **Why:** predictable behaviour. `\d` in a custom pattern raises a clear
  `InvalidPatternError` at registration, not a silent mismatch at redaction.
- **Cost:** ergonomic friction — users must know POSIX ERE.
- **Reversible?** Yes — translation can be added later without breaking strict
  patterns.

### `[REDACTED]` as the default placeholder
- **Why:** one allocation strategy, one length constant, simpler C. *(Configurable
  modes shipped in 0.4.0 — plain / `:tagged` / `:hash`.)*
- **Reversible?** Yes — already extended.

### Process-local state for custom patterns (no persistence)
- **Why:** matches built-in behaviour (compiled at init, lives until VM exit).
  Predictable, no I/O at redaction time, no config parser.
- **Cost:** every process re-registers at boot. App-level concern.
- **Reversible?** Yes — a YAML/JSON loader is on the deferred list.

### Public API is the Ruby wrapper, not the C function
- **Why:** keyword args (`only:`, `except:`) are awkward in C-defined methods. The
  Ruby wrapper validates, builds the bitmask, then calls `_redact(text, mask)`.
- **Cost:** one extra Ruby call per redaction. Negligible vs the C work.
- **Reversible?** Yes, but no reason to.
