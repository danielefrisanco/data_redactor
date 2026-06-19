# DONE

Archive of completed work, moved out of [TODO.md](TODO.md) to keep that file to
open items only. The authoritative, line-by-line record of every user-visible
change is [CHANGELOG.md](CHANGELOG.md); this file keeps the *rationale and research
narrative* that doesn't belong in a changelog. Versions are noted where a change
shipped in a release.

---

## Multi-pattern matcher research → v19 engine (the production payoff)

The whole research arc (prototypes v1–v19, `prototypes/multi_pattern_matcher/`,
`docs/research_log.md`) converged on **v19**: a zero-dependency, pure-C engine
(NFA → bytecode → per-pattern lazy DFA + two selective merges) that is **2.3× over
pure-Ruby, ~11× over the old C, byte-for-byte equal to Ruby `gsub`**.

- **Prototype decision.** v7 (AC + BM + PCRE2 JIT) cleared the ≥2× bar but required
  `libpcre2-dev` with JIT — violates the zero-runtime-dependency rule. Abandoned in
  favour of the zero-dependency v8→v19 pure-C engine. v19 is the engine that
  shipped.
- **v18.1 EOL-at-buffer-end bug — FIXED (v19.1).** The lazy-DFA path dropped
  boundary-wrapped matches ending exactly at end-of-buffer (`OP_EOL` never fired in
  the position-independent closure). Fix: `scan_one` NFA-falls-back for start
  positions within `max_len` of the buffer end when the pattern carries `$`
  (`has_eol`), symmetric to the existing BOL fallback. Touches only buffer-tail
  bytes; hot path unchanged. `verify19.rb` is byte-for-byte equal to v15 on every
  payload (escape hatch removed).
- **Port into the gem (Gaps 1–5, shipped 0.10.0; minor bump, no API change).**
  - **Gap 1 — source of truth.** Built-ins live in `ext/data_redactor/patterns.{h,c}`;
    the engine table is built from them at `mm_init()`.
  - **Gap 2 — hybrid split (decided 2026-06-09).** The v19 engine handles ONLY the
    88 built-in patterns (all pure ASCII). **Custom patterns keep running through
    glibc `regexec`**, unchanged. Necessary, not just convenient: `name_pattern`
    emits multibyte-UTF-8 char classes (`[oOòóôõöø…]`) that glibc matches but the
    byte-level v19 parser can't — routing customs through glibc preserves the
    `José`/`Muñoz` match exactly. (`mm_add`/`mm_remove`/`mm_clear_custom` exist but
    are unused by the gem.)
  - **Gap 3 — thread-safety (0.13.0).** `engine_t` split into immutable shared
    compiled state and per-thread `scan_state_t` (NFA scratch, digit/IBAN cursors,
    lazy DFA cache) in a `__thread` block; `g_pattern_gen` invalidates a thread's
    cache on pattern-set change. Concurrency stress test added (a real race detector
    — fails 3/3 with `__thread` stripped).
  - **Gap 4 — selective merges.** Digit-group and IBAN-union passes are detected
    once at `mm_init()` over the fixed built-in set; moot under the hybrid split.
  - **Gap 5 — overlap resolution.** `mm_scan` emits raw events; `mm_resolve`
    resolves them. Originally an index-order greedy claim reproducing the old
    "earlier-index wins" behaviour byte-identically (decided 2026-06-09,
    differential-tested over 4000+ randomized inputs).
- **Longest-match-wins overlap policy (0.15.0, `feat/longest-match-resolver`).**
  `mm_resolve` now keeps the longest CORE span at each position; equal-length ties
  go to the lower pattern-id. A drop-in swap of the resolve sort key + keep-rule —
  `mm_scan` and the hot path untouched, throughput unchanged (2.38× on the 1 MB
  log). Deliberate behaviour change: redacts *more* when uncertain (a 40-char AWS
  secret is redacted whole rather than leaking bytes past a shorter prefix),
  aligning with Onigmo/PCRE/RE2/Hyperscan.
- **Ship hygiene.** 256-example rspec suite green against the new engine;
  `extconf.rb` builds with no new dependency on glibc + musl/Alpine; end-to-end
  bench: 1 MB log **0.87 → 7.27 i/s** (~8.4× throughput; from 4× slower than pure
  Ruby to 2.25× faster).

### Bound greedy tails (0.14.1, `feat/bound-greedy-tails`)
Bounded the open-ended tails of seven Tier-2 token patterns at `RE_DUP_MAX` (255):
`jwt`, `grafana_api_token`, `ssh_public_key`, `bearer_token`, `anthropic_api_key`,
`openai_project_api_key`, `sendgrid_api_key`. Restores a finite `max_len`, removes
the O(N²) worst case. **Policy: redaction-for-safety (flat, not per-call optional)**
— a 255-cap already redacts the whole front of any realistic token; only a
crypto-dead tail of an >255-char token survives. Tier-1 URL/email tails left
unbounded (delimiter-terminated, a different risk class). Each bounded pattern got
an over-255 positive spec.

### Legal check before shipping the BM implementation (2026-06-02)
No copying. `build_bm_tables` + `bm_find` is the Horspool (1980) bad-character-only
variant (~20 lines, textbook). Onigmo's `bm_search` uses the same algorithm because
it *is* the algorithm; structural similarity is inevitable. No attribution or
rewrite needed.

### Divergence ledger (ported engine vs original gem)
1. **Single-pass original-frame emission** — `mm_scan` scans the original input once
   and emits CORE-frame `(pattern_id, start, length)` directly, replacing N
   `regexec` passes with coordinate-mapping. Simpler and faster.
2. **Directly-abutting tokens with no separator** (accepted; see TODO.md) — a
   boundary-wrapped pattern can miss a match where the original buffer has no word
   boundary that a `[REDACTED]`-created boundary would have provided. ~2% of
   adjacency-heavy synthetic inputs; irrelevant in real text.
3. **Custom patterns bypass the selective merges** — customs always go through glibc
   `replace_all_matches`, even a pure-digit/IBAN-prefix regex.
4. **Overlap policy is longest-match-wins** (0.15.0).

---

## Full thread safety

- **Custom-pattern lock (0.12.0, `feat/custom-pattern-lock`).** Plain
  `pthread_mutex_t` around the custom-pattern array; critical sections kept
  `rb_raise`-free so the mutex can't leak via longjmp. Linked `-lpthread` on glibc.
  Closed a latent race that becomes load-bearing once the GVL is released.
- **Per-thread engine scan state (0.13.0, `feat/gvl-release` Step 1).** Immutable
  shared compiled/DFA state vs per-thread `scan_state_t` in a `__thread` array,
  lazily grown; `g_pattern_gen` drops a thread's cache on pattern-set change. 286
  specs + a differential gate (~6000 inputs byte-for-byte vs baseline) +
  gen-invalidation specs. 0 allocations/scan steady state; ~3% lower small-input
  throughput (the indirection — recovery tracked in TODO.md).
- **Release the GVL during long redactions (0.13.0, Step 2).** `redact` releases the
  GVL via `rb_thread_call_without_gvl` around the built-in v19 pass for inputs ≥ 4
  KB; smaller inputs run inline. Custom glibc loop stays under the GVL. New parallel
  large-input spec is a real race detector.
- **Lower the per-thread DFA memory floor (0.13.0).** Lazy-DFA `states_cap` start
  64 → 8. Per-thread DFA ~3.2 MB → ~0.86 MB (−73%); throughput within noise.
- **Free per-thread scan state on thread exit (0.13.0).** Heap `thread_block_t`
  registered with a `pthread_key_t` destructor; RSS flat (~0.22 KB/thread) over 500
  churning threads, plus a spawn-join stress spec.
- **README** updated: per-thread engine state + GVL-release for large inputs +
  runtime-registration guarantee.

---

## Patterns added

- **Distinctive-prefix API keys (0.6.1), tag `:credentials`:** Anthropic
  (`sk-ant-api03-`), OpenAI (`sk-proj-`), GitLab PAT (`glpat-`), DigitalOcean PAT
  (`dop_v1_`), Databricks (`dapi`), Sentry DSN (modern + legacy `KEY:SECRET@`).
  HashiCorp Vault service (`hvs.`) + batch (`hvb.`) tokens, Terraform Cloud
  (`atlasv1`). Skipped: Heroku (plain UUIDv4, covered by `uuid_v4`), Okta/PagerDuty
  (no stable prefix → FP risk), Azure SQL hostname (not a secret), DataDog
  (deferred — needs a context-aware prefix).
- **Assignment-style key-name-anchored secrets (0.14.0).** Redact a value by the
  *name of the field* it's assigned to (`PASSWORD=…`, `api_key: …`), not by the
  secret's own format. Key words: `password`, `passwd`, `pwd`, `secret`, `token`,
  `api_key`, `apikey`, `access_key`, `client_secret` (case-insensitive via explicit
  char-class expansion). Compound keys both ways. Redacts only the **value**, keeps
  the key (greppable logs) via a `keyname_anchored[]` tier + emit-block strip rule.
  Requires `=`/`:` so prose ("reset your password") never matches; unquoted values
  need ≥6 chars to cut FPs like `FLAG=true`. Out of scope: `*_URL=` (too generic),
  `%PWD%` templates (references, not assignments), `=>` separator.

---

## Roadmap items shipped

- **Tagged categories (0.2.0)** — 8 tags + `:custom`, `redact(only:/except:)`,
  `DataRedactor.tags`/`TAGS`/`UnknownTagError`, C-level bitmask filtering.
- **User-supplied custom patterns (0.3.0)** — `add_pattern`/`remove_pattern`/
  `custom_patterns`/`clear_custom_patterns!`, strict POSIX-ERE validation
  (`InvalidPatternError` at registration), `:custom` reserved tag, registration-order
  execution after built-ins.
- **Configurable placeholder (0.4.0)** — plain `"***"`, `:tagged`
  (`[REDACTED:CONTACT]`), `:hash` (`[CONTACT_a3f9]`, djb2).
- **Length-aware placeholder (0.15.1)** — `:length` (`[REDACTED:16]`) and
  `:tagged_length` (`[REDACTED:CONTACT:16]`), where the number is the byte length
  of the core match (boundary chars excluded, consistent with `:hash`). Two new
  `placeholder_t` modes, one `sprintf` each; additive values on the existing
  `placeholder:` keyword — patch bump, no API/behaviour change.
- **Report / dry-run mode (0.5.0)** — `scan` returns `{ redacted:, matches: [...] }`
  with byte offsets into the original string.
- **Pattern-level allowlist (0.6.0)** — `only:`/`except:` accept Symbols (tags) and
  Strings (names); `except:` wins on overlap; single-pass per-pattern enable bits.
- **Rails / Rack integration (0.7.0)** — `Integrations::Logger`,
  `Integrations::Rails.filter`, `Integrations::Rack` (soft-required, zero deps).
- **Hash / JSON / object traversal (0.8.0)** — `redact_deep`, `redact_json`
  (pure-Ruby walker over the C `redact`).
- **Name-pattern helper (0.9.0)** — `DataRedactor.name_pattern(first, last,
  middle:)` returns a POSIX ERE String with baked-in boundary, optional separators,
  and bidirectional diacritic folding.
- **Claude / OpenAI integration (0.11.0)** — `Integrations::Claude` /
  `Integrations::OpenAI` `.redact_messages` + `.redact_response`; deep-copy (never
  mutate), pass non-text blocks through, forward `only:`/`except:`/`placeholder:`,
  no SDK dependency.
- **Distribution / QoL** — published to RubyGems (0.5.0, 2026-05-08); CI matrix
  Ruby 3.1–3.4 on Linux glibc + musl; OIDC trusted publisher; 100% YARD docs +
  GitHub Pages deploy; README thread-safety note + Shields.io badges; precompiled
  binaries via `rake-compiler-dock` (6 native gems, 0.7.2); CHANGELOG + SemVer
  (0.1.0); CI/release actions bumped to Node-24-compatible versions; `release:
  published` trigger dropped from `ci.yml`.
- **`extconf.rb` glob** — `$srcs = Dir.glob(...)` so adding a module needs no
  Makefile change.

### musl/Alpine build verification (2026-06-10)
`memmem`/`_GNU_SOURCE`, the digit/IBAN merges, and the EOL fallback compile clean
and match correctly on `ruby:3.3-alpine`. Surfaced + fixed a real load-time bug
(0.10.1): `hashicorp_vault_batch_token`'s `{138,300}` exceeds POSIX `RE_DUP_MAX`
(255) — glibc accepts it, musl's `regcomp` rejects it, so the native musl gem raised
at `require`. Capped to `{138,255}`. (A musl *load*-and-smoke CI job is still wanted
— tracked in TODO.md.)

---

## C extension refactor
`data_redactor.c` (1047 lines) split into `tags.h`, `patterns.{h,c}`,
`placeholder.{h,c}`, `custom_patterns.{h,c}`, `redact.{h,c}`, `scan.{h,c}`, and a
60-line `data_redactor.c` entry point. Pure structural change; all specs green.

---

## Performance research (the road to v19)
The detailed narrative — why the old engine was O(N²), confirmed from glibc and
Onigmo source — is preserved in git history and `docs/research_log.md`. Summary of
what shipped on the way:

- **0.x perf fixes (`fix/redact-performance`, 2026-05-23).** B — `strstr` literal
  pre-filter (54/88 patterns); G — chunk inputs > 64 KB in the Ruby wrapper, bounding
  glibc's per-call O(N); buffer-sizing fix; deep-scan offset fix (repl_log in
  original-input coords). B: ~25–30% faster across the board; G: linear scaling for
  large inputs (10 MB: 56 s → ~15 s). Honest conclusion at the time: still 3–5×
  slower than pure Ruby — Onigmo's built-in Boyer-Moore pre-filter was structurally
  faster than a manual `strstr`. That gap is what the v19 engine finally closed.
- **Root cause confirmed.** glibc `re_search_internal` allocates an O(N) state-log
  per call before matching; the per-pattern loop over a shrinking buffer is
  Σ(N−cursorᵢ) ≈ O(N²/2). The bug was glibc's calling convention, not our loop —
  fixable only by calling `regexec` less (chunking/pre-filter) or not at all (the
  combined matcher → v19).
- **Engine survey** (options A–J) recorded in history: RE2 (not multi-pattern),
  Hyperscan (x86-only), Aho-Corasick (literals only), Onigmo (MRI-coupling +
  identity cost) — no portable, multi-pattern, regex-subset C library exists, which
  is exactly why the combined matcher (v19) was built in-house.

---

## Benchmarks
- **Suite (`benchmark/`, on `feat/benchmarks`):** `support/corpus.rb` (payload
  builders + pure-Ruby baseline, reads `BUILTIN_PATTERN_SOURCES`/`BOUNDARY` live),
  `throughput.rb`, `per_pattern.rb`, `vs_pure_ruby.rb`, `scaling.rb` (1 KB → 50 MB),
  `README.md`. `vs_alternatives.rb` skipped — no comparable maintained Ruby gem.
- **Post-v19 numbers (2026-06-10, 0.10.1):** vs_pure_ruby 1.6–2.4× faster small
  strings, 2.1× on 1 MB; throughput ~7 MB/s flat 1 KB→50 MB (confirms O(N)). README
  gained a Benchmarks section; `benchmark/` confirmed excluded from the built `.gem`.
- **CI gates.** Zero-allocation hot-path gate (`benchmark/ci_alloc_gate.c`,
  0.13.0) — interposes `malloc`/`realloc`/`calloc`, asserts 0 allocs/scan; a
  deterministic hard gate, run under both glibc and musl. Throughput-regression gate
  (`benchmark/ci_throughput_gate.rb`, 0.14.1) — gates on the C-engine **ratio** to a
  pure-Ruby gsub loop (`MIN_RATIO=1.5`; cancels runner variance) with a correctness
  guard.

---

## Paper (`paper/`, research/experience report)

The paper is about the *work* — replacing the redaction engine under production
constraints — not a gem changelog. Sole author; Claude used as a directed instrument
(disclosed, not credited). Draft is `paper/main.tex` (acmart, ~14 pp, builds clean).

- **Benchmark rigor + one operating point (2026-06-18).** Hardware/OS/Ruby/glibc
  versions pinned in `paper/data/environment.md`. The original headline table spliced
  two operating points (fast engines at performance-clock-under-boost, glibc baseline
  at an older powersave draft) and carried a caveat. We re-ran the slow glibc baseline
  at a verified `performance` governor (`density_sweep_glibc_perf.csv`, reps=10) so the
  table is a single consistent comparison; the powersave draft is retained for
  provenance only. The re-run confirmed the baseline was understated by ~1.1–1.5× under
  powersave but changed no conclusion — glibc stays ~an order of magnitude above every
  shippable engine, and the crossover/ordering were identical under both clocks.
- **Profiling evidence (Callgrind).** Instruction-attribution study
  (`prototypes/.../profile_*`) that *disproved* the original "allocation is the
  bottleneck" account: glibc cost is automaton eval (~73%) + per-call search setup
  (~26%), allocation <1%. The paper reports the corrected, measured account; the
  override is recorded in the AI-use appendix.
- **Bibliography verified (2026-06-18).** Every entry checked against DBLP / arXiv /
  publisher: BLARE (PACMMOD 2023), HybridSA (OOPSLA 2024), RE\# (POPL 2025), PCRE-JIT
  (Herczeg, CGO 2014). Only BLARE is cited; the rest are verified leads kept uncited.
- **Drafting complete.** All sections written; AI-use methodology appendix +
  acknowledgments disclosure; affiliation/CCS metadata; prototype-vs-in-gem
  reconciliation; plain-language opener + a glossary of engines/terms.
- **arXiv-ready (2026-06-19).** Two external review passes addressed: exact
  per-thread memory bound (~0.86 MB, was "well under a megabyte"); boundary-wrap
  semantics clarified and rendered as a clean \texttt{} block; readability pass on
  the densest sentences. Author read the full draft and signed off on the AI-use
  appendix. `make dist` emits the upload file `frisanco-fastest-engine-2026.pdf`.
  Open: arXiv post, then Wiley-template reformat + S:P&E submission (TODO.md "Paper").

---

## Promotion (done)
RubyGems push (0.5.0, 2026-05-08); GitHub repo topics; Shields.io badges; YARD docs;
README thread-safety note; `examples/` (8 runnable scripts + index README,
repo-only).
