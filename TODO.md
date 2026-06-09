# TODO

## Multi-pattern matcher research (branch `feat/matcher-prototype-v1`)

### 1. Decide which prototype to implement in the gem

Six prototypes benchmarked. Decision required before any production work starts.

Current best result: **v5 (AC + Onigmo + BM) — 1.52× over pure-Ruby, 15.2× over today's C**.

Open question: would **v7 (AC + BM + PCRE2 JIT)** meaningfully improve on v5 for Group B
always-candidates (pure-digit patterns: SSN, PESEL, credit card, IPv4)?
Published benchmarks suggest 2–5× faster confirmation for those patterns.

**~~Decision: ship v7 (AC + BM + PCRE2 JIT).~~ SUPERSEDED — see §1d.** v7 cleared the
≥2× bar (2.79× over pure-Ruby) but requires `libpcre2-dev` with JIT, violating the
gem's zero-runtime-dependency rule (CLAUDE.md). The v8→v19 arc then built a
**zero-dependency** pure-C engine that beats Onigmo: **v19 is 2.3× over pure-Ruby,
~11× over today's C, no external link**, and byte-for-byte correct vs Ruby `gsub`.
v19 is the engine to port. Porting plan and open design gaps are tracked in §1d.

**Historical checklist (v7 — kept for the record):**
- [x] Build and benchmark prototype v7 (AC + BM + PCRE2 JIT) — 2.79× over pure-Ruby. ✅
- [x] Go/no-go: v7 ≥ 2× → cleared the bar. ✅
- [x] ~~Portability trade-off for PCRE2~~ → resolved by abandoning the dependency (v19).
- [ ] ~~Wire v7 into the gem~~ → superseded by §1d (port v19 instead).

### 1b. Bound greedy tails in built-in patterns (perf + worst-case)

The `jwt` pattern is `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`.
The final `+` (and the `{10,}`) are **unbounded**, which:
- makes `ast_max_len` report unbounded → disables the v12 literal back-up skip and
  the bounded-window optimizations for this pattern;
- is a theoretical O(N²) trigger (a crafted `eyJ…` + a megabyte of base64url chars
  forces the greedy tail to scan far). Measured engines are O(N) on real payloads,
  but the worst case is real.

Key insight: **redaction does not need to match the whole token to neutralize it.**
A JWT is unusable once its front is gone, so matching `eyJ` + a bounded prefix and
redacting that is sufficient for safety. So:

- [ ] Evaluate bounding the greedy tails: `[A-Za-z0-9_-]+` → `[A-Za-z0-9_-]{N,M}`
      (pick N large enough to neutralize, e.g. ≥ the smallest real signature) and
      `{10,}` → `{10,M}`. Restores a bounded `max_len`, kills the O(N²) worst case,
      enables more skip optimizations.
- [ ] Decide the policy: redaction-for-safety (bounded tail OK, leaves the token's
      tail visible but cryptographically dead) vs redaction-for-privacy (must not
      leak any of it → keep unbounded). May differ per tag.
- [ ] Re-examine whether the `jwt` regex itself is correct (three base64url
      segments, `eyJ` anchor on each). Real JWT signature lengths are fixed per alg
      (HS256≈43, ES256≈86, RS256≈342) — could anchor lengths instead of `+`.
- [ ] Apply the same bounded-tail review to other patterns with trailing `+`/`{n,}`
      (audit `ext/data_redactor/patterns.c`). NOTE: this is a **gem pattern change**
      governed by CLAUDE.md pattern tiers + false-positive rules, separate from the
      matcher-engine prototypes. Any change needs positive + negative spec coverage.

### 1c. Fix v18.1 EOL-at-buffer-end bug (DFA path drops `$`-terminated matches) ✅ FIXED (v19.1)

**Resolution:** implemented the first option below in `matcher19.c`. `scan_one` now
NFA-falls-back for start positions in the final ~`max_len` bytes whenever the pattern
carries a `$` anchor (`has_eol`), symmetric to the existing `boundary_wrapped && pos==0`
BOL fallback. Added per-engine `has_eol` + `max_len` fields and a `prog_has_eol` helper.
`verify19.rb` is now byte-for-byte equal to v15 on every payload (KNOWN escape hatch
removed → any diff is a hard failure). Benchmarks unchanged (2.33×/2.30×/1.75×/1.82×):
the fallback touches only the buffer-tail bytes, never the hot path.

**Bug:** in the lazy-DFA path (v18/v18.1/v19), `addthread_dfa` computes
position-independent closures by calling `addthread(pos=1)` on a dummy empty string.
That correctly excludes the `^` branch — but it *also* means `OP_EOL` never fires.
Consequently a boundary-wrapped match whose trailing boundary is `$` (the match ends
**exactly at end-of-buffer**) is never accepted by the DFA and is silently dropped.

**Why it hid:** `verify18_1.rb`'s corpus always appends `\n`/text after every hit, so
no boundary-wrapped match ever lands at the very end of the buffer. Adding
buffer-edge digit payloads to `verify19.rb` surfaced it (see §research_log v19).

**Impact:** every boundary-wrapped pattern at end-of-buffer. v19's merged digit pass
*does* honor `$`, so it already fixes the **9 pure-`[0-9]{n}` patterns**. Still open:
the ~15 other boundary-wrapped patterns that go through `scan_one` — czech_rodne_cislo,
romanian_cnp, us_ssn / canadian_sin / korean_rrn (dashed), etc. (IBANs are **not**
affected: they are fixed-length with a distinctive prefix, carry no `$` anchor, and
now run through the v19 IBAN union pass — `iban-eob` in `verify19.rb` confirms a
buffer-end IBAN matches.)

- [x] In `scan_one`, fall back to the position-sensitive NFA inner loop for start
      positions within `max_len` of the buffer end (symmetric to the existing
      `boundary_wrapped && pos==0` BOL fallback). Stored per-engine `max_len` +
      `has_eol`. Cheap: only the final ~max_len bytes use the NFA.
- [ ] ~~Alternative: EOL-conditional MATCH in the DFA~~ — not needed; the fallback
      above is simpler and has no measurable cost.
- [x] Buffer-edge cases (digit runs, dashed IDs, IBANs ending at `len`, after `\n`)
      are in `verify19.rb` (digit-eos9/digit-runs/iban-eob etc.).
- [x] `verify19.rb` shows zero diffs vs v15 (escape hatch removed).

### 1d. Port the v19 engine into the gem (replace the glibc `regexec` confirmation loop)

**Goal.** Replace the gem's current per-pattern POSIX `regexec` engine in
`ext/data_redactor/` with the v19 pipeline (NFA → bytecode → per-pattern lazy DFA +
the two selective merges). v19 is **zero-dependency, 2.3× over pure-Ruby, ~11× over
today's C, byte-for-byte equal to Ruby `gsub`** (`prototypes/multi_pattern_matcher/`,
`docs/research_log.md` §v19). This is the production payoff of the whole research arc.

**Do this as its own branch (`feat/v19-engine`), not bundled with the research merge.**
Start with a design spike on the four gaps below — they, not the matching algorithm,
are where prototype→production ports fail. The 244-example rspec suite is the
correctness gate the ported engine must pass unchanged.

**Gap 1 — pattern source-of-truth + the existing public `add_pattern` API.** The
prototype matches a fixed generated `MM88_PATTERNS` table. The gem already ships
(0.3.0, §"User-supplied custom patterns") a public `DataRedactor.add_pattern` /
`remove_pattern` / `clear_custom_patterns!` API backed by per-pattern `regcomp`, with
patterns stored in a process-local dynamic array and executed after built-ins in
registration order.
- [x] Built-in patterns live in `ext/data_redactor/patterns.{h,c}` (CLAUDE.md tiers);
      v19's engine table is built from them at `mm_init()`.
- [x] **Customs do NOT go through v19** (hybrid split — see Gap 2). `redact`/`scan` run
      the v19 engine over built-ins, then the existing glibc `regexec` loop over customs
      on the (already built-in-redacted) buffer — preserving registration order and the
      sequential built-ins→customs semantics exactly. So the engine has no dynamic
      add/remove of custom slots to keep in lockstep; `mm_add`/`mm_remove`/
      `mm_clear_custom` exist but are unused by the gem (kept for a possible future move
      of customs onto v19).

**Gap 2 — v19's parser vs the gem's POSIX-ERE subset contract + multibyte UTF-8.**
`add_pattern` today compile-tests with `regcomp` and rejects anything outside POSIX
ERE. v19 has its own **byte-oriented** parser/matcher (`parse_regex`), and that byte
orientation is the deciding factor:
- **RESOLVED by the hybrid split (decision 2026-06-09).** The v19 engine handles ONLY
  the 88 built-in patterns (all pure ASCII — verified). **Custom patterns keep running
  through the existing glibc `regexec` path** (`replace_all_matches`), unchanged. So
  the v19 parser never has to accept arbitrary user regex, and the POSIX-subset
  contract / `regerror` messages are exactly as today (still `regcomp` at registration).
- **Why the split is necessary, not just convenient — multibyte UTF-8 in character
  classes.** `DataRedactor.name_pattern` emits classes like `[oOòóôõöø…]` whose members
  are multibyte UTF-8 sequences. glibc's locale-aware `regexec` matches `José`/`Muñoz`
  against these; the v19 byte-level engine parses each `[...]` as a 256-bit set and a
  multibyte char as separate bytes, so `[…é…]` (one class atom) cannot match the 2-byte
  `é` — a real **false negative on PII**. The `redact` diacritics spec (`José Muñoz`)
  caught this when the engine went live. Routing customs through glibc preserves today's
  match exactly.
- [ ] (Deferred, only if customs ever move onto v19) Teach the parser to treat a
      multibyte UTF-8 sequence inside `[...]` as a single multi-byte alternative, and
      add UTF-8 class-matching tests. Larger change; not needed while customs stay on
      glibc. Tracked here so the limitation is explicit.

**Gap 3 — thread-safety / re-entrancy (correctness, not perf).** The prototype uses
file-scope mutable globals: `g_engines`, `g_dfa`, and crucially the per-scan cursors
`g_digit_last_end[]` / `g_iban_last_end[]` and `g_gen[]`. Under threaded Ruby (Puma,
Sidekiq) concurrent `redact` calls would race on these:
- [ ] Separate **immutable, shared** state (compiled programs, DFA transition tables —
      safe to share once built) from **per-scan mutable** state (match cursors,
      generation stamps, clist/nlist scratch) which must be stack-local or per-call.
- [ ] Decide the model: per-call scratch (allocate/reuse on the C stack or a passed-in
      context struct) vs a GVL assumption. Do NOT assume the GVL serializes redaction —
      `redact` may release it for large inputs. Document the chosen guarantee.
- [ ] Add a concurrency stress test (N threads redacting distinct inputs, compare to
      single-threaded results) — mirrors prototype `stress-600` but parallel.

**Gap 4 — selective merges over a dynamic set.** The digit group and IBAN union pass
are detected by `parse_pure_digit` / `parse_iban_prefix` over the built-in set.
- [x] **Moot under the hybrid split.** Custom patterns run on glibc, not v19, so they
      never join the digit/IBAN merges by construction. The merges operate only over the
      fixed built-in set, detected once at `mm_init()`. If customs ever move onto v19,
      revisit (a user `[0-9]{lo,hi}` could then join the digit pass).

**Gap 5 — cross-pattern overlap: mm_scan is single-pass, the gem is sequential-rewrite.**
This is the subtle correctness gap, NOT covered by the prototype's `verify19.rb`.
`verify19.rb` proved v19 == v15, but **v15 is also a single-sweep multi-pattern NFA**,
not the gem's engine. The gem runs patterns *sequentially*, each `gsub`-ing the buffer
the previous pattern already rewrote — so a lower-index pattern's `[REDACTED]` can
*block* a higher-index pattern from matching bytes it otherwise would. The canonical
case is the spec at `spec/data_redactor_spec.rb:1299` (AKIA): `aws_access_key_id`
(idx 14) redacts the leading 20 chars; `aws_secret_access_key` (idx 15, `{40}`) then
sees only 20 chars after `[REDACTED]` and cannot match — so 20 chars are left
unredacted. A naive emit-all-events over the *original* buffer would instead match the
full 40 and redact everything, flipping that passing spec.
- [x] **Decision (2026-06-09): index-order greedy claim.** Resolve `mm_scan`'s raw
      events with `mm_resolve`: iterate events in `(pattern_id, start)` order; keep an
      event iff its CORE span does not overlap an already-kept span; else drop it. This
      reproduces "earlier-index pattern wins any region it can match" — byte-identical
      to today. Verified character-independent (suffix A/B/Z/9/mixed/lower/`/` all give
      the same 20-char redaction). ~30-line post-pass; keeps the full event list intact
      so the deferred longest-match-wins policy is a drop-in swap of the resolve rule.
- [x] **Differential-tested (2026-06-09).** A Fiddle harness drove `mm_scan`+`mm_resolve`
      vs `DataRedactor.redact` over 4000+ randomized adjacency-heavy inputs plus fixed
      overlap shapes. Found one — and only one — divergence class, below.
- [ ] **Accepted divergence — rewrite-created/destroyed boundary (~2% of adjacency-heavy
      random inputs; all 84/4000 divergences were this class).** When two sensitive
      tokens abut with **no separator between them**, today's sequential rewrite replaces
      the lower-index token with `[REDACTED]`, and the `[`/`]` of that placeholder becomes
      the boundary an adjacent **boundary-wrapped** pattern needs — so it matches on the
      *rewritten* buffer. A single pass over the *original* buffer can never see that
      created boundary, so the second token is missed (or, symmetrically, a greedy
      lower-index match destroys a boundary and leaves a mangled half-token, e.g.
      `192.168.1.1123-45-6789` → today `[REDACTED]3-45-6789`). Examples:
      `123-45-6789192.168.1.1` (today redacts both; engine redacts only ipv4),
      `ghp_…85121612345` (the 11-digit ID after a key).
      **Decision: accept, do NOT model the rewrite.** Rationale: (1) it only fires on
      directly-abutting secrets with no separator — rare in real text, which is
      whitespace/punctuation-delimited; (2) today's output in these cases is itself a
      glibc-rewrite artifact (mangled partial tokens), not behaviour worth preserving;
      (3) the decided 1.0 longest-match-wins policy redacts the whole region and fixes
      these properly. No existing spec asserts a no-separator back-to-back redaction, so
      the suite stays green. This is the single documented behavioural difference of the
      ported engine vs the original — see the divergence ledger (§ "Where the ported
      engine differs"). If a future need arises, a bounded re-scan around each `[REDACTED]`
      edge would recover byte-identical behaviour without a full multi-pass.

**Ship hygiene (once the gaps are closed):**
- [x] 256-example rspec suite green against the new engine (the correctness gate). ✅
- [ ] `extconf.rb` builds with no new dependency; verify on glibc + musl/Alpine.
- [x] SemVer: engine swap with no public API change → **minor** bump; `0.9.0` → `0.10.0`. ✅
- [x] Bench the gem end-to-end: 1 MB log: **0.87 i/s → 7.27 i/s** (~8.4× throughput
      gain; from 4× slower than pure Ruby to 2.25× faster). Small strings: 3–4.6×
      slower → 1.7–2.3× faster. The 2.3× prototype win survives the Ruby↔C boundary. ✅

**Phase 1 — ported but NOT done yet (tracked for future work):**
- [ ] **Longest-match-wins overlap policy** — the decided 1.0 policy (keep the longest
      CORE span at each position; pattern-id breaks ties). Currently deferred; `mm_resolve`
      keeps the index-order greedy claim to reproduce today's sequential semantics. Changing
      the resolver is ~40 lines + spec work to unmark the two `pending` 1.0 specs. The event
      list is preserved intact so this is a drop-in swap.
- [ ] **Full per-call thread re-entrancy** — `mm_scan` mutates per-engine fields
      (`iban_last_end`, `digit_last_end`, DFA scratch). Phase 1 is safe only because MRI's
      GVL serialises C extension calls (no `rb_thread_call_without_gvl` is ever used).
      Full re-entrancy requires moving the mutable scan scratch into a per-call context
      struct (alloca/stack or caller-supplied). Needed before releasing the GVL for large
      inputs or before supporting Ractors.
- [ ] **Custom patterns in selective merges** — pure-digit or IBAN-prefix custom patterns
      won't join the group passes; they're handled per-pattern by glibc. Acceptable for
      Phase 1 (customs are rare hot paths); revisit if perf matters.
- [ ] **Streaming `mm_scan_chunk`** — scan across caller-managed chunks for large inputs
      without buffering the full string in C. Not needed while callers buffer Ruby strings.
- [ ] **Hopcroft minimisation** — lazy-DFA states are not minimised; minimisation would
      reduce transition table size and improve cache behaviour on large pattern sets.
- [ ] **Fuzz / ASan CI harness** — see `docs/standalone_matcher_design.md` risk table.
      The `OP_EOL` OOB read (fixed) was found by ASan; a CI fuzz job would catch regressions.
- [ ] **musl/Alpine build verification** — `memmem` availability and `_GNU_SOURCE` behaviour
      on musl libc. Current guard: `#ifndef _GNU_SOURCE / #define _GNU_SOURCE` at top of
      `matcher.c`. Needs a CI matrix job.

**Where the ported engine differs from the original gem (divergence ledger):**

1. **Single-pass original-frame emission** — `mm_scan` scans the original input once and
   emits CORE-frame `(pattern_id, start, length)` directly. The old engine ran N `regexec`
   passes, each on the buffer the previous already rewrote, and used `repl_log` /
   `WORKING_TO_ORIG` to map coordinates back. The new approach is simpler and faster;
   the only observable difference is the rewrite-boundary class below.

2. **Rewrite-created / rewrite-destroyed boundary** (Gap 5, accepted) — when two secrets
   directly abut with no separator, the `[REDACTED]` placeholder from the lower-index
   match can create (or destroy) the word boundary a higher-index boundary-wrapped pattern
   needs. A single-pass scan over the original buffer cannot see the rewritten boundary.
   ~2% of adjacency-heavy synthetic inputs; irrelevant in real text (always separator-
   delimited). Pinned by DIVERGENCE specs; fixed by the future longest-match-wins resolver.

3. **Custom patterns bypass the selective merges** — customs always go through glibc
   `replace_all_matches`, even if their regex is a pure digit run or an IBAN prefix.
   Built-in digit/IBAN patterns continue to use the group passes. Acceptable because
   customs are a small minority of calls.

4. **Overlap policy is still index-order greedy** — see item 1 of "Phase 1 not done yet".
   The 1.0 longest-match-wins policy is deferred; for now the resolver reproduces today's
   sequential-rewrite behaviour exactly.

### 1b. Legal check before shipping BM implementation

Before porting the Boyer-Moore inner-loop implementation from `bench_bm_inner.c`
into the gem's `redact.c` / `scan.c`, verify that the specific BM bad-character
algorithm we wrote is not a copy (or near-copy) of Onigmo's or PCRE2 JIT's source.

- [x] Compare `bm_find` in `bench_bm_inner.c` against Onigmo's `bm_search` in
      `regcomp.c` / `regexec.c` (BSD-2 licensed — compatible, but we should not
      copy code verbatim without attribution).
- [x] Compare against PCRE2's study/JIT code to confirm no overlap.
- [x] Standard bad-character BM (Horspool variant) is public domain / textbook
      algorithm — confirm our implementation is derived from the algorithm
      description, not from either project's source code.
- [x] **Conclusion (2026-06-02):** no copying. Our `build_bm_tables` + `bm_find`
      is the Horspool (1980) bad-character-only variant — ~20 lines, identical to
      any textbook implementation. Onigmo's `bm_search` uses the same algorithm
      because it is the algorithm; structural similarity is inevitable, not
      indicative of copying. No attribution or rewrite needed.

### 2. Write and publish the paper

Research log at `docs/research_log.md` is the source of truth. Contains all prototype data,
benchmark methodology, root-cause analysis, related work, and open questions.

**Recommended path:**
1. [ ] Complete benchmark rigor: document hardware, OS, Ruby/glibc versions; add stddev across runs;
       add a microbenchmark isolating AC filter overhead from confirmation overhead.
2. [ ] Add profiling evidence (perf/callgrind): show where cycles go in v2 (glibc) vs v3 (Onigmo)
       to support the "BM literal pre-filter is the decisive factor" claim.
3. [ ] Post preprint to **arXiv** (categories: `cs.PL` + `cs.DS`) — establishes priority, no peer review.
4. [ ] Submit to **Software: Practice and Experience** (Wiley, Q2 journal) as the primary venue.
       Scope: "practical experience with new and established software" — direct fit.
       Timeline: ~6–12 months to decision. No conference travel required.
5. [ ] If SPE reviewers push back on novelty: retarget **USENIX ATC** (experience report track).

**Paper shape:** systems/experience report, 12–15 pages.
Core contribution: two-stage AC + fast-engine pipeline is near-optimal for mixed-prefix DLP pattern
sets; BM pre-filter is a worthwhile third stage; always-candidates are the binding constraint.
Key related work to cite: Hyperscan (NSDI 2019), BLARE (SIGMOD 2023), HybridSA (OOPSLA 2024).

**Estimated effort from current state:** 3–4 months part-time (10–15 h/week).

---

## References
- https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- https://github.com/advanced-security/secret-scanning-custom-patterns
- https://github.com/gitleaks/gitleaks/tree/master

## Additional patterns to add (from former plan.md)

Distinctive-prefix API keys with low false-positive risk, grouped under `:credentials`:

- [x] Anthropic API Key (`sk-ant-api03-...`) — added in 0.6.1
- [x] OpenAI API Key (`sk-proj-...`) — added in 0.6.1
- [x] GitLab PAT (`glpat-...`) — added in 0.6.1
- [x] DigitalOcean PAT (`dop_v1_...`) — added in 0.6.1
- [x] Databricks API Token (`dapi...`) — added in 0.6.1
- [x] Sentry DSN — added in 0.6.1 (matches both modern and legacy `KEY:SECRET@` form)
- Heroku API Key — **skipped**: format is a plain UUID v4, already covered by the `uuid_v4` pattern
- Okta API Token — **skipped**: 42-char alphanum with no distinctive prefix → high FP risk
- Azure SQL hostname — **skipped**: hostname, not a secret
- DataDog API Key — **deferred**: 32 hex chars with no prefix; needs a context-aware prefix (e.g. `dd[-_]?api[-_]?key=`) to avoid false positives
- PagerDuty API Key — **skipped**: REST tokens are 20-char alphanum without a stable distinctive prefix; v2 routing keys are 32 hex chars → both FP-prone
- HashiCorp — ✅ **DONE**: Vault service tokens (`hvs.`), Vault batch tokens (`hvb.`), Terraform Cloud API tokens (`atlasv1`). `hcp.` prefix not found in public pattern databases — skipped.

### Assignment-style secret patterns (key-name anchored) — WANTED

Patterns that redact a secret by the **name of the field it is assigned to**, not by
the secret's own format. Requested 2026-06-09. The secret value itself has no
distinctive shape, so the key name is the only anchor:

- [ ] `%PWD%`, `%PASSWORD%` (env-var-template style)
- [ ] `PASSWORD="..."` / `PASSWORD=...` (assignment / dotenv style)
- [ ] generalize to common secret key names: `password`, `passwd`, `pwd`, `secret`,
      `token`, `api_key`, `apikey`, `access_key`, `client_secret`, etc., across the
      common separators (`=`, `:`, `=>`) and quoting styles.

**Open design questions (resolve before implementing):**
- Redact only the **value**, keep the key (`PASSWORD=[REDACTED]`) — almost certainly
  the right call, so logs stay greppable.
- Case-insensitivity: POSIX ERE has no `/i`. Need `[Pp][Aa]...` char-class expansion
  or a parser-level fold — decide which.
- Value terminator: where does the value end? Quoted (`"..."`/`'...'`) is easy;
  unquoted runs to whitespace/newline/`;`/`,`. Define the value grammar.
- FP risk: `password` appears in prose ("reset your password"). Anchoring on the
  separator (`password\s*[=:]`) mitigates this — require the assignment, not the word.
- These are a new tier (value-after-key-name); confirm where they sit in the
  specific→generic ordering and whether they need `boundary_wrapped`.

## Roadmap to a usable gem

### 1. Tagged categories (highest impact) ✅ DONE in 0.2.0
Shipped: 8 tags (`:credentials`, `:financial`, `:tax_id`, `:national_id`, `:contact`, `:network`, `:travel`, `:other`), `redact(text, only:/except:)`, `DataRedactor.tags`, `DataRedactor::TAGS`, `UnknownTagError`. C-level filtering via bitmask in `pattern_tags[]`.

### 2. User-supplied custom patterns ✅ DONE in 0.3.0

Every team has internal IDs (employee numbers, customer codes, internal URLs) the gem can't ship.

**Chosen approach (strict + reserved `:custom` tag):**

```ruby
DataRedactor.add_pattern(name: "employee_id", regex: /EMP-[0-9]{6}/, tag: :custom, boundary: false)
DataRedactor.remove_pattern("employee_id")
DataRedactor.custom_patterns         # => [{name:, source:, tag:, boundary:}, ...]
DataRedactor.clear_custom_patterns!  # mostly for test suites

DataRedactor.redact(text, only: [:custom])              # only user patterns
DataRedactor.redact(text, only: [:custom, :credentials]) # mix
```

Rules:
- `tag:` defaults to `:custom` (new reserved tag bit). May also be any built-in tag. Anything else raises `UnknownTagError`.
- `regex:` accepts a `String` (POSIX ERE) or a `Regexp`, but only the subset POSIX `regex.h` understands — no `\d`, `\s`, `\w`, `\b`, `(?:...)`, lookaround, non-greedy, named groups. Reject at registration with a clear `InvalidPatternError`.
- Compile-test with `regcomp` at `add_pattern` time; raise `InvalidPatternError` carrying the `regerror` message. Fail fast at registration, never at redaction.
- Patterns with capture groups are rejected when `boundary: true` (same constraint that exists for built-ins, see [data_redactor.c:310-313](ext/data_redactor/data_redactor.c#L310-L313)).
- Storage: process-local dynamic array (matches how built-ins work — lives until the Ruby VM exits).
- Execution order: after all built-in patterns, in registration order. Built-ins are ordered specific→generic for a reason; appending custom keeps that invariant.
- Name collisions: replace the existing pattern (and free its compiled `regex_t`).

**Future improvements (deferred, document but do not implement now):**
- Translate Ruby-only regex syntax (`\d`→`[0-9]`, `\s`→`[[:space:]]`, `\w`→`[0-9A-Za-z_]`, etc.) so users can pass familiar patterns. Reject lookaround/non-greedy/named groups even after translation.
- Free-form user tag symbols (e.g. `tag: :anything_you_want`) with dynamic bit allocation, up to 24 user tags (8 reserved built-ins + `:custom` + room to grow within a 32-bit mask). Requires a tag registry. Only ship if users ask.
- Persistence: load patterns from a YAML/JSON config file at boot.
- Per-pattern placeholder override (ties into roadmap item #3).

### 3. Configurable placeholder ✅ DONE in 0.4.0
`placeholder: "***"` (plain), `placeholder: :tagged` (`[REDACTED:CONTACT]`), `placeholder: :hash` (`[CONTACT_a3f9]` deterministic djb2).

**Future: length-aware placeholder** — embed the byte-length of the redacted value so readers can gauge what was there without seeing it. Proposed modes:

- `placeholder: :length` → `[REDACTED:16]` (just the length)
- `placeholder: :tagged_length` → `[REDACTED:CONTACT:16]` (tag + length)

Implementation note: `write_placeholder` already receives `match` and `match_len`; adding these two modes is a small C change (one `sprintf` each) plus the corresponding Ruby symbol dispatch in `resolve_placeholder`. The `:hash` mode could also optionally append the length (`[CONTACT_a3f9:16]`) if that turns out to be useful for log pipelines.

### 4. Report / dry-run mode ✅ DONE in 0.5.0
`DataRedactor.scan(text, only:, except:)` returns `{ redacted:, matches: [{tag:, name:, value:, start:, length:}, ...] }`. Positions are byte offsets into the original string.

### 5. Hash / JSON / object traversal ✅ DONE in 0.8.0
Pure-Ruby walker on top of the C `redact`:

```ruby
DataRedactor.redact_deep(params_hash)
DataRedactor.redact_json(json_string)
```

### 6. Allowlist / ignore list ✅ DONE in 0.6.0 (pattern-level)
Shipped a *pattern-level* allow/deny: `only:` and `except:` accept a mix of Symbols (tags) and Strings (pattern names). Combine them for precision: `only: :contact, except: ["email"]` redacts every contact pattern except email. `except:` wins when the two overlap. Implementation: Ruby builds a per-pattern enable bit array; C iterates by index and skips zeros — single pass, no second scan.

**Future: value-level allowlist** — escape hatch for known-safe substrings the broad patterns flag (40-char base64 inside a known image blob, `test@example.com` in fixtures, etc.). Original sketch:

```ruby
DataRedactor.redact(text, allow: [/example\.com/, "test@foo.com"])
```

Different from the pattern-level filter we have now — this would suppress individual *matches* whose value is in the allowlist, regardless of which pattern hit them. Implementable as a per-match check after `regexec` succeeds (cheap if the allowlist is small) or as a post-filter on `_scan`. Defer until someone asks — `except: ["email"]` already covers the most common case (turn off the noisy pattern entirely).

### 7. Checksum validation
Massive false-positive killer. Apply only when the structural regex matches:
- Luhn for credit cards
- mod-97 for IBANs
- Italian Codice Fiscale check character
- Spanish DNI letter
- Brazilian CPF/CNPJ check digits
- PESEL, CNP, etc.

Probably an opt-in flag per call (`strict: true`) since validation costs CPU.

### 8. Streaming API
Defer until 1+2 land. Chunk boundaries can split a match — needs an overlap/lookback window equal to the longest pattern.

```ruby
DataRedactor.redact_stream(input_io, output_io)
```

### 9. Rails / Rack integration ✅ DONE in 0.7.0
Shipped under `lib/data_redactor/integrations/` as soft-required adapters (zero runtime dependencies added):
- ✅ `DataRedactor::Integrations::Logger` — `Logger::Formatter` wrapper, preserves exception cause chains
- ✅ `DataRedactor::Integrations::Rails.filter` — `filter_parameters` adapter
- ✅ `DataRedactor::Integrations::Rack` — middleware with `scrub: [:body, :headers]` opt-in surfaces

Future work for this area: a `Rack` `:env_logs` surface that scrubs `PATH_INFO` / `QUERY_STRING` for downstream access loggers (deferred — needs to wrap the upstream logger rather than mutate env, which has been blocking the design).

### 10. Claude / OpenAI API integration (planned for 0.8.0)

Helpers that sanitize LLM payloads before they leave the process and optionally scrub responses before they're logged or stored.

**Proposed API:**

```ruby
require "data_redactor/integrations/claude"
# or
require "data_redactor/integrations/openai"

# Redact a messages array in place before sending to Claude / OpenAI
safe_messages = DataRedactor::Integrations::Claude.redact_messages(messages)
safe_messages = DataRedactor::Integrations::OpenAI.redact_messages(messages)

# Redact a response (assistant message / completion) before logging
safe_response = DataRedactor::Integrations::Claude.redact_response(response)
safe_response = DataRedactor::Integrations::OpenAI.redact_response(response)
```

**Variants to cover:**
- `messages` array: walk each `{ role:, content: }` entry; `content` may be a String or an array of content blocks (text/image). Redact all text parts.
- System prompt: include in the walk if present at the top level (Claude) or as a `{"role": "system"}` message (OpenAI).
- Response: Claude returns a `content` array of blocks; OpenAI returns `choices[].message.content`. Extract, redact, return a patched copy.
- All helpers forward `only:`, `except:`, `placeholder:` to `DataRedactor.redact`.
- No runtime dependency on the `anthropic` or `openai` gems — operate on plain Ruby Hashes/Arrays so they work with any HTTP client or SDK version.

**Open questions:**
- Redact in place (mutate) or return a copy? Prefer a copy — callers shouldn't have to worry about their original payload being changed.
- Should the response helper return the full response object (patched) or just the text? Full object is more composable.

### 11. Distribution / quality of life (formerly #10)
- ~~Publish to RubyGems~~ ✅ DONE — 0.5.0 published 2026-05-08
- ~~CI matrix: Ruby 2.7, 3.0, 3.1, 3.2, 3.3 on Linux + macOS~~ ✅ DONE — `.github/workflows/ci.yml` tests Ruby 3.1/3.2/3.3, builds gem, publishes via OIDC on release
- ~~RubyGems OIDC trusted publisher setup~~ ✅ DONE
- ~~YARD inline documentation~~ ✅ DONE — `@param`/`@return`/`@raise` for all public methods; `bundle exec yard doc` is 100% documented.
- ~~GitHub Pages deploy job for YARD docs~~ ✅ DONE — `docs` job in `ci.yml` builds and deploys on every push to `main`.
- ~~Thread-safety note in README~~ ✅ DONE
- ~~Shields.io badges in README~~ ✅ DONE — gem version, CI build, license
- ~~Precompiled binaries via `rake-compiler-dock`~~ ✅ DONE in 0.7.2 — 6 native gems (Linux glibc/musl x86_64+aarch64, macOS Intel+ARM) for Ruby 3.1–3.4. Atomic release pipeline gates source + native together.
- ~~CHANGELOG.md + semver commitment~~ ✅ DONE in 0.1.0
- Demo / example script (`examples/rails_logger.rb` or similar) showing real-world usage
- ~~Bump CI/release workflow actions to Node 24-compatible versions before 2026-06-02.~~ ✅ DONE — `checkout@v6.0.2`, `upload-artifact@v7.0.1`, `download-artifact@v8.0.1`, `upload-pages-artifact@v5.0.0`, `deploy-pages@v5.0.0`.
- ~~Drop `release: published` trigger from `ci.yml`.~~ ✅ DONE — removed; CI now runs only on push to main and PRs.

### 12. Name-pattern helper ✅ DONE in 0.9.0

`DataRedactor.name_pattern(first, last, middle:)` in `lib/data_redactor/name_pattern.rb` — pure Ruby, returns a POSIX ERE String for `add_pattern`.

Design decisions made:
- **Boundary** — the wrapper `(^|[^A-Za-z])(...)([^A-Za-z]|$)` is baked into the returned string, so the caller registers with the default `boundary: false`. `Mario` matches as a word but not inside `Mariolino`.
- **Separator** — `[ ,-]*` (optional) between name parts, so `MR` / `M.R.` / `Rossi,Mario` all collapse correctly. Spaces and hyphens are interchangeable; a hyphenated part (`Anne-Marie`) also matches `Anne Marie`, `AnneMarie`, and each half alone. Multi-word parts (`Van der Berg`) tolerate any separator between words.
- **Middle** — explicit `middle:` kwarg; when given, generates both the no-middle and with-middle forms.
- **Diacritics** — `DIACRITIC_FOLD` table maps each ASCII letter to its accented variants; matching is bidirectional (`Jose` matches `José` and vice versa).
- **Output** — `String` (POSIX ERE), matching what `add_pattern` accepts.

## C extension refactor ✅ DONE

`ext/data_redactor/data_redactor.c` (1047 lines) split into:

- `tags.h` — `TAG_*` bit constants
- `patterns.{h,c}` — `pattern_strings[]`, `boundary_wrapped[]`, `pattern_tags[]`, `pattern_names[]`, `NUM_PATTERNS`, `compiled_patterns[]`
- `placeholder.{h,c}` — `placeholder_t`, `PLACEHOLDER_MODE_*`, `write_placeholder`, `max_placeholder_len`, `djb2`, `tag_name_for_bit`
- `custom_patterns.{h,c}` — `custom_pattern_t`, the dynamic registry, and the four Ruby-facing functions (`rb_add_pattern`, `rb_remove_pattern`, `rb_clear_custom_patterns`, `rb_custom_patterns`)
- `redact.{h,c}` — `wrap_boundary`, `replace_all_matches`, `rb_data_redactor_redact`
- `scan.{h,c}` — `rb_data_redactor_scan` and the replacement-log macros
- `data_redactor.c` — 60-line entry point: includes + `Init_data_redactor` only

`extconf.rb` now uses `$srcs = Dir.glob("#{__dir__}/*.c")` so adding a new module requires no Makefile changes. All 155 specs still pass — pure structural change.

## Performance: optimize and minimize allocations

### ✅ DONE 2026-05-23: B, G, scan-offset fixes shipped on `fix/redact-performance`

**Commits (newest first):**
- `24bade5` G — chunk inputs > 64KB in Ruby wrapper, bounds glibc per-call O(N).
- `8bf28a7` Deep scan offset fix — repl_log now in original-input coords,
  sorted-walk translation. Fixed a pre-existing cross-pattern bug that the
  G testing surfaced (intra-pass only entries were limited but cross-frame
  comparison was still wrong).
- `de4641e` Partial scan fix — intra-pattern shift exclusion (kept; superseded
  by 8bf28a7 but doesn't conflict).
- `c2f773c` B — `strstr` literal pre-filter, 54/88 patterns get one.
- `7a70f0a` Buffer-sizing fix in `replace_all_matches`.

**Measured impact (`benchmark/vs_pure_ruby.rb`):**

| Size  | Pre-fix       | After B      | After B+G    |
|-------|---------------|--------------|--------------|
| 168B  | 4.2× slower   | 3.0× slower  | 3.4× slower  |
| 580B  | 6.3× slower   | 4.7× slower  | 5.0× slower  |
| 1.3KB | 5.4× slower   | 3.9× slower  | 4.1× slower  |
| 17KB  | 5.7× slower   | 4.2× slower  | 4.4× slower  |
| 1MB   | 6.3× slower   | 4.7× slower  | 4.25× slower |
| 10MB  | ~56s (cliff)  | ~32s         | **~15s**     |

(Small-string post-G numbers within noise of post-B — chunking doesn't kick
in below CHUNK_SIZE=64KB, only adds the bytesize-and-is_a-String check.)

**What B+G actually achieved:**
- **B: ~25-30% faster across the board.** Real, lasting win. Skipping
  patterns with absent literals avoids a chunk of glibc's per-call O(N)
  setup × 80-ish patterns per call.
- **G: linear scaling for large inputs.** 10MB went from "cliffs to 56s"
  to "~15s, MB/s flat across 1-10MB". Doesn't speed up the per-byte
  constant — chunk size from 4KB to 256KB barely changes 1MB timing
  because the per-pattern × per-match work dominates.
- **Honest conclusion: we did NOT beat Ruby.** Still 3-5× slower at every
  size. Onigmo's built-in Boyer-Moore literal pre-filter (option H finding)
  is structurally faster than what we can manually replicate with `strstr`.

**What's still needed to actually beat Ruby:**
- **Option I** (user idea, 2026-05-23): single-pass, position-by-position
  match. Naive form still O(N×P), but lets us skip whole matched tokens.
- **Option E** (combined automaton): the real answer. O(N) one pass. See
  [docs/standalone_matcher_design.md](docs/standalone_matcher_design.md).
- **Option H** (use Onigmo): pragmatic stopgap if I/E are too far off.
  Brings us to roughly Ruby parity at the cost of MRI coupling.

**Per-pattern impact of B+G (1MB log, re-run 2026-05-23):**
Sum of all 88 patterns: **3001 ms → 1451 ms (2.07× faster).**
Two regimes — patterns split cleanly:
- **Patterns with a required literal** (the `pattern_required_literal[]`
  entries) → typically 0.5-0.7 ms each. They `strstr`-fail on most 64KB
  chunks and skip `regexec` entirely. `hashicorp_terraform_api_token` went
  from 125 ms to 0.6 ms — 208×. `slack_webhook_url`, `github_pat_*`,
  `iban_*` etc. all ~0.5-1 ms.
- **Patterns without a required literal** (NULL in the array) → still
  expensive even after G:
  ```
  email                   96 ms   10 MB/s   (was 205 ms /  5 MB/s)
  aws_secret_access_key  116 ms    9 MB/s   (was 154 ms /  7 MB/s)
  credit_card             55 ms   18 MB/s   (was 155 ms /  6 MB/s)
  ipv4                    49 ms   21 MB/s   (was 148 ms /  7 MB/s)
  pure-digit IDs         ~35 ms each  ~28 MB/s
  ```
  These are exactly the patterns where no distinctive literal exists:
  `email`'s `@` is too common to skip useful work; AWS secret/credit
  card/IPv4 are alternation-heavy with no required literal.

**Implication for option I/E:** the remaining 1.45 s on a 1 MB log is
~85% spent in ~10 patterns. A combined matcher that walks the input once
and tracks partial-match state across these patterns simultaneously would
collapse most of this to a single linear pass. The "long tail" of 78
prefixed patterns is essentially free already (0.6 ms each, fully skipped
when literal absent).

**Other loose ends from this session:**
- Option G could in theory recompose two adjacent chunks if the boundary
  splits a long line; deferred until someone files a real bug for it.

### Earlier checkpoint 2026-05-22 (branch `fix/redact-performance`)

Resume here. Branch `fix/redact-performance` is off `feat/benchmarks`.
Commits on this branch so far:
- `7a70f0a fix: eliminate O(n^2) buffer sizing in redact.c` (the only real fix)
- `4b0dd25` + `55e6634` — this checkpoint (docs only).

Sibling branch `feat/benchmarks` (parent of this one) is HELD — 2 commits, the
benchmark suite + the `BUILTIN_PATTERN_SOURCES/BOUNDARY` constants, not yet
merged or PR'd. The benchmark scripts used below live there.

**What we know (measured):**
- The benchmark suite found `redact` runs at ~0.5 MB/s and is ~7× SLOWER than a
  pure-Ruby `gsub` loop on the same 88 patterns. 10MB redact ≈ 56s before any fix.
- Defect 1 (per-match `strlen(cursor+full_eo)` in `replace_all_matches`) is FIXED
  in `7a70f0a` — buffer now sized once as `in_len*(ph_max+1)+1`. 231 specs green.
- **But the engine is still O(n²).** After the fix, 10MB redact = 32s. Email-only
  scaling: 1MB 144ms → 2MB 347ms (2.4×) → 4MB 954ms (2.7×) → 8MB 3216ms (3.4×).
  Each doubling more than doubles the time — confirmed super-linear.
- Cost is per-MATCH, not per-byte: on 10MB, `gpg_private_key` (0 matches) = 24ms
  (~420 MB/s, healthy); `email` (heavy matches) = 4729ms; `credit_card` = 4419ms.
- So Defect 1 was real but NOT the dominant cost. The TODO's old assumption
  ("allocation is almost certainly the bottleneck") is WRONG — see below.

**Why Onigmo (Ruby) is faster — CONFIRMED from Onigmo source (2026-05-23):**
Onigmo's `forward_search_range` does Boyer-Moore (`bm_search`) fast-skipping to
literal anchors *before* calling the NFA matcher. The compiled regex stores
`reg->optimize` flags (`ONIG_OPTIMIZE_EXACT_BM` etc.) and pointers to the
extracted literal. glibc `regex.h` has no such pre-filter — it runs the full
DFA from every position. **That difference IS the 4–6× gap.** It also means
**option B (`memchr` pre-filter) only brings us TO parity with Ruby, not
dramatically past it** — we'd be manually replicating what Onigmo does
automatically for every pattern. Beating Ruby decisively requires G (chunked
input) or E (true multi-pattern matcher).

**Mechanism — CONFIRMED from glibc source (2026-05-23):**
Read `posix/regexec.c` `re_search_internal` in the glibc tree. Findings:
1. Every `regexec` call allocates a state-log array proportional to the input
   length passed in (`mctx.state_log = re_malloc(..., mctx.input.bufs_len + 1)`),
   *before any matching begins*. That's O(N) setup per call, mandatory.
2. The DFA traversal is O(N) per call in the worst case.
3. `prune_impossible_nodes` does another O(N) backward sift.
Therefore our loop `while (regexec(pat, cursor, ...) == 0) cursor += full_eo;`
with M matches in N bytes costs **Σ(N - cursor_i) ≈ O(N²/2)** when matches are
evenly spread — the email-in-log case exactly.
**The bug is in glibc's calling convention, not our code.** No buffer fix, no
ping-pong, no smarter loop around `regexec` will change the complexity class.
Either we *call regexec less often* (chunking, memchr pre-filter) or we *stop
using regexec* (combined matcher / different engine).

(The filler test the previous checkpoint recommended is no longer needed —
the glibc source confirmed the mechanism directly. The 2× → 4× growth we
measured matches the O(N²/2) prediction.)

**How the engine actually works (and how the user expects it to):**
- ACTUAL: for each of 88 patterns separately, call glibc `regexec()` in a loop
  over the whole working buffer, replace matches, emit a new buffer, pass it to
  the next pattern. 88 independent full passes, 88 separate regex engines.
- USER'S MENTAL MODEL (and the right fix direction): a single streaming pass —
  read a char, advance every pattern's match state, track which patterns are
  still alive, replace when one completes. That's a combined multi-pattern
  matcher (Aho-Corasick for literals / a merged NFA-DFA for regex). O(n) total,
  one pass, regardless of pattern count. This is a much bigger change than
  "ping-pong buffers" but it is the real answer if `regexec` is the bottleneck.

**Small-string measurement (2026-05-23):**
Per-call latency, C extension vs pure-Ruby `gsub` (88 patterns each):
```
size                       C        Ruby     ratio
log line (168B)         0.23 ms   0.06 ms   4.2× slower
json blob (~578B)       0.69 ms   0.11 ms   6.5× slower
8 log lines (~1.3KB)    0.23 ms   0.06 ms   4.2× slower
100 log lines (~17KB)  22.58 ms   3.99 ms   5.7× slower
```
**The C extension is slower than Ruby at every size we've measured.** The earlier
session noted 7× slower on 1 MB; small strings are 4–6× slower. The slowdown
isn't size-specific — it's per-call overhead × 88 patterns, dominating
everywhere. This is the central problem.

**Benchmark gap:** `benchmark/vs_pure_ruby.rb` only tests 1 MB. Add a
small-string variant (or extend it to walk 1KB → 1MB) so we're measuring the
typical use case, not just the stress test.

**Use-case sizing (matters for which fix wins):**
The gem is called **many times on small strings**, not once on huge ones:
- Log scrubbing — per line, ≤ 1 KB
- Rails param filtering — typically ≤ 10 KB
- Rack response bodies — can be MB-scale
- LLM payloads — tens of KB to a few MB
- `redact_deep` / `redact_json` — walks per-leaf, each leaf typically small
The 1MB/10MB benchmarks are stress tests, not the dominant use case.
**Implication:** for the typical small-string call, the O(N) setup *per regexec*
× 88 patterns dominates. Skipping patterns entirely (B) saves more than reducing
N (G) when N is already small.

**Our ideas / options to evaluate (re-ordered with new understanding):**
- A. ~~Confirm the mechanism first~~ — DONE via glibc source; skip.
- B. **`memchr` literal pre-filter — closes the gap with Ruby, doesn't exceed it.**
  Most patterns have a required literal (`@`, `AKIA`, `BEGIN `, `sk_live_`,
  `eyJ`, etc.). `memchr` the buffer once per pattern; if the literal is absent,
  skip `regexec` entirely — saving the O(N) state-log alloc AND the O(N) DFA
  walk. ~60 of 88 patterns have an obvious literal. **Reality check:** this
  manually replicates what Onigmo already does internally via `bm_search` (see
  the "Why Onigmo is faster" note above), so it brings the C extension TO
  parity with Ruby, not far past it. The remaining edge from C (no Ruby-VM
  overhead) is small. Still worth doing — it eliminates the embarrassing
  "C extension is slower than Ruby" situation — but understand it's the floor,
  not the ceiling. Does NOT help heavy-match patterns on matching input.
- C. **`REG_NOSUB`** for non-boundary patterns — cheap, marginal.
- D. **Anchor / bound the greedy patterns** — `email`'s `+` quantifiers backtrack;
  rewriting to possessive-style or length-capped forms (POSIX has no possessive
  quantifiers — would need `{1,64}` style caps) could kill the backtracking.
- G. **Chunked input — biggest worst-case win, same problem as streaming.** Split
  the input into bounded chunks (e.g. 4–8 KB), run the existing 88-pattern
  pipeline on each chunk, concatenate. Each `regexec` sees ≤ chunk_size, so the
  O(N²) is bounded → effectively linear in total input. **Estimate: 10 MB
  email-heavy goes ~32 s → ~0.1 s. ~300×.**
  - **Boundary problem (same as TODO #8 Streaming API — solve them together):**
    a match could straddle a chunk boundary and be missed → leaked secret.
    Worst-case bug for a redaction gem.
  - **Mitigations:**
    - Newline-split for log inputs (the dominant case); patterns rarely cross
      lines. Falls back to overlap chunking on any chunk > hard cap.
    - Overlap windows for general text: chunks overlap by `max_pattern_length`
      bytes; dedupe matches in the overlap. More general, trickier.
    - **For very long no-newline inputs:** warn the user (or document the
      limitation) until overlap chunking is in. A separate opt-in
      `redact_chunked(text, chunk_size:)` API could surface the trade-off
      explicitly.
  - **Max-size safety valve:** consider raising above e.g. 10 MB unless
    `chunked: true` is passed. Pragmatic backstop.
- E. **Combined single-pass matcher** (the user's model) — merge all 88 patterns
  into one engine. **Full design doc: `docs/standalone_matcher_design.md`** —
  decided 2026-05-23 to spec this as its own C library (gem-agnostic, shareable
  with the Elixir port, testable in isolation, big enough that mixing it into
  `ext/` would dwarf the gem). Multi-week project, deferred. Land B and/or G as
  the near-term wins.
- I. **Streaming position-by-position match (user idea, 2026-05-23).** Walk the
  input once, left to right. At each position, try patterns sequentially until
  one matches. If a pattern matches → emit `[REDACTED]`, advance past the
  matched span (no later pattern can re-match within it, naturally enforcing
  specific→generic priority by pattern order). If no pattern matches → advance
  one byte, retry. **Conceptually exactly what option E does** — but the naive
  form still costs O(N × P) `regexec` calls (P = 88), same complexity class as
  today. What turns it into true O(N) is a *shared automaton* over all pattern
  prefixes so each position needs ONE state transition, not P probes — that's
  the combined-matcher data structure in [docs/standalone_matcher_design.md](docs/standalone_matcher_design.md).
  - **Useful as an intermediate step toward E:** the algorithmic skeleton
    (single pass, position-by-position, first-match-wins, skip past matches)
    is exactly what E uses. The combined automaton just replaces the inner
    "try P patterns" loop with a single DFA lookup.
  - **Might already win as a quick prototype** even in naive form: when
    matches are common, each match skips a whole token (~20-40 bytes), so
    average cost per byte = P / token_length, often << P. Worth measuring
    before E if we want a partial win sooner.
  - Cleanly solves the chunking boundary problem (option G) — no buffer
    between patterns to chunk in the first place.

- H. **Use Onigmo (Ruby's own regex engine) instead of glibc `regex.h`.**
  Available "for free" via Ruby's C API (`onig_search`, `rb_reg_search`); no new
  dependency — Onigmo ships with MRI Ruby. Gets Onigmo's Boyer-Moore literal
  pre-filter automatically (the thing currently making Ruby's `gsub` 4–6× faster
  than us), plus the per-call O(N) state-log allocation that plagues glibc may
  be smaller for typical patterns (Onigmo uses stack/alloca for short matches).
  - **Realistic gain:** ~1.5–2× faster than pure-Ruby `gsub` — we save Ruby's
    `String`/`MatchData`/method-dispatch overhead per pass, but the matching
    itself is the same engine doing the same work. We are not adding algorithm
    over `gsub`; we are a thin C wrapper that calls the same engine slightly
    more efficiently.
  - **Cost — couples to MRI internals.** JRuby ships Joni (Java port of
    Oniguruma) and TruffleRuby ships TRegex. Neither has Onigmo. Either we add
    a Ruby-implementation detection layer with separate code paths, or we drop
    non-MRI support. The gem currently uses POSIX `regex.h` precisely so it
    works on any libc — switching to Onigmo gives up that portability.
  - **Identity cost.** The C-extension framing becomes hollow: "we wrap Ruby's
    regex engine slightly more efficiently than `gsub`." Honest answer to "what
    does this gem give me over `gsub` directly?" shrinks to "less object churn."
    Defensible as a stopgap; not as the long-term differentiator.
  - **When to consider:** if B + G don't close the gap with Ruby, H is the
    pragmatic stopgap while E is being built. If E succeeds, H becomes
    irrelevant.
- F. Swap glibc POSIX `regex.h` for a faster engine. Survey (2026-05-23):
  - **RE2** (Google, BSD, C++): single regex, linear-time. Used by Chrome, Go's
    `regexp`. **Not multi-pattern** — we'd still call it 88 times. Better per
    call than glibc but same complexity class for our access pattern.
  - **Hyperscan** (Intel, BSD, C): **multi-pattern, linear-time** — exactly what
    we want. **But x86-only** (SSE/AVX intrinsics) → disqualified for a gem that
    ships on ARM (Apple Silicon, Graviton).
  - **Aho-Corasick** libraries: multi-pattern but **literals only**, no regex →
    insufficient.
  - **Onigmo** (Ruby's engine): single-pattern, just faster per call.
  Conclusion: no portable, multi-pattern, regex-subset C library exists — which
  is exactly why E warrants the spinoff.

- J. **Convert the C extension to C++ (open question, raised 2026-05-23).**
  Worth considering before/during E since the matcher is the biggest new C
  surface area we'd ever write. Trade-offs to evaluate:
  - **Pro:** standard library (`std::vector`, `std::unique_ptr`, RAII)
    eliminates a lot of the manual `malloc`/`free`/`realloc` discipline
    that's already caused subtle bugs this session (the scan offset bug,
    the buffer-sizing bug). For NFA/DFA construction specifically, having
    `std::set` for state-set comparisons and `std::vector` for adjacency
    lists is a real ergonomic win.
  - **Pro:** RE2 is C++ for exactly this reason; their codebase is
    significantly cleaner than equivalent C implementations like glibc's
    regex.
  - **Pro:** Speed parity with C — `-O2` C++ produces equivalent code for
    the kinds of constructs an NFA/DFA needs. No measurable runtime cost.
  - **Con:** Ruby C extensions compile their C with `mkmf` and Ruby's
    default CFLAGS; switching to C++ means `mkmf` C++ support
    (`have_library`, separate `.cpp` extension, sometimes a manual
    `Makefile` patch). Cross-platform precompilation via `rake-compiler-dock`
    has worked for C extensions for years — needs verification for C++.
  - **Con:** Ruby's C API uses `extern "C"` and pre-C++11 conventions in
    headers; bridging into modern C++ is fine but requires care at the
    boundary (no Ruby `VALUE` flowing into C++ template machinery).
  - **Con:** Build dependencies grow — every install platform needs a C++
    compiler, not just C. Precompiled gems make this invisible to most
    users but raises the bar for source installs.
  - **Decision deferred** to when the Phase 2 matcher implementation
    starts (per `docs/combined_matcher_plan.md`). If we decide yes, the
    conversion happens *at the start* of Phase 2 so the matcher is C++
    from day one; converting later means rewriting.

**Will the fix beat the pure-Ruby benchmark? (assessment 2026-05-23, revised)**
- Earlier-in-the-day assessment (B comfortably beats Ruby) was WRONG. After
  reading Onigmo's source we found Ruby's engine already does the equivalent of
  option B internally (Boyer-Moore literal pre-filter via `bm_search`). Sharper:
- **B (memchr) brings us TO parity with Ruby**, maybe slightly past. It catches
  up to a standard regex-engine optimization glibc lacks. Not a "win," but ends
  the "C extension is slower than Ruby" embarrassment. ~3-4h, low risk.
- **G (chunking) is the first genuine win past Ruby** for inputs with many
  matches. Both engines pay O(N²) per pattern; chunking bounds it for *both*
  but we get to apply it without Ruby paying for it. Estimate: 3-5× past Ruby
  on large heavy-match inputs. ~half-day.
- **E (combined matcher) is the only way to dramatically beat Ruby across the
  board.** Multi-week project; see design doc.
- **Pragmatic path unchanged but with realistic expectations:** B first (achieve
  parity, no embarrassment), G second (the first real win), E long-term.

**Old plan status:** `~/.claude/plans/dapper-forging-nest.md` Parts B/C/D (ping-pong
buffers, scan offset-map) were written BEFORE we learned `regexec` is the hot
spot. Parts B/C/D are still valid cleanups but will NOT fix the O(n²) on their
own. RE-PLAN after the filler test pins the mechanism.

**Benchmark suite caveat:** `scaling.rb`'s 50MB step and `per_pattern.rb` take
many minutes under the current O(n²) engine — expected, they'll be fast post-fix.

---

Current `redact` runs each pattern over a fresh working buffer, copying non-matching segments and `realloc`ing as needed. That's correct but allocation-heavy. Things to try, roughly in order of expected payoff:

- **Single-pass, two-buffer ping-pong** — keep two buffers alive across patterns and swap pointers instead of `malloc`/`free`-ing per pattern. Saves `NUM_PATTERNS - 1` allocation pairs per call.
- **Initial buffer sizing from input length** (currently grows from a small starting size) — `malloc(input_len + slack)` upfront avoids early `realloc`s for typical payloads.
- **Skip patterns with no possible match** — quick `memchr` for a required literal (e.g. `sk_live_` for Stripe, `AKIA` for AWS, `BEGIN ` for PEM) before invoking `regexec`. For most inputs most patterns won't match — bailing without `regexec` is a big win.
- **`REG_NOSUB` where we don't need capture groups** — non-boundary patterns currently request unused match info.
- **Replace `strdup`/`strncpy` chains with direct `memcpy` into a known-size output buffer** — fewer C-library calls, simpler escape analysis for the compiler.
- **Reuse the same allocation across `redact` *calls*** — process-local thread-local buffer (after [Full thread safety](#full-thread-safety) lands) reset to length 0 between calls. Eliminates allocation entirely on the hot path.
- **Branch-free `write_placeholder` for the plain mode** — the common case is one `memcpy` of a fixed-size string; specialize it.
- **Profile first** — wire up `benchmark/throughput.rb` (see [Benchmarks](#benchmarks)) and `perf` / `Instruments` before changing code. Optimize the actual hot spot, not the assumed one.

**Why:** the C extension is the gem's selling point. Beating pure-Ruby `gsub` by 2× isn't impressive; beating it by 20× is.

> **Update 2026-05-22:** the original guess here — "allocation is almost
> certainly the bottleneck" — was DISPROVEN by the benchmark suite. Allocation
> is minor; the dominant cost is per-match `regexec` work (see the IN PROGRESS
> checkpoint above). `regexec` is NOT fast for greedy patterns. Profile, don't
> guess.

## Full thread safety

Today `redact` and `scan` are thread-safe but `add_pattern` / `remove_pattern` / `clear_custom_patterns!` are not (documented in README as "register at boot"). Goal: make every public method safe to call from any thread at any time.

- **Reader-writer lock around the custom-pattern array** — `redact`/`scan` take a read lock for the duration of the call (they already iterate the array), `add_pattern`/`remove_pattern`/`clear_custom_patterns!` take a write lock. Use `pthread_rwlock_t` (POSIX) — or, simpler and good enough, a plain `pthread_mutex_t` since contention is low in practice.
- **Release the GVL during long redactions** — `rb_thread_call_without_gvl` so other Ruby threads can run while a big payload is being scanned. The lock above must be acquired *before* releasing the GVL and held until reacquiring it, so the array can't change mid-scan.
- **Atomic snapshot alternative** — copy-on-write the custom-pattern array on every mutation; readers grab a pointer to the current snapshot under a brief lock and use it lock-free. More allocation per write, zero contention per read. Probably overkill until someone reports it as a real problem.
- **Tests** — Ruby thread-stress test that registers/removes patterns from one thread while N readers `redact` concurrently. Run under TSan in CI on Linux if affordable.
- **Update README** — once shipped, replace the "not thread-safe" caveat in the Thread safety section with a plain "fully thread-safe" statement, and note the `rb_thread_call_without_gvl` behavior.

**Why:** "register at boot" is a real ergonomic limitation — anyone building a multi-tenant app that loads tenant-specific patterns at request time can't use the gem safely today. Removing that caveat is a real differentiator.

## Possible Erlang / Elixir port

The C core is portable — the Ruby-specific layer is thin (`StringValueCStr`, `rb_str_new_cstr`, `rb_define_module_function`, the `TAG_*`/`PH_MODE_*` constant exposure, and the keyword-argument wrapper). Reimplementing for the BEAM is realistic.

Two viable shapes:

- **NIF (`erl_nif.h`)** — wrap the same POSIX `regex.h` engine in a NIF, exposed as a Hex package `data_redactor_ex`. Same patterns, same tags, same placeholder modes. Use `enif_make_binary` / `enif_inspect_binary` instead of `rb_str_new_cstr` / `StringValueCStr`. NIFs that can run >1ms must yield via `enif_consume_timeslice` / `enif_schedule_nif`, so large-payload `redact` would need chunked execution to avoid blocking the scheduler.
- **Pure Elixir with `:re` (PCRE)** — slower but no NIF risk and idiomatic for the BEAM. Patterns would need translating from POSIX ERE to PCRE (largely a no-op since PCRE is a superset, but `(^|[^0-9A-Za-z])` boundary wrappers can be replaced with `\b` for legibility).

**API sketch (Elixir):**

```elixir
DataRedactor.redact("token AKIA...")
DataRedactor.redact(text, only: [:credentials])
DataRedactor.scan(text)
# => {:ok, %{redacted: "...", matches: [%{tag: :credentials, name: "aws_access_key_id", ...}]}}
DataRedactor.add_pattern(name: "employee_id", regex: "EMP-[0-9]{6}")
```

**Why:** Phoenix and Broadway pipelines have the same redaction problem Rails apps do — logs and message payloads with embedded PII. The BEAM ecosystem doesn't have an obvious incumbent here, and a NIF that mirrors the Ruby gem keeps both implementations honest (same patterns, same tag taxonomy, same placeholder semantics, shared test corpus).

**Cost / risk:**
- Maintenance doubles. Either the C core lives in a shared submodule both gems vendor in, or the two implementations drift.
- NIF safety bugs (segfaults) crash the entire BEAM VM, not just one process. Higher bar than a Ruby C extension where a segfault only crashes the worker.
- Hex publishing, ExDoc, and a separate CI matrix are real work.

Defer until the Ruby gem has real adoption and someone explicitly asks for it. Documented here so the option isn't forgotten.

## Benchmarks

A `benchmark/` directory using `benchmark-ips` and `benchmark/memory` (both
dev-only deps). Repo-only — not packaged in the gem.

**Done (on branch `feat/benchmarks`, committed):**
- `benchmark/support/corpus.rb` — payload builders + pure-Ruby baseline redactor
  (reads `BUILTIN_PATTERN_SOURCES`/`BOUNDARY` live, no drift from `patterns.c`).
- `benchmark/throughput.rb` — MB/s on log line, JSON blob, 1MB/10MB log files.
- `benchmark/per_pattern.rb` — per-pattern scan cost over a 1MB payload.
- `benchmark/vs_pure_ruby.rb` — C extension vs pure-Ruby `gsub`, same 88 patterns.
- `benchmark/scaling.rb` — runtime vs input size (1KB → 50MB).
- `benchmark/README.md` — how to run / what each script measures.
- `BUILTIN_PATTERN_SOURCES` / `BUILTIN_PATTERN_BOUNDARY` C constants.

**`vs_alternatives.rb` — skipped.** No comparable maintained Ruby gem:
`pii-detector` (Shopify) is abandoned, `confidential_info_redactor` is NER-based
and not comparable, `logstop` covers far fewer patterns. A head-to-head would
mislead more than inform.

**What the benchmarks found (the reason the fix below exists):**
- `redact` runs at ~0.5 MB/s on a 1MB log; a 10MB log takes ~56s.
- The C extension is **~7× slower than pure-Ruby `gsub`** on the same 88 patterns.
- Cost is per-match, not per-byte: patterns that don't match run at 500–900 MB/s;
  patterns that match heavily (`email`, `credit_card`, `ipv4`) crawl at ~5 MB/s.
- Root cause: O(n²) tail re-scan — see the Performance section above.

**Remaining benchmark work (do NOT do until the performance fix lands):**
- [ ] Re-run all four scripts on the fixed engine and capture real numbers.
- [ ] Add a `## Benchmarks` section to the README with the post-fix numbers
      (throughput MB/s, vs-pure-Ruby speedup). Deliberately deferred — publishing
      pre-fix numbers would advertise the gem losing to pure Ruby.
- [ ] Note in the README that no other Ruby PII gem publishes benchmarks
      (factual differentiator).
- [ ] Add `benchmark/` to the README `## Directory structure` tree.
- [ ] CHANGELOG `[Unreleased]` entry for the benchmark suite + the two new
      `BUILTIN_PATTERN_*` constants. No version bump (repo tooling + internal
      constants).
- [x] Verify `benchmark/` is excluded from the built `.gem` — confirmed, 0
      `benchmark/` entries in `data_redactor-0.9.0.gem`.
- [x] Fix `benchmark/README.md`: run command is `bundle exec ruby`, not bare
      `ruby` (bare `ruby` hits `incompatible library version` when the system
      Ruby differs from the bundled one).
- [ ] Reconsider `scaling.rb`'s 50MB step — under the current O(n²) engine it
      runs for many minutes. After the fix it should be fast; if not, drop the
      largest size or reduce the repeat count.

**Follow-up (separate task, not part of the benchmark suite):**
- [ ] CI benchmark integration — a PR job that runs the suite on the branch +
      `main` and posts a before/after comment (e.g. `github-action-benchmark`,
      history on `gh-pages`). Caveat: GitHub-hosted runners have 5–15%
      run-to-run variance, so any regression gate needs a loose threshold (≥20%)
      or must stay informational-only.

---

## Promotion checklist

Things to do **once the gem is published** to build visibility and trust.

### One-time setup
- [x] `gem push` to RubyGems.org — published 2026-05-08 (0.5.0)
- [x] Add GitHub repo topics: `ruby`, `gem`, `pii`, `redaction`, `security`, `rails`
- [ ] Submit to [The Ruby Toolbox](https://www.ruby-toolbox.com) (community-curated catalog; lets developers compare gems in the same category)
- [x] Add Shields.io badges to README: gem version, CI build, license
- [x] Write YARD docs for all public methods (`@param`, `@return`, `@raise`)
- [x] Add a thread-safety note to README (built-in `regex_t` array is read-only after init; custom pattern registration is not thread-safe — document this)
- [ ] Create a minimal demo app or `examples/` directory showing real-world usage (Rails logger wrapper, Rack middleware, etc.)

### Announcement
- [ ] Post to r/ruby and r/rails — ask for feedback, don't just "sell" it
- [ ] Write a short article on DEV Community or Medium: "Why I built a C-extension PII redactor for Ruby" — the C vs. pure-Ruby angle is the hook
- [ ] Announce on X / Mastodon with `#ruby` and `#rails` hashtags
- [ ] Submit to [Ruby Weekly](https://rubyweekly.com) and [Short Ruby Newsletter](https://newsletter.shortruby.com) for potential feature
- [ ] If there is a local / virtual Ruby meetup, offer a 5-minute lightning talk

### Ongoing
- [ ] Keep CHANGELOG up to date (already doing this ✅)
- [ ] Respond to issues and PRs promptly — responsiveness is the biggest trust signal
- [ ] Track download stats on RubyGems.org; high growth can get the gem onto trending lists

---

## Design decisions

Permanent record of choices made and why, so future contributors don't have to re-litigate them. Add to this list when a non-obvious decision is made; remove an entry only when the decision is reversed (and note the reversal in CHANGELOG).

### Regex engine: POSIX `regex.h`, not Onigmo / PCRE

- **Why**: ships with libc on Linux/macOS, zero extra dependency, fast enough for the use case, keeps the C code small.
- **Cost**: no `\d`, `\s`, `\w`, `\b`, `(?:...)`, lookaround, non-greedy, named groups. Patterns must be POSIX ERE. We use a manual boundary wrapper (`(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)`) where word boundaries are needed.
- **Reversible?** Yes — could swap to Onigmo (Ruby's own engine) later if user-supplied patterns need richer syntax. Would mean linking against Ruby's regex internals or pulling in PCRE.

### Pattern ordering: most-specific first, generic last

- **Why**: patterns run sequentially on a working buffer. An early broad pattern (e.g. 9-digit passport) can consume digits a later pattern (credit card) depends on. Ordering specific→generic + boundary-wrapping the generic ones prevents this.
- **Cost**: adding a new pattern requires choosing the right tier (see comment block at the top of `pattern_tags[]`).
- **Reversible?** Difficult. Would require a fundamentally different match-collection algorithm (find all matches first, resolve overlaps, then replace).

### Tag system: 8 fixed bits + 1 reserved (`:custom`)

- **Why** (over free-form tags): no registry, no dynamic bit allocation, simple `int` mask, covers the obvious use cases. We can add free-form tags later without breaking the existing API.
- **Cost**: users can't add arbitrary tags like `:internal_pii`. They get `:custom` for everything user-defined.
- **Reversible?** Yes — additive. Free-form tags would slot in alongside the fixed bits using bits 9-31 of the mask.

### Custom patterns: strict validation, no Ruby-syntax translation

- **Why**: predictable behaviour. A user who writes `\d` in a custom pattern gets a clear `InvalidPatternError` at registration, not a silent mismatch at redaction time. Translation is a meaningful chunk of code (and a maintenance burden) that we should only pay for if users actually ask.
- **Cost**: ergonomic friction. Users must know POSIX ERE syntax.
- **Reversible?** Yes — translation can be added later without breaking existing strict patterns (translated patterns just produce equivalent POSIX ERE before `regcomp`).

### `[REDACTED]` as the placeholder, hardcoded for now

- **Why**: one allocation strategy, one length constant (`PLACEHOLDER_LEN`), simpler C code.
- **Cost**: no per-tag placeholders, no deterministic-hash mode (yet).
- **Reversible?** Yes — roadmap item #3 plans to make this configurable.

### Process-local state for custom patterns (no persistence)

- **Why**: matches built-in pattern behaviour (compiled at module init, lives until VM exit). Predictable, no I/O at redaction time, no config-file parser to maintain.
- **Cost**: every process re-registers patterns at boot. App-level concern, not the gem's.
- **Reversible?** Yes — a YAML/JSON loader is on the deferred list.

### Public API is the Ruby wrapper, not the C function

- **Why**: keyword arguments (`only:`, `except:`) are awkward in C-defined methods. The Ruby wrapper (`DataRedactor.redact`) handles validation, builds the bitmask, then calls `_redact(text, mask)`. Underscore-prefixed C function signals "internal".
- **Cost**: one extra Ruby method call per redaction. Negligible vs. the C work.
- **Reversible?** Yes, but no reason to.
