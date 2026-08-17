# TODO

Open work only. Completed items have been archived in [DONE.md](DONE.md); the
detailed record of every shipped change lives in [CHANGELOG.md](CHANGELOG.md).
Permanent design rationale is in the [Design decisions](#design-decisions)
section at the bottom (kept here, not in DONE.md — it's reference, not a task).

---

## Engine & correctness

### 🔴 BUG — chunk boundaries leak secrets in the clear (scope, then fix)
**Reproduced 2026-08-08 against 0.17.1. Not a "documented limitation" — a
redaction gem emitting an unredacted AWS key is a correctness bug, and it is the
one open item that silently produces wrong, unsafe output.** Both split paths in
`_chunk_bytes` (`lib/data_redactor.rb`) leak; only the first was previously
written up, and the second is the more dangerous of the two.

**1. Newline-aligned split.** Patterns whose separator is `[[:space:]]*` — e.g.
`keyname_anchored_secret`, `patterns.c:627` — match across a `\n`, because POSIX
`[[:space:]]` includes newline. A key ending one chunk with its value opening the
next is never seen as a pair:
```
chunk1 ends:   "x\npassword:\n"
chunk2 starts: "   hunter2secret\ntai"     → "hunter2secret" emitted verbatim
```
This one is **not** limited to the no-newline fallback, which is what the earlier
write-up assumed. The ordinary, newline-respecting split leaks too.

**2. No-newline hard split (worse).** When a single line exceeds `CHUNK_SIZE`,
the fallback cuts at exactly 65536 bytes, straight through whatever token sits
there:
```
chunk1 tail: "xxx AKIAIO"
chunk2:      "SFODNN7EXAMPLE end"
output:      "xxxxx AKIAIOSFODNN7EXAMPLE end"   ← full key, in the clear
```
Minified single-line JSON logs are routinely well over 64 KB, and for those
*every* chunk boundary is a blind mid-token cut — not a rare edge case.

**Scope this before writing any fix — deliberately not started 2026-08-08.**
The two repros above each produced exactly **two** chunks, so they demonstrate a
leak at *a* boundary; they do **not** establish the blast radius. Answer these
first, with tests, and record the answers here:
- **Every boundary, or only some?** `_chunked_scan` loops over all chunks and
  scans each in isolation with no overlap, so the mechanism suggests every
  boundary is equally blind — but that is inference from reading the loop, not a
  measured result. Build a ≥4-chunk input with a planted secret at every
  boundary and count how many survive.
- **Last chunk special?** The `remaining <= CHUNK_SIZE` early-exit takes a
  different path from the windowed split. Check whether the final boundary
  behaves like the others.
- **Which patterns can actually span a cut?** Only some can. `[[:space:]]`-
  separated ones provably do (case 1). Patterns using `[^[:space:]]` cannot span
  a newline cut but *can* span a mid-line hard cut. An inventory of which of the
  89 patterns are exposed, and by which cut type, sizes the real risk.
- **How wide must the overlap be?** Needs the true longest possible match, which
  interacts with the 255-char bounded tails from 0.14.1 — the bound may already
  cap the window usefully.
- **Does an overlap window double-count?** Dedupe by byte offset in
  `_chunked_scan` (it already rebases `:start`) — verify against adjacent and
  nested matches, not just isolated ones.

**Likely fix once scoped:** re-scan an overlap window spanning **every**
boundary, not just the no-newline fallback the earlier write-up assumed. Specs
must cover both cut types plus the exact-boundary off-by-ones.

**Interacts with:** the CLI (`exe/data_redactor`) below — piped `kubectl logs` /
CI logs cross 64 KB on essentially every invocation, which would turn a latent
library edge case into the CLI's normal path. Also the general form of the
streaming API (#8).

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

### Recover the ~3% small-input throughput
**Partly addressed in 0.17.1** — the per-call re-entrancy refactor fetches the
per-thread cache base **once** per `mm_scan` (not per pattern), lifting the
`thread_state()` generation check out of the per-pattern inner loop. Remaining: if
the small-input regression persists in the paper's benchmark table, consider
inlining `thread_state()` or further caching the `scan_state_t *` base. Low
priority (within run variance) — re-measure before doing more.

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

- **musl load-and-smoke across a Ruby matrix** (optional) — the `musl-load` job
  already `require`s the gem and smoke-tests redaction on `ruby:3.3-alpine`
  (the load-and-smoke class is covered). Widening it to a `3.1`–`3.4` Alpine
  matrix would catch a musl regcomp divergence that is Ruby-version specific.
  Nice-to-have, not blocking.

- **Ship precompiled binaries for Ruby 4.0** — CI now proves the gem compiles
  and passes on 4.0, but the native gems still cover 3.1–3.4 only, so every 4.0
  user falls back to the source gem and needs a compiler — the exact friction
  the precompiled binaries exist to remove. `rake-compiler-dock` 1.12.0 (already
  the locked version) cross-compiles 4.0, so the change is `CROSS_RUBY_VERSIONS`
  in the Rakefile plus the README target table. It grows every native gem by one
  more `.so` and only reaches users on a release, so land it *with* a release
  rather than between them.

- **Coverage tracking (SimpleCov)** — nice-to-have only; the per-pattern
  positive/negative test discipline already does the real work. Consider only if
  contributors arrive.

- **RuboCop (lint job)** — no linter today; style is enforced by hand via
  CLAUDE.md. Add `rubocop` (+ likely `rubocop-rspec`) as a dev dependency with a
  **curated `.rubocop.yml`** matching the house style — not the defaults, which
  conflict with several CLAUDE.md rules (no forced comments, "three similar lines
  beats a premature helper", keyword-arg conventions). Add a `rake rubocop` task
  and a CI lint job. Tune cops to the existing code rather than mass-rewriting it;
  `# rubocop:disable` is fine for deliberate divergences. Low priority — a
  polish/contributor-experience item, not correctness.

---

## Features (roadmap, not yet started)

### Checksum validation (#7)
Massive false-positive killer; apply only when the structural regex already
matched: Luhn (credit cards), mod-97 (IBANs), Italian Codice Fiscale check char,
Spanish DNI letter, Brazilian CPF/CNPJ, PESEL, CNP, etc. Probably an opt-in
per-call flag (`strict: true`) since validation costs CPU.

- **Publish false-positive numbers when this lands.** Run the engine over a
  public log corpus, measure precision/recall per pattern, and put the numbers
  in the README/wiki. False positives are the #1 reason teams rip out redaction
  tools, and nobody in this space publishes FP rates — with the existing
  benchmark discipline this is a cheap credibility moat, and it feeds the paper
  narrative too.

- **Re-check the spaced-card vs Aadhaar collision after checksums land.** A
  space-grouped credit card `4111 1111 1111 1111` currently matches
  `indian_aadhaar` (national_id) on its first 12 digits, NOT `credit_card`
  (financial) — the unspaced `4111111111111111` matches credit_card correctly.
  (Found 2026-06-20 while writing `examples/ruby_llm.rb`.) Luhn (card) +
  Verhoeff (Aadhaar) validation should disambiguate: the spaced form's 16 digits
  pass Luhn as a Visa card, and the 12-digit Aadhaar slice would fail Verhoeff.
  Verify this resolves once #7 is in; if not, may need ordering/anchoring work.

### CLI executable (`exe/data_redactor`)
Read stdin, write redacted stdout; flags mirroring `only:`/`except:`/
`placeholder:`, plus `--scan` for audit JSON. Makes the gem demoable to people
who never write Ruby — `kubectl logs … | data_redactor`, CI log scrubbing, a
pre-push hook — and turns every promotion post's demo into one shell line. No
new deps; an afternoon of work on the existing API.

**Sequencing:** the chunk-boundary bug at the top of Engine & correctness lands
first — piped log input crosses 64 KB constantly, so shipping the CLI ahead of
it would make that leak the CLI's normal path rather than a latent edge case.

**⚠️ `--scan` output contains the raw secrets.** `scan` returns `:value` per
match (`lib/data_redactor.rb`), i.e. the unredacted token. A naive
`--scan` dumping the hash to JSON turns the audit flag into an exfiltration
path — `data_redactor --scan < app.log | tee audit.json` writes every secret to
disk in the clear, from a tool whose whole purpose is preventing exactly that.
Decide before implementing: omit `:value` by default and gate it behind an
explicit `--unsafe-show-values`, or emit only `:tag`/`:name`/`:start`/`:length`.
This is the single most important design call in the CLI.

**Settled design decisions (2026-08-08):**
- **Slurp stdin, don't stream.** Line-by-line reading misses
  `[[:space:]]`-separated key/value pairs that span a newline — verified, it
  leaks. Consequence: `kubectl logs -f | data_redactor` (follow mode) emits
  nothing until EOF. Acceptable and documented until the streaming API (#8).
- **`--scan` exits 0** by default; opt-in `--fail-on-match` for pre-push-hook /
  CI gating so piping isn't surprised by a non-zero status.
- **`CLI.run(argv, stdin:, stdout:, stderr:)` returning an exit code**, in
  `lib/data_redactor/cli.rb`; `exe/data_redactor` is a shebang stub that
  delegates. Keeps redaction logic out of the executable (Single Responsibility)
  and lets specs run in-process — no subprocess spawning, no compiled-gem path
  juggling in CI.

**Mechanics already verified, so nobody re-derives them:**
- **No `exe/` or `bin/` directory exists yet** — this is greenfield.
- **`optparse` and `json` are stdlib**, so the zero-runtime-dependency rule
  holds; `json` is already required by `lib/data_redactor.rb`.
- **Gemspec** needs `spec.bindir = "exe"`, `spec.executables`, and `Dir["exe/*"]`
  added to `spec.files` (currently `lib/**/*.rb` + `ext/**` + docs only).
- **Native gems are safe.** The Rakefile's `cross_compiling` block rejects only
  `ext/`-prefixed files, so executables survive into all six platform gems.
- **`redact` is byte-safe on invalid UTF-8** (verified: `\xff\xfe` passes
  through untouched, ASCII-8BIT and UTF-8-tagged alike). No encoding-sanitising
  layer needed — important, since scrubbing real log output is the use case.
- **`--list-patterns` / `--list-tags` are free** from `DataRedactor.pattern_names`
  and `DataRedactor.tags`.
- **Filter validation is free.** `only:`/`except:` already accept tag Symbols and
  pattern-name Strings and raise `UnknownTagError` / `UnknownPatternError`, so
  the CLI splits on commas and passes through. **Open ambiguity:** a bare CLI
  token must be mapped to a Symbol (tag) or String (pattern name) — resolve tags
  first, fall back to pattern name, and decide what happens if a future pattern
  is ever named the same as a tag.
- **`--placeholder` needs a mode/literal split.** `:tagged`, `:hash`, `:length`,
  `:tagged_length` are Symbols; anything else is a literal String. So
  `--placeholder tagged` is ambiguous with wanting the literal text "tagged".
  Either document the reserved words or add a separate `--placeholder-mode`.
- **Rescue `Errno::EPIPE`** so `data_redactor … | head` doesn't backtrace.
- **Size:** ~200 lines implementation, ~150 spec. "An afternoon" holds.
- **Release:** new public surface ⇒ minor bump (0.18.0), with CHANGELOG, a README
  CLI section, and this entry moved to DONE.md in the shipping commit.

### Error-tracker and job-queue integrations
Meet leaks where they hurt most, on the existing soft-require pattern (~50
lines each):
- **Sentry / Honeybadger / Rollbar** — a `before_send` scrubber that deep-redacts
  the event payload before it leaves the process.
- **Sidekiq** — client/server middleware redacting job arguments before they hit
  Redis and the Sidekiq Web UI.
Each one is also a searchable article title ("Stop leaking PII to Sentry"), so
each integration brings its own audience. Positioning note for the README while
these land: lead with one concrete leak story (a JWT in an exception message, a
card number in a support transcript), not the architecture.

### Path to 1.0
0.x scares exactly the compliance-minded teams the gem targets. Define what 1.0
requires (checksum validation, chunk-boundary fix, the adoption integrations
above, stable API commitment), state it in the README, and cut 1.0 when the
list is done rather than drifting through 0.x forever.

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

### RubyLLM integration — built, parked until 2.0 ships
Branch `feat/ruby-llm-before-request`. Implementation is complete and green; it
cannot merge until `ruby_llm` 2.0 is released (RubyGems is still on 1.16.0, and
their `docs/_reference/upgrading.md` says "2.0 is currently in development").

**What it is.** `Integrations::RubyLLM.chat(...)` (drop-in for `RubyLLM.chat`),
`attach!(target)` (chat / `Agent` / `acts_as_chat` record), and `hook(...)`, all
built on `Chat#before_request` — RubyLLM 2.0's public request hook, which receives
the fully rendered payload as the last step of `Protocol#render` and discards the
callback's return value, so hooks edit the payload in place. Redaction runs through
`DataRedactor.redact_deep!`, added for exactly this contract. **No monkeypatching.**

**Why the old approach is gone.** 0.17.0 prepended `RubyLLM::Protocol#render`
because no public seam existed. Two things settled that:
- **crmne/ruby_llm#765 was closed 2026-08-12** as "superseded by RubyLLM 2.0's
  first-class instrumentation surface". That surface is observe-only —
  `Connection#instrument_request` publishes `{provider:, method:, url:, status:}`
  and the body is not in the event — so it does *not* solve payload rewriting, and
  the `config.faraday_middleware` option will never land. No point pushing further.
- **2.0 shipped the seam under another name** (`before_request`), which is strictly
  better than middleware for us: a mutable Hash, after all provider formatting.

**Bug the rewrite exposed** (worth remembering): a blanket walk of the payload
corrupts `model`. Dated ids like `claude-haiku-4-5-20251001` end in eight digits,
which `dutch_bsn` matches, and the provider then rejects the request. Hence
`skip_keys:` on the deep methods and a `[:model]` default in the hook. The old
`Protocol#render` patch had the same flaw; the fake payload in its spec used
`claude-opus-4-8`, which has no digit run, so it never surfaced. **Only the
opt-in real-gem spec catches this class of bug** — keep it.

**Before merging, when 2.0 releases:**
1. Install real 2.0; run `bundle exec rspec spec/integrations/ruby_llm_spec.rb`
   with no `RUBY_LLM_PATH` (the opt-in example un-skips itself once the installed
   gem has `before_request`).
2. Re-read `Protocol#render` / `apply_before_request_hooks`: hooks still last, return
   values still discarded, payload still a mutable Hash (not pre-serialized JSON).
3. Exercise **tool-call arguments** — the one shape never seen end to end, since they
   are model-generated mid-loop and need a live response. Tool *definitions* were
   verified against real 2.0: `name` and every schema field (`type`, `required`,
   `additionalProperties`, `strict`) survive, and only the human-readable
   `description`s are redacted, which is intended. Residual risk to watch: a tool
   named with an eight-digit run would be redacted and break the call. `:name` is
   deliberately not in the default skip list — it is a common PII key elsewhere, and
   skipping it would leak real names.
4. Decide whether `install!` keeps raising for another release or is deleted.
5. Then: DONE.md entry, wiki RubyLLM-Integration page, version bump, merge.

**Upstream, resolved — crmne/ruby_llm#872** (filed 2026-08-13, fixed by someone
else in PR #876, merged 2026-08-17): `Agent` now delegates `before_request` like
its six sibling callbacks. Our patch was never pushed and is obsolete.

That fix has a sharp edge worth remembering, since it is why `resolve` hops
before it checks. `Agent#chat` is "the wrapped Chat, **or the chat record in Rails
mode**", and the delegation is unconditional — so a Rails-mode agent answers
`respond_to?(:before_request)` with true while the call forwards to a record that
has no such method (`ActiveRecord::ChatMethods` defines none). Resolving to the
real chat first (`chat` hop, then `to_llm`) sidesteps the delegator. Trusting
`respond_to?` first would have raised `NoMethodError` for Rails-mode agents from
2.0 onward, on a path that worked before the upstream fix.

### MCP server (`data_redactor-mcp`)
Expose redaction as a [Model Context Protocol](https://modelcontextprotocol.io)
server so an MCP client — Claude Code (CLI / VS Code extension / desktop), or any
other agent — can call `redact` as a tool. Use case: an agent scrubs secrets/PII
out of text before it logs, pastes, or forwards it.

**No C-code extraction needed.** MCP is just JSON-RPC over stdio (or HTTP); an MCP
server is a small long-lived process that `require "data_redactor"` like any other
consumer and answers `tools/call`. The C extension already *is* a reusable library
(the compiled `.so` behind the gem) — the server links it transitively by depending
on the gem. So this does **not** require splitting the engine out; the request's
premise that it might is the thing to note and dismiss here.

Shape (when started):
- New entrypoint (likely a separate gem `data_redactor-mcp`, or a `bin/` + extra
  in the same repo) so the core gem keeps **zero runtime deps** — an MCP SDK is a
  dependency, and it must not leak into the pure gem (CLAUDE.md: "no runtime gem
  dependencies"). Soft-require / separate-gem pattern, same as the integrations.
- One tool, `redact`, params: `text` (required), `only`/`except` (tag filters),
  `placeholder` — forwards straight to `DataRedactor.redact`. Optionally a
  `redact_json` tool for structured payloads.
- Stateless, read-only, returns a copy (the gem already guarantees this) — no
  filesystem or network surface, which keeps it safe to register as an MCP server.
- Decide the SDK: official Ruby MCP SDK if mature enough, else hand-roll the
  JSON-RPC loop over stdin/stdout (small, and keeps the dep surface tiny).

Open question: is this worth a tool when a caller can already `require` the gem
directly? Value is only for **agent** workflows where the consumer is an LLM that
can't run Ruby inline but can call MCP tools. Defer until that workflow is real.

### Rack `:env_logs` surface
Scrub `PATH_INFO` / `QUERY_STRING` for downstream access loggers. Deferred — needs
to wrap the upstream logger rather than mutate env, which has blocked the design.

### Possible Erlang / Elixir port (and the standalone C library that gates it)
The C core is portable; the Ruby-specific layer is thin. **Verdict unchanged:
defer until the Ruby gem has real adoption and someone asks** — a second ecosystem
doubles maintenance (separate CI, Hex publishing, NIF safety story) while the
distribution problem repeats there identically. Researched detail (2026-07) so the
option isn't re-investigated:

- **Registry / tooling:** [Hex](https://hex.pm) is the RubyGems of both Erlang and
  Elixir (`mix` ≈ bundler+rake; `rebar3` for Erlang); docs auto-hosted on
  [hexdocs.pm](https://hexdocs.pm). Package name would be `data_redactor_ex`.
- **Three shapes, in increasing order of preference:**
  1. *Pure Elixir over `:re`* (Erlang's PCRE binding) — no C, no crash risk, least
     work, but abandons the single-pass v19 engine, i.e. the differentiator.
  2. *NIF (`erl_nif.h`)* — the BEAM's C extension. The engine is unusually ready:
     NIFs run concurrently on many scheduler threads, so they require the per-call
     re-entrancy shipped in 0.17.1, and long scans must run on **dirty schedulers**
     (`ERL_NIF_DIRTY_JOB_CPU_BOUND`) — the exact analog of the GVL-release work.
     Blast radius is worse than Ruby: a NIF segfault kills the whole BEAM VM, no
     rescue — the ASan/fuzz CI gate is what makes this thinkable. Precompiled
     distribution exists (`elixir_make` + checksummed prebuilt artifacts, analog of
     the rake-compiler-dock native gems).
  3. *Extract `libdataredactor` first (do this before any binding).* The engine
     already compiles without Ruby — the alloc-gate and ASan CI jobs build
     `matcher.c` standalone daily, so the seam is proven. A plain C library
     (engine + pattern tables + a small `dr_redact()`/`dr_scan()` API) makes every
     binding thin: Elixir NIF, Python cffi, Node N-API, the CLI.
- **Market note:** Elixir has almost no redaction tooling (thin competition, small
  audience); Python already has Microsoft Presidio (huge audience, entrenched
  competitor). Elixir-via-NIF is the more winnable port; the
  standalone-C-library-first ordering serves both.

---

## Paper

Research log at `docs/research_log.md` is the source of truth (all prototype data,
benchmark methodology, root-cause analysis, related work, open questions).

Draft lives in `paper/main.tex` (acmart). **Submitted to Software: Practice and
Experience** on 2026-06-19 as an Experience Report — **Manuscript ID 7985366**,
status "In Screening" (Wiley submission ID 9f2cb74b-c51a-4e47-b5b2-12bb9b7085f6).
The exact submitted snapshot is git tag `paper-spe-submit`. See DONE.md "Paper".

### Open
1. **Wait for the S:P&E editorial decision** (screening → review, ~6–12 mo). The
   submission cannot be edited unless returned. If returned/revise: upload the
   revised PDF + the editable `.tex` source (Wiley wants source at revision stage),
   tag `paper-spe-r1`, and respond to reviews.
2. **arXiv: blocked for now.** A first submission needs endorsement, and the author
   has no institutional email and no endorser, so all CS categories are gated. Revisit
   once there is an endorser (e.g. after acceptance, or a willing established arXiv
   author). S:P&E permits a preprint, so this can be added later; if posted, update
   the preprint with a link to the published article.
3. If S:P&E rejects on scope/novelty: retarget **USENIX ATC** (experience report
   track) or another practice venue.

### Versioning across the submission pipeline
The paper is **not** versioned in the PDF (nothing to go stale) and is **not** tied
to the gem's SemVer. Version provenance is tracked three ways:
- **git tags** at each external milestone — the precise snapshot of what was uploaded:
  `paper-arxiv-v1`, `paper-spe-submit`, `paper-spe-r1`, `paper-arxiv-v2`, …
- **arXiv** assigns the public `vN` on every replacement (canonical citable version).
- each **journal** assigns its own manuscript ID + revision rounds (R1, R2).
Workflow: tag → upload to arXiv (`paper-arxiv-v1`); revise for a journal → reformat to
its template → tag (`paper-spe-submit`) → submit; if a revision is substantial, also
push it back to arXiv (becomes `v2`) and tag `paper-arxiv-v2`.

**Shape:** systems/experience report, ~14 pages. Core thesis: engine replacement in
production is a constrained search, not a benchmark — the fastest engine is not the
shippable one. Cites Hyperscan (NSDI 2019), BLARE (PACMMOD 2023). HybridSA (OOPSLA
2024), RE\# (POPL 2025), and PCRE-JIT (CGO 2014) are verified leads, kept uncited.

---

## Promotion & adoption

**Lesson (2026-07): the Medium article shipped and got essentially no readers.**
Medium has no built-in Ruby audience — publishing there is publishing into the
void. Distribution beats content: the article must go where Ruby readers already
are, and it lands better when the gem has its adoption features in place. New
strategy, in order:

**Progress:** ready-to-send drafts for every Step 2 channel exist locally in
`drafts/outreach.md` (gitignored). Posted so far: RubyFlow, 2026-07-14 —
<https://rubyflow.com/p/tesaty-dataredactor-stop-secrets-and-personal-data-leaking-into-logs-and-llm-prompts>.

### Step 1 — land the adoption features first
Do these before the next outreach push, so a visitor who clicks through finds a
gem that installs itself and proves its claims (each has a full entry under
Features):
(The Rails Railtie, the biggest lever, has shipped — see DONE.md.)
1. CLI executable — makes every demo a one-liner.
2. Checksum validation (#7) + published false-positive numbers.
3. Error-tracker / Sidekiq integrations — each one brings its own audience.
4. README positioning: lead with a concrete leak story and the
   "`filter_parameters` only filters keys you name" pitch, not the architecture.
5. State the path to 1.0.

### RubyLLM post — write it when 0.18.0 ships
The rebuilt RubyLLM integration deserves its own post, and it has a story the
generic "stop leaking secrets" pitch does not: **tool results**. An agent reads a
file or runs a command, the output is inlined into the *next* request, and the
user never typed it — so per-call redaction cannot reach it, and only a request
hook can. That is a concrete leak most RubyLLM users have not thought about.

Angle notes for the draft:
- Lead with the agent tool-result leak, not the API.
- The blanket-redaction bug is a good, honest detail: redacting the whole payload
  corrupts dated model ids (`claude-haiku-4-5-20251001` → the eight-digit suffix
  matches a national-ID pattern), which is why `skip_keys:` exists.
- Timing matters: the post only makes sense once `ruby_llm` 2.0 is released and
  0.18.0 is out, since the integration needs the 2.0 `before_request` hook.
- Cross-post per the Step 2 channel order below; drafts live in
  `drafts/outreach.md` (gitignored).

### Step 2 — coordinated outreach round (one week, all channels at once)
- **Cross-post the Medium article to [dev.to](https://dev.to)** (set the
  canonical URL to Medium) — dev.to's `#ruby` tag has organic readership Medium
  lacks. Same for future posts: dev.to first, Medium second.
- Submit to [Ruby Weekly](https://rubyweekly.com) and
  [Short Ruby Newsletter](https://newsletter.shortruby.com) — a newsletter
  mention is worth more than a month of Medium.
- Submit to [The Ruby Toolbox](https://www.ruby-toolbox.com) and PR the gem into
  [awesome-ruby](https://github.com/markets/awesome-ruby).
- **Get listed in RubyLLM's ecosystem/docs** — a PR or issue proposing
  data_redactor in their README/docs as the redaction companion. Their users are
  the exact audience, and the #765 thread is already a warm contact.
- Post to r/ruby and r/rails — ask for pattern feedback, don't just sell it.
- Show HN — the C-extension performance work + the paper is a strong
  "Show HN: I replaced a regex engine and wrote a paper about it" story.
- Pitch podcasts: Remote Ruby, The Bike Shed, Ruby Rogues — the engine-replacement
  story is guest material, not just a plug.
- Answer Stack Overflow / Reddit questions on log scrubbing, `filter_parameters`
  gaps, and PII in LLM prompts where the gem is genuinely the answer.
- Offer a 5-minute lightning talk at a local/virtual Ruby meetup; consider a
  RubyConf / EuRuKo CFP with the paper's story.
- Announce on X / Mastodon (ruby.social) with `#ruby` `#rails`.

**Ongoing:** keep CHANGELOG current; respond to issues/PRs promptly; track
RubyGems download stats after each channel to learn which ones convert.

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
