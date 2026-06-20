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

- **musl load-and-smoke across a Ruby matrix** (optional) — the `musl-load` job
  already `require`s the gem and smoke-tests redaction on `ruby:3.3-alpine`
  (the load-and-smoke class is covered). Widening it to a `3.1`–`3.4` Alpine
  matrix would catch a musl regcomp divergence that is Ruby-version specific.
  Nice-to-have, not blocking.

---

## Features (roadmap, not yet started)

### Checksum validation (#7)
Massive false-positive killer; apply only when the structural regex already
matched: Luhn (credit cards), mod-97 (IBANs), Italian Codice Fiscale check char,
Spanish DNI letter, Brazilian CPF/CNPJ, PESEL, CNP, etc. Probably an opt-in
per-call flag (`strict: true`) since validation costs CPU.

- **Re-check the spaced-card vs Aadhaar collision after checksums land.** A
  space-grouped credit card `4111 1111 1111 1111` currently matches
  `indian_aadhaar` (national_id) on its first 12 digits, NOT `credit_card`
  (financial) — the unspaced `4111111111111111` matches credit_card correctly.
  (Found 2026-06-20 while writing `examples/ruby_llm.rb`.) Luhn (card) +
  Verhoeff (Aadhaar) validation should disambiguate: the spaced form's 16 digits
  pass Luhn as a Visa card, and the 12-digit Aadhaar slice would fail Verhoeff.
  Verify this resolves once #7 is in; if not, may need ordering/anchoring work.

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

### RubyLLM integration (auto-interception)
RubyLLM (`ruby_llm`, crmne) is a unified, Faraday-based client across every LLM
provider, with strong traction. It has lifecycle hooks (`on_new_message`,
`before_tool_call`, `with_params`) but **no redaction of its own** — scrubbing is
left to the caller. The shipped `Claude`/`OpenAI` adapters already redact LLM
payloads, but **passively**: the caller must remember to wrap each request. The
value RubyLLM adds is hooking *once* to cover every provider automatically.

New opt-in file `lib/data_redactor/integrations/ruby_llm.rb`
(`require "data_redactor/integrations/ruby_llm"`), soft-require pattern, no
gemspec dependency on `ruby_llm`. **Outbound only** (scrub what we send TO the
provider; do not touch responses). Reuse `LLMSupport` (`deep_copy`, `fetch`/`put`,
`redact_text_blocks`) and forward `only:`/`except:`/`placeholder:`.

**No dependency on the streaming items above.** Streaming concerns the *inbound*
response arriving in chunks; the request body is sent as one buffered JSON payload
even when the response streams, so an outbound hook always sees the full body — no
chunk-boundary problem. The `redact_stream` / `mm_scan_chunk` work is only needed
if inbound (streamed-response) redaction is ever added, which is out of scope here.

**On ship: write up the integration** as a LinkedIn + Medium post (see the
Promotion section). RubyLLM has momentum; "auto-redact secrets/PII before they
reach any LLM provider, in one require" is a strong, timely hook.

**Investigated 2026-06-20 — no public Faraday-middleware hook exists.** RubyLLM
builds its connection entirely inside `Connection#initialize`
(`Faraday.new { ... setup_middleware(faraday) ... }`, `lib/ruby_llm/connection.rb`)
with no yield/block or config option to inject external middleware.
v1.14.0 added *self-registered config options* (providers declare
`<slug>_<option>` keys — a good precedent for our own config key) and a
*configurable Faraday adapter* (`config.faraday_adapter`), but neither lets a
third party add a middleware. So hook #1 below is NOT a clean ~30-line job today;
the realistic plan inverts the original priority.

**Most non-prompt content IS reachable today without patching RubyLLM** (verified
2026-06-20 against current `Chat`). The public API exposes more than the prompt:
- `attr_reader :messages` — the full message array, *including the system message*
  (`with_instructions` stores it as a `Message`); readable and mutable.
- `with_instructions(text, append:)` — wrap to redact the system prompt at set time.
- **CORRECTION (verified 2026-06-20 against `ruby_llm 1.16.0` source): the
  `before_*`/`after_*` callbacks CANNOT do outbound redaction.** In
  `chat.rb#complete_once`, `before_message` fires *after* `provider_completion`
  (request already sent) AND receives **no message argument**; `run_callbacks`
  discards return values, so all callbacks are **observe-only**. They concern the
  *response/agentic loop*, not the outbound request. There is **no public callback
  that exposes the outbound request body before send.**
- `render` builds the full payload (`@provider.render(messages, tools:, params:,
  schema:, ...)`) but is read-only from outside — there's no public seam to mutate
  its *result* before the connection. That seam is exactly what #765/middleware adds.

So the ONLY reliable public outbound mechanism today is **redact `chat.messages` +
the system message BEFORE calling `ask`/`complete`** — a manual pre-send helper,
not an auto-hook. (`messages` is a public, mutable accessor; `render` reads from it.)

The message-layer ↔ middleware gap, restated honestly:
- Reachable now (pre-send, manual): user prompt, **system prompt**, conversation
  history. Tool-call *arguments* are model-generated mid-loop, so they're only
  scrubbable outbound via the middleware.
- Genuinely needs #765/middleware: transparent auto-interception of the *final
  assembled wire body* (incl. tool args + provider-injected fields) in ONE
  chokepoint, with no manual call.
- Mutating `chat.messages` in place **alters the stored conversation** — the redacted
  text becomes the history for all future turns. Desirable for outbound safety, but
  it's a semantic choice (scrubbing the record), so the helper should default to a
  copy and offer an in-place `!` variant.

**FULL SEND-PATH TRACE (verified 2026-06-20 against `ruby_llm 1.16.0`, line by
line — do not re-investigate).** `ask` → `complete` → `instrument_completion` →
`complete_once` → `provider_completion` → `@provider.complete(messages, ...)`
where `payload = Utils.deep_merge(render_payload(messages, ...), params)` is built
and handed straight to `sync_response`/`stream_response` → `connection.post(url,
payload)` → Faraday (`request :json`). Findings after checking EVERY method on
`Chat`/`Provider`/`Connection`:
- **No public mutation seam between body-build and send.** `render_payload` runs
  inside the provider and `post` follows immediately; intercepting means
  subclassing `provider.complete`/`connection.post` = monkeypatch (ruled out).
- `instrument_completion` exposes `input_messages` but as a `.dup`, observe-only
  (ActiveSupport-notifications instrumentation, not mutation).
- `with_params(**)` deep-merges INTO the final body — real, but **add/override
  only**; can't read-and-rewrite existing message text. Dead end for redaction.
- Callbacks: observe-only (established above).
- **Conclusion: the only outbound seam anyone can add is at Faraday = #765.** Until
  then, scrub `chat.messages` + system BEFORE `ask` is the sole public path.

**ARCHITECTURE DECISION (2026-06-20): ONE integration, two modes — not two files.**
Both modes share the redaction core + payload shape-walking; they differ only in
*where* the data is grabbed (messages array vs Faraday body). Build one file
`lib/data_redactor/integrations/ruby_llm.rb`:
- **Now (message mode):** `RubyLLM.redact_messages(messages, ...)` and
  `RubyLLM.redact_chat(chat, ...)` (returns a scrubbed copy; `redact_chat!` mutates
  in place). Manual pre-send call. Works on `ruby_llm` 1.15+ today, public API only.
- **Later, additive (middleware mode), when #765 lands:** add
  `RubyLLM.middleware`/`RubyLLM.install!(config)` to the SAME module, reusing the
  SAME private payload-walker. New methods, no breaking change (Open/Closed). Do
  NOT make a second integration file — that would duplicate the body walker.

Two hook points:
1. **Message-layer pre-send helper (ship NOW — public, stable).** `redact_messages`
   / `redact_chat` scrub the messages array + system prompt before `ask`. Manual
   call (callbacks can't auto-intercept outbound — see correction above). Won't
   break on RubyLLM internals. Covers prompt + system + history; NOT tool args /
   wire body.
2. **Faraday request middleware (needs an upstream unlock — no monkeypatch).**
   Insert a `request` middleware that redacts the JSON request body on the wire —
   catches user prompts, the `system` prompt, AND tool-call arguments for *every*
   provider. But `setup_middleware` is private and there's no public injection
   point, so this is gated on upstream adding one. **Monkeypatching is ruled out.**
   Build the middleware on the existing `Claude`/`OpenAI` shape walkers
   (`deep_copy` → walk → `redact_text_blocks` → re-serialise).

   **Upstream issue already exists AND is PR-ready: crmne/ruby_llm#765**
   ("[FEATURE] Expose `config.faraday_middleware` so observability gems can stop
   monkey-patching", opened 2026-05-09). The reporter (sergey-homenko) posted a
   complete implementation on 2026-05-11 — `option :faraday_middleware, -> { [] }`
   in `configuration.rb` + a private `apply_user_middleware(faraday)` in
   `connection.rb` called from `initialize` after `setup_middleware` (so user
   middleware sits outside `:llm_errors`), with specs in
   `spec/ruby_llm/connection_middleware_spec.rb`. He's "happy to ship on your OK."
   **Bottleneck = maintainer sign-off, not code.** One open naming question he
   raised: `faraday_middleware` (honest, locks API to Faraday) vs
   `connection_middleware` (neutral). For us the name is irrelevant — we run on the
   *request* side (his `:llm_errors`/raw-response note is response-side, which we
   don't touch, being outbound-only).
   **No PR exists yet** (verified 2026-06-20: sergey has no `ruby_llm` fork, zero
   PRs on the repo; #765 is code-in-a-comment awaiting crmne's OK before he forks).
   His use-case is **observability** (he maintains `llm_cost_tracker`), so his
   design is **response-biased** — he justifies the "after `setup_middleware`"
   placement only in terms of seeing raw responses outside `:llm_errors`. **What we
   under-specified for: request-side ordering.** Faraday middleware is
   bidirectional and ordering means opposite things per direction (outer = first on
   request, last on response). We need our request-phase middleware to see the
   payload *before* `request :json` serializes it (ideally as the Hash). Ask him to
   make that a stated guarantee + test, not incidental.
   **Commented on #765 (2026-06-20)** — framed as a payload-rewrite use-case (no
   redaction/gem disclosure), asked for the request-side ordering guarantee (request
   middleware runs ahead of `request :json` so it sees the Hash, not just response
   middleware outside `:llm_errors`), and asked whether a branch/PR exists or it's
   still awaiting sign-off. Awaiting reply. Drop the gem link later as a natural
   second bump once the integration ships.
   **Do NOT block the integration on it.** Hook #2 ships first regardless; once #765
   lands, hook #1 is a thin middleware on the existing shape walkers.

Specs: a fake Faraday stack (or recorded RubyLLM request body) asserting prompts,
system prompt, and tool args are scrubbed outbound and responses are untouched;
plus a negative test that a clean payload round-trips byte-identical. Open
question to resolve at build time: exact RubyLLM version that stabilised the
middleware/config-registration API (pin the minimum in the integration's doc
comment, not the gemspec).

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

## Promotion (post-publish visibility)

- Submit to [The Ruby Toolbox](https://www.ruby-toolbox.com).
- Post to r/ruby and r/rails — ask for feedback, don't just sell it.
- Write a short DEV/Medium article: "Why I built a C-extension PII redactor for
  Ruby" (the C vs pure-Ruby angle is the hook).
- **If/when the RubyLLM integration ships** (see "RubyLLM integration" under
  Features): write a LinkedIn post **and** a Medium article on it — angle:
  "auto-redact secrets & PII before they reach any LLM provider, in one require."
  RubyLLM's traction makes this a timely hook; lead with the one-line opt-in and
  a before/after of a leaked prompt.
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
