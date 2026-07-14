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

### Close the chunk-boundary redaction miss
`_chunk_bytes` falls back to a hard 64 KB split when a single line exceeds
`CHUNK_SIZE`, so a token straddling that split escapes redaction. Documented as a
limitation, but for a security tool a silent miss is the worst failure mode. Fix:
at the no-newline fallback split only, re-scan an overlap window (longest-pattern
length) spanning the boundary, or back the split off to the nearest non-token byte.
Cheap, and a stepping stone to the streaming API (#8) which has the same
boundary problem in general form.

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

- **Back the Ruby 2.7 floor with CI** — the gemspec claims `>= 2.7` but the
  matrix only tests 3.1–3.4, so the floor is an untested promise (2.7 users get
  the source gem; precompiled binaries are 3.1+ only). Add `2.7` and `3.0` to the
  test matrix. Keeping the floor is deliberate: legacy Rails apps stuck on old
  Rubies are prime candidates for log redaction. If the old rubies can't be kept
  green cheaply (dev-dep resolution, C-API drift), raise the floor to 3.1 instead
  — either way the claim and the matrix must agree.

- **ruby-head / 3.5-preview CI job (allow-failure)** — Ruby 3.5 ships December
  2026 and the native-gem matrix must support it on day one. An allow-failure
  `ruby-head` entry in the test matrix gives months of warning on C-API or
  stdlib breakage instead of a release-week scramble.

- **Split `spec/data_redactor_spec.rb`** — 1,800+ lines in one file. Integration
  specs already live in `spec/integrations/`; split the main file by concern
  (patterns / filtering / placeholders / deep-walk / custom patterns / chunking)
  and update the CLAUDE.md testing note when done.

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

### Rails Railtie — zero-config onboarding (adoption lever #1)
Today every integration is a manual opt-in; Rails devs adopt what installs
itself. Ship a Railtie that, on `require "data_redactor/railtie"` (or a separate
`data_redactor-rails` gem to keep the zero-runtime-deps rule), automatically
wires the Logger formatter and `filter_parameters`, configurable via an
initializer. The pitch writes itself: *`filter_parameters` only redacts keys you
name; data_redactor catches the card number inside an exception message — free
text you can't enumerate.* Rails is where the buyers are (GDPR/PCI compliance
teams); one Gemfile line to value is the single biggest adoption gap.

### CLI executable (`exe/data_redactor`)
Read stdin, write redacted stdout; flags mirroring `only:`/`except:`/
`placeholder:`, plus `--scan` for audit JSON. Makes the gem demoable to people
who never write Ruby — `kubectl logs … | data_redactor`, CI log scrubbing, a
pre-push hook — and turns every promotion post's demo into one shell line. No
new deps; an afternoon of work on the existing API.

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
2. **Faraday request middleware (needs an upstream unlock — preferred path).**
   Insert a `request` middleware that redacts the JSON request body on the wire —
   catches user prompts, the `system` prompt, AND tool-call arguments for *every*
   provider. But `setup_middleware` is private and there's no public injection
   point, so this is gated on upstream adding one (#765). Build the middleware on
   the existing `Claude`/`OpenAI` shape walkers (`deep_copy` → walk →
   `redact_text_blocks` → re-serialise). **Caveat from the #765 body:** their
   design runs user middleware "after JSON encoding, just before the adapter" — so
   on the request path we'd get the **already-serialized JSON string**, not the
   Hash (parse → redact → re-serialise; workable but less clean). Our #765 comment
   asks them to guarantee pre-`request :json` (Hash) ordering instead.
3. **Monkeypatch (SHIPPED 0.17.0 — `Integrations::RubyLLM.install!`).** Prepends
   `RubyLLM::Protocol#render` and deep-redacts the rendered payload before it's
   posted; covers all providers + tool results, version-pinned + fail-fast. See
   DONE.md for the rationale (why `Protocol#render`, the base64 limitation, why it's
   opt-in). This is the transparent fallback until #765 lands; once it does, hook #2
   replaces it. Reference — how the three observability gems patch (verified
   2026-06-21): sinaptia aliases `Chat#complete`, thoughtbot prepends
   `Chat`/`Embedding`, llm_cost_tracker prepends `Provider`. All observe-only; none
   rewrite the payload, so none were a usable template — we patch `Protocol#render`
   (lower, post-render) instead.

   **Upstream issue: crmne/ruby_llm#765** ("[FEATURE] Expose
   `config.faraday_middleware` so observability gems can stop monkey-patching",
   opened 2026-05-09). The reporter (sergey-homenko) posted a complete
   implementation on 2026-05-11 — `option :faraday_middleware, -> { [] }` in
   `configuration.rb` + a private `apply_user_middleware(faraday)` in
   `connection.rb` called after `setup_middleware`, with specs. He's "happy to ship
   on your OK." One naming question raised: `faraday_middleware` (honest, locks API
   to Faraday) vs `connection_middleware` (neutral). For us the name is irrelevant —
   we run on the *request* side, not his response-side `:llm_errors` concern.
   **Status (verified 2026-06-21): NOT in `main`, issue reopened.** On 2026-06-20
   crmne commented "It's already implemented in main", closed #765 as completed,
   then **reopened it one minute later** — so the "completed" is walked back. Reading
   `crmne/ruby_llm@main` directly: `connection.rb`'s `setup_middleware` is still
   **hardcoded and private** (no `apply_user_middleware`, no loop over user
   middleware); `configuration.rb` has **no `faraday_middleware`/`connection_middleware`
   option**. What *is* in main and probably prompted "already implemented" is the
   read-only **`instrumenter` hook** (`option :instrumenter` + `RubyLLM.instrument(
   'request.ruby_llm', …)` wrapping every `post`/`get`). That's an
   ActiveSupport-notifications-style observability seam — it covers the *observability*
   gems' reading use-case but is **observe-only: it cannot rewrite the outbound
   payload**, which is exactly ours. The mismatch is the likely reason for the reopen.
   **What we still need from #765 specifically: request-side ordering.** Faraday
   middleware is bidirectional (outer = first on request, last on response). Our
   request-phase middleware must see the payload *before* `request :json` serializes
   it (ideally as the Hash). The `instrumenter` hook does not give that; only the
   `faraday_middleware` option (run ahead of the JSON encoder) does.
   **Commented on #765 (2026-06-20)** — framed as a payload-rewrite use-case (no
   redaction/gem disclosure), asked for the request-side ordering guarantee, and
   asked whether a branch/PR exists. crmne replied + reopened (above); next: a short
   follow-up clarifying that `instrument` is observe-only so the payload-mutation
   gap remains, offer to PR the `faraday_middleware` shape. Drop the gem link later
   as a natural second bump once the integration ships.
   **Do NOT block the integration on it.** Hook #2 ships first regardless; once #765
   lands, hook #1 is a thin middleware on the existing shape walkers.

Specs: a fake Faraday stack (or recorded RubyLLM request body) asserting prompts,
system prompt, and tool args are scrubbed outbound and responses are untouched;
plus a negative test that a clean payload round-trips byte-identical. Open
question to resolve at build time: exact RubyLLM version that stabilised the
middleware/config-registration API (pin the minimum in the integration's doc
comment, not the gemspec).

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

## Promotion & adoption

**Lesson (2026-07): the Medium article shipped and got essentially no readers.**
Medium has no built-in Ruby audience — publishing there is publishing into the
void. Distribution beats content: the article must go where Ruby readers already
are, and it lands better when the gem has its adoption features in place. New
strategy, in order:

### Step 1 — land the adoption features first
Do these before the next outreach push, so a visitor who clicks through finds a
gem that installs itself and proves its claims (each has a full entry under
Features):
1. Rails Railtie (zero-config onboarding) — the biggest lever.
2. CLI executable — makes every demo a one-liner.
3. Checksum validation (#7) + published false-positive numbers.
4. Error-tracker / Sidekiq integrations — each one brings its own audience.
5. README positioning: lead with a concrete leak story and the
   "`filter_parameters` only filters keys you name" pitch, not the architecture.
6. State the path to 1.0.

### Step 2 — coordinated outreach round (one week, all channels at once)
- **Cross-post the Medium article to [dev.to](https://dev.to)** (set the
  canonical URL to Medium) — dev.to's `#ruby` tag has organic readership Medium
  lacks. Same for future posts: dev.to first, Medium second.
- Post to [RubyFlow](https://rubyflow.com) — the community link blog newsletters
  trawl for content.
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
