# TODO

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

### 12. Name-pattern helper (planned for 0.8.0)

Helper to generate a custom pattern from a person's name covering common variations. Names can't ship as built-ins (every team has different ones), but the pattern-construction logic is the same boilerplate everyone re-derives.

**Proposed API:**

```ruby
DataRedactor.name_pattern("Mario", "Rossi")
# => returns a String regex (POSIX ERE) ready to pass to add_pattern

DataRedactor.add_pattern(
  name: "person_mario_rossi",
  regex: DataRedactor.name_pattern("Mario", "Rossi"),
  tag:   :contact
)
```

**Variations to cover** (all confirmed in scope by user):

1. **Order swap** — `Mario Rossi`, `Rossi Mario`, `Rossi, Mario`, `Rossi,Mario`
2. **Initials** — `M. Rossi`, `M Rossi`, `Mario R.`, `Mario R`, `M.R.`, `MR`, `M. R.`
3. **Case-insensitive matching** — POSIX ERE has no `/i` flag, so build per-letter alternations: `[Mm][Aa][Rr][Ii][Oo]` (or `[mM][aA]...` — same thing). Apply uniformly to first AND last name. Increases pattern length but is the only way without engine support.
4. **Diacritics tolerance** — when input contains accented characters (`é`, `ñ`, `ü`, `ç`, `ø`...), also match the unaccented form. Implement by mapping each accented char to a `[éeÉE]`-style class. ASCII-only inputs skip this step.

**Open design questions:**

- Multi-part last names (`Van der Berg`, `García Marquez`)? Treat space as `[ ]?` between parts, or require canonical spacing?
- Middle names (`Mario Luigi Rossi`)? Probably accept optional `(Luigi )?` between first and last — or take an explicit `middle:` kwarg.
- Hyphens vs spaces (`Anne-Marie` vs `Anne Marie`)? Make hyphens match `[ -]?`.
- Word boundaries: wrap with the existing boundary-wrap mechanism (`boundary: true`)? Probably yes by default — otherwise `Mario` matches inside `Mariolino`. But boundary-wrapped patterns reject capture groups, so the alternation would have to use `(?:...)` — which POSIX ERE doesn't support either. May need to expose a non-capturing alternation builder, or relax the no-capture-groups rule for this helper specifically.
- Output as `String` (POSIX ERE) or `Regexp`? `String` is simpler and matches what `add_pattern` already accepts.
- Where to put the implementation: pure Ruby in `lib/data_redactor/name_pattern.rb` — no need for C since this runs at registration time, not on the hot path.

**Test plan:**

Roundtrip via `add_pattern` and assert that each canonical variant gets redacted and that obvious non-matches (`marioland`, `Maria Rossi`, `Mariolino Rossini`) do not.

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

Current `redact` runs each pattern over a fresh working buffer, copying non-matching segments and `realloc`ing as needed. That's correct but allocation-heavy. Things to try, roughly in order of expected payoff:

- **Single-pass, two-buffer ping-pong** — keep two buffers alive across patterns and swap pointers instead of `malloc`/`free`-ing per pattern. Saves `NUM_PATTERNS - 1` allocation pairs per call.
- **Initial buffer sizing from input length** (currently grows from a small starting size) — `malloc(input_len + slack)` upfront avoids early `realloc`s for typical payloads.
- **Skip patterns with no possible match** — quick `memchr` for a required literal (e.g. `sk_live_` for Stripe, `AKIA` for AWS, `BEGIN ` for PEM) before invoking `regexec`. For most inputs most patterns won't match — bailing without `regexec` is a big win.
- **`REG_NOSUB` where we don't need capture groups** — non-boundary patterns currently request unused match info.
- **Replace `strdup`/`strncpy` chains with direct `memcpy` into a known-size output buffer** — fewer C-library calls, simpler escape analysis for the compiler.
- **Reuse the same allocation across `redact` *calls*** — process-local thread-local buffer (after [Full thread safety](#full-thread-safety) lands) reset to length 0 between calls. Eliminates allocation entirely on the hot path.
- **Branch-free `write_placeholder` for the plain mode** — the common case is one `memcpy` of a fixed-size string; specialize it.
- **Profile first** — wire up `benchmark/throughput.rb` (see [Benchmarks](#benchmarks)) and `perf` / `Instruments` before changing code. Optimize the actual hot spot, not the assumed one.

**Why:** the C extension is the gem's selling point. Beating pure-Ruby `gsub` by 2× isn't impressive; beating it by 20× is. Allocation is almost certainly the bottleneck — `regcomp` is a one-time cost, `regexec` is fast, `malloc` per pattern per call is not.

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

Add a `benchmark/` directory with scripts using `benchmark-ips` and `benchmark/memory`:

- `benchmark/throughput.rb` — MB/s on representative payloads (log line, JSON blob, 1MB log file, 10MB log file)
- `benchmark/per_pattern.rb` — cost of each pattern in isolation, to spot the expensive ones
- `benchmark/vs_pure_ruby.rb` — head-to-head against a pure-Ruby `gsub` loop with the same patterns, to demonstrate the C extension's value
- `benchmark/vs_alternatives.rb` — vs. existing gems (e.g. `pii-redactor`, `personally_identifiable_information`) on the same input
- `benchmark/scaling.rb` — runtime vs. input size (1KB → 100MB) to confirm linear scaling

Publish numbers in the README — the C extension is the differentiator and the current README does not show it off.

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
