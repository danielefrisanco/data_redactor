# TODO

## References
- https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- https://github.com/advanced-security/secret-scanning-custom-patterns
- https://github.com/gitleaks/gitleaks/tree/master

## Additional patterns to add (from former plan.md)

Distinctive-prefix API keys with low false-positive risk — easy wins once the tag system (item 1 below) lands so they can be grouped under `:credentials`:

- Anthropic API Key (`sk-ant-api03-...`)
- OpenAI API Key (`sk-proj-...`)
- GitLab PAT (`glpat-...`)
- DigitalOcean PAT (`dop_v1_...`)
- Heroku API Key
- Databricks API Token (`dapi...`)
- Okta API Token
- Azure SQL hostname
- DataDog API Key (needs context prefix to avoid FPs)
- Sentry DSN
- PagerDuty API Key

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

### 5. Hash / JSON / object traversal
Pure-Ruby walker on top of the C `redact`:

```ruby
DataRedactor.redact_deep(params_hash)
DataRedactor.redact_json(json_string)
```

### 6. Allowlist / ignore list
Escape hatch for the broad patterns we already flag (40-char base64, 9-digit passport, etc.):

```ruby
DataRedactor.redact(text, ignore: [/example\.com/, "test@foo.com"])
```

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

### 9. Rails / Rack integration
What turns "neat gem" into "we put it in production":
- `Logger` formatter that wraps messages
- `Rails.application.config.filter_parameters` adapter
- Rack middleware that scrubs request/response bodies

### 10. Distribution / quality of life
- ~~Publish to RubyGems~~ ✅ DONE — 0.5.0 published 2026-05-08
- ~~CI matrix: Ruby 2.7, 3.0, 3.1, 3.2, 3.3 on Linux + macOS~~ ✅ DONE — `.github/workflows/ci.yml` tests Ruby 3.1/3.2/3.3, builds gem, publishes via OIDC on release
- ~~RubyGems OIDC trusted publisher setup~~ ✅ DONE
- ~~YARD inline documentation~~ ✅ DONE — `@param`/`@return`/`@raise` for all public methods; `bundle exec yard doc` is 100% documented. Deferred: GitHub Pages deploy job in `ci.yml`.
- ~~Thread-safety note in README~~ ✅ DONE
- ~~Shields.io badges in README~~ ✅ DONE — gem version, CI build, license
- Precompiled binaries via `rake-compiler-dock` so `gem install` doesn't need a C toolchain — biggest reason people skip C-extension gems
- ~~CHANGELOG.md + semver commitment~~ ✅ DONE in 0.1.0
- Demo / example script (`examples/rails_logger.rb` or similar) showing real-world usage
- GitHub Pages deploy job for YARD docs (currently disabled; would need a separate job after YARD docs are stable)

## C extension refactor

`ext/data_redactor/data_redactor.c` is a single ~1000-line file. Split it into focused modules before it grows further:

- `patterns.h` / `patterns.c` — `pattern_strings[]`, `boundary_wrapped[]`, `pattern_tags[]`, `pattern_names[]`, `NUM_PATTERNS`. Pure data, no Ruby API.
- `placeholder.h` / `placeholder.c` — `placeholder_t`, `PLACEHOLDER_MODE_*` constants, `write_placeholder`, `max_placeholder_len`, `djb2`, `tag_name_for_bit`.
- `custom_patterns.h` / `custom_patterns.c` — `custom_pattern_t` struct, dynamic array (`custom_patterns`, `custom_count`, `custom_cap`), `find_custom_by_name`, `free_custom_at`, and the four Ruby-facing C functions (`rb_add_pattern`, `rb_remove_pattern`, `rb_clear_custom_patterns`, `rb_custom_patterns`).
- `redact.h` / `redact.c` — `replace_all_matches`, `rb_data_redactor_redact`, `wrap_boundary`.
- `scan.h` / `scan.c` — `rb_data_redactor_scan` and the replacement-log logic.
- `data_redactor.c` — kept as the thin entry point: `#include` all headers, `Init_data_redactor` only.

`extconf.rb` will need to list each `.c` file via `$srcs` or use a glob so the Makefile compiles them all.

**Why:** the current file is already hard to navigate; as checksum validation (item 7) and streaming (item 8) land it will get worse. Splitting now while the boundaries are clear is cheaper than splitting a 2000-line file later.

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
- [ ] `gem push` to RubyGems.org
- [ ] Add GitHub repo topics: `ruby`, `gem`, `pii`, `redaction`, `security`, `rails`
- [ ] Submit to [The Ruby Toolbox](https://www.ruby-toolbox.com) (community-curated catalog; lets developers compare gems in the same category)
- [ ] Add Shields.io badges to README: gem version, CI build, coverage
- [ ] Write YARD docs for all public methods (`@param`, `@return`, `@raise`)
- [ ] Add a thread-safety note to README (built-in `regex_t` array is read-only after init; custom pattern registration is not thread-safe — document this)
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
