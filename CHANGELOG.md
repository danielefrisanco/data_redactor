# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Custom-pattern registration is now thread-safe.** `add_pattern`,
  `remove_pattern`, and `clear_custom_patterns!` are guarded by a mutex shared
  with the `redact`/`scan` custom-pattern loop, so patterns may be registered,
  removed, or cleared from any thread at any time — including at runtime from a
  request handler — without coordinating with in-flight redactions. The previous
  "register custom patterns at boot only" caveat is lifted. (The C extension now
  links `-lpthread` on glibc; no-op on musl and macOS where pthread is in libc.)
- **`redact` releases the GVL for large inputs.** The v19 engine's per-scan
  mutable state (NFA scratch and the lazy DFA cache) moved into per-thread
  storage, making the engine re-entrant. `redact` now releases the GVL
  (`rb_thread_call_without_gvl`) around the built-in scan for inputs above a few
  KB, so a large redaction on one thread no longer blocks other Ruby threads.
  Small inputs keep the GVL. No public API change; output is byte-for-byte
  identical (verified by a differential gate over ~6000 inputs).

## [0.11.0] - 2026-06-10

### Added
- **Claude / OpenAI LLM integrations** — two new soft-required adapters that
  scrub PII and secrets from LLM payloads before they leave the process and
  from responses before they're logged:
  - `DataRedactor::Integrations::Claude` — `.redact_messages` (handles the
    `messages` array plus a top-level `system:` prompt; String or
    array-of-content-block content) and `.redact_response` (Messages API
    `content` text blocks).
  - `DataRedactor::Integrations::OpenAI` — `.redact_messages` (Chat
    Completions `messages`, including a `system` message and array-of-parts
    content) and `.redact_response` (`choices[].message.content`).
  Both operate on plain Ruby Hashes/Arrays with String or Symbol keys (no
  runtime dependency on the `anthropic`/`openai` gems), return a deep copy
  (never mutate the caller's input), pass non-text content blocks through
  untouched, and forward `only:`/`except:`/`placeholder:` to
  `DataRedactor.redact`.

## [0.10.1] - 2026-06-10

### Fixed
- **musl/Alpine load failure** — the `hashicorp_vault_batch_token` pattern used a
  `{138,300}` interval whose upper bound exceeds POSIX `RE_DUP_MAX` (255). glibc
  accepts it, but musl's `regcomp` rejects it ("Invalid contents of {}"), so the
  native musl gem raised at load (`require "data_redactor"`) on Alpine. Capped the
  bound at 255; tokens are still neutralized (prefix + 251+ chars redacted).

## [0.10.0] - 2026-06-09

### Changed
- **Engine rewrite (v19 hybrid)** — `redact` and `scan` now run through a
  Thompson NFA → bytecode → lazy-DFA multi-pattern engine (v19) for all 88
  built-in patterns, replacing the previous per-pattern POSIX `regexec` loop.
  Custom patterns (`add_pattern`) continue to use the glibc path (hybrid split
  — required for correct UTF-8 multibyte character-class matching in user regex).
- Throughput on a 1 MB log: **~8.4× faster** than the previous C engine
  (0.87 i/s → 7.27 i/s); **2.25× faster** than pure-Ruby `gsub` (was 4×
  slower). Small per-call strings: 1.7–2.3× faster (was 3–4.6× slower).
- Overlap resolution: built-in matches are now resolved by an index-order
  greedy claim (`mm_resolve`) that reproduces today's sequential per-pattern
  rewrite semantics exactly. The one accepted divergence (rewrite-created
  boundary when two secrets abut with no separator) is documented in
  `TODO.md §1d` and pinned by `DIVERGENCE` specs.
- `rb_data_redactor_scan`: coordinate mapping (`repl_log` / `WORKING_TO_ORIG`)
  replaced by direct original-frame offset emission from the v19 engine; custom
  patterns use a lightweight offset-walk over the built-in event list.

### Fixed
- **Swiss AHV false-negative** — boundary-wrapped patterns with a
  start-anchored required literal now correctly set `max_back = 1` (not 0) so
  the literal-skip does not overshoot the boundary byte. `756.1234.5678.90`
  now matches as expected. (Pre-existing bug in the old engine, caught by
  going live.)

## [0.9.0] - 2026-05-22

### Added
- `DataRedactor.name_pattern(first, last, middle:)` — generates a POSIX ERE that matches a person's name across common written variations (case-insensitivity, First/Last order swaps, `Last, First`, initials, diacritics, and interchangeable space/hyphen separators). Returns a String ready to pass to `add_pattern`. The pattern is boundary-wrapped, so `"Mario"` matches as a word but not inside `"Mariolino"`. When `middle:` is given, both the no-middle and with-middle forms match.

## [0.8.0] - 2026-05-21

### Added
- `DataRedactor.redact_deep(data, only:, except:, placeholder:)` — recursively redacts every String value in a nested Hash/Array structure. Non-string scalars (Integer, Float, nil, Boolean) and Hash keys are passed through unchanged. Returns a deep copy; never mutates the input. Raises `ArgumentError` on circular references.
- `DataRedactor.redact_json(json_string, only:, except:, placeholder:)` — parses JSON, redacts via `redact_deep`, and returns valid JSON. Raises `JSON::ParserError` on invalid input.
- HashiCorp Vault service tokens (`hvs.` prefix, 90–120 chars) — pattern `hashicorp_vault_service_token`
- HashiCorp Vault batch tokens (`hvb.` prefix, 138–300 chars) — pattern `hashicorp_vault_batch_token`
- HashiCorp Terraform Cloud API tokens (`<14-char-id>.atlasv1.<token>`) — pattern `hashicorp_terraform_api_token`

All three HashiCorp patterns are tagged `:credentials` and do not require word-boundary wrapping (distinctive prefixes eliminate false positives).

## [0.7.2] - 2026-05-09

**Supersedes 0.7.1, which has been yanked from RubyGems.**

0.7.1 had a release pipeline bug: the source gem and the precompiled native
gems were published by two independent workflows, with no gating between
them. When the native-binary builds failed (`oxidize-rb/actions/cross-gem`
couldn't pull `rbsys/aarch64-linux:0.9.128` from Docker Hub), the source
gem still published — leaving users with release notes that promised
precompiled binaries that didn't exist on RubyGems. 0.7.2 ships the same
features as 0.7.1 plus the pipeline fix.

### Changed
- **Atomic release pipeline.** Source-gem publishing moved out of `ci.yml`
  and into `release-binaries.yml`, alongside the native-gem builds. The
  publish job now `needs: [build-source, build-native]`; if any native
  platform fails to build, **nothing publishes**. This guarantees the
  RubyGems release matches what the GitHub release notes promise.
- **Direct `rake-compiler-dock` invocation in CI** instead of the
  `oxidize-rb/actions/cross-gem` action. Same code path as `rake gem:all`
  locally and the existing PR-time smoke test in `ci.yml`. Uses
  `ghcr.io/rake-compiler/*` images (no Docker Hub rate limits).

### Fixed
- All 6 precompiled native gems now actually publish on release — the
  `aarch64-linux` variant in particular was previously failing.

### Documentation
- README installation section rewritten around the user's question
  ("what changes for me?"). Adds explicit Docker / Alpine guidance and a
  heads-up about `bundle lock --add-platform` for cross-platform deploys.

## [0.7.1] - 2026-05-09 [YANKED]

### Added
- **Precompiled native gems** for the most common platforms — installing
  `data_redactor` no longer requires a C toolchain on these targets:
  - `x86_64-linux`, `aarch64-linux` (glibc)
  - `x86_64-linux-musl`, `aarch64-linux-musl` (Alpine)
  - `x86_64-darwin`, `arm64-darwin` (macOS Intel + Apple Silicon)
  Each native gem ships compiled `.so` files for Ruby 3.1, 3.2, 3.3, and 3.4.
  Bundler/RubyGems automatically picks the right gem for the host; users on
  any other platform fall back to the source gem and compile as before.
- `rake gem:all` task — builds every native gem locally via `rake-compiler-dock`
  (requires Docker). Single command to regenerate the full release matrix.
- `.github/workflows/release-binaries.yml` — builds & publishes all native
  gems on every GitHub release. Also exposes `workflow_dispatch` so a
  maintainer can rebuild any past release without cutting a new tag.

### Changed
- CI test matrix now includes Ruby 3.4 in addition to 3.1, 3.2, 3.3.
- Gemspec: added `rake-compiler-dock` as a development dependency. Source-only
  gem size is unchanged — native gems strip `ext/` and the `extconf.rb`
  extension hook so they only carry the prebuilt `.so` files.

## [0.7.0] - 2026-05-08

### Added
- **Rails / Rack / Logger integrations** under `lib/data_redactor/integrations/`. Soft-required — none are loaded by default; the gem still has zero runtime dependencies in the gemspec.
  - `DataRedactor::Integrations::Logger` — drop-in `Logger::Formatter` that scrubs every emitted line, wraps an inner formatter (default `Logger::Formatter`), and preserves exception cause chains.
  - `DataRedactor::Integrations::Rails.filter(...)` — returns a `(key, value)` proc for `Rails.application.config.filter_parameters`. Mutates String values in place via `String#replace`.
  - `DataRedactor::Integrations::Rack` — middleware with selectable surfaces. `scrub:` accepts any subset of `[:body, :headers]` (default both). `:body` buffers the response and drops `Content-Length`; `:headers` scrubs sensitive response headers (`Set-Cookie`, `Authorization`, `X-Api-Key`, ...) and request headers in the env hash. Unknown surfaces raise `ArgumentError`.
- All three integrations forward `only:`, `except:`, `placeholder:` to `DataRedactor.redact`.

### Changed
- Gemspec: added `rack` as a development dependency. No new runtime dependencies.

## [0.6.1] - 2026-05-08

### Added
- Six new distinctive-prefix API key patterns under the `:credentials` tag, exposed via `DataRedactor.pattern_names`:
  - `anthropic_api_key` — `sk-ant-apiNN-...`
  - `openai_project_api_key` — `sk-proj-...`
  - `gitlab_pat` — `glpat-...`
  - `digitalocean_pat` — `dop_v1_...`
  - `databricks_api_token` — `dapi...`
  - `sentry_dsn` — `https://KEY@oNNN.ingest.sentry.io/PID` (also matches the legacy `KEY:SECRET@` form)

### Changed
- `NUM_PATTERNS` is now 85 (was 79). Built-in pattern indices in C have shifted accordingly; the public Ruby API and pattern names are stable.

## [0.6.0] - 2026-05-08

### Added
- **Per-pattern allow / deny via `only:` / `except:`.** Both kwargs now accept a mix of Symbols (tags) and Strings (pattern names from `DataRedactor.pattern_names`). They can be combined: `only: :contact, except: ["email"]` redacts every contact pattern except email. Mixed-list shapes like `only: [:credentials, "iban_de"]` also work. Precedence: `except:` always wins when the two overlap.
- `DataRedactor.pattern_names` — array of every known pattern name (built-ins + currently registered custom).
- `DataRedactor::BUILTIN_PATTERN_NAMES` and `DataRedactor::BUILTIN_PATTERN_TAG_BITS` constants (frozen) exposing the compiled-in pattern roster.
- `DataRedactor::UnknownPatternError` raised when a String passed to `only:`/`except:` does not match any known pattern.
- YARD docs deploy job in `.github/workflows/ci.yml` publishes `bundle exec yard doc` output to GitHub Pages on every push to `main`.

### Changed
- **C entry-point signatures.** `_redact(text, ph_mode, ph_str, enable_bits)` and `_scan(text, enable_bits)` now take a per-pattern enable bit array (built by the Ruby wrapper from `only:`/`except:`) instead of a tag bitmask. The public `DataRedactor.redact` / `.scan` API is fully backward compatible — only the underscore-prefixed C boundary changed. Single-pass: filtering happens in C, no second pass through `_scan`.
- `only:` and `except:` may now be combined (previously raised `ArgumentError` if both were passed).
- **Internal: C extension split into focused modules.** `ext/data_redactor/data_redactor.c` was a single ~1000-line file; it is now a 60-line entry point plus `patterns.{c,h}`, `placeholder.{c,h}`, `redact.{c,h}`, `scan.{c,h}`, `custom_patterns.{c,h}`, and `tags.h`. `extconf.rb` now globs every `.c` in the extension directory via `$srcs`, so adding a new module needs no Makefile edits.
- **YARD inline docs** — every public method on `DataRedactor` now has `@param`/`@return`/`@raise` annotations (100% coverage); `.yardopts` configures markdown rendering with the README as the front page.

### Documentation
- README: gem version / CI / license badges; new "Thread safety" section clarifying that `redact`/`scan` are thread-safe but `add_pattern`/`remove_pattern`/`clear_custom_patterns!` are not (register custom patterns once at boot).

## [0.5.0] - 2026-05-02

### Added
- `DataRedactor.scan(text, only:, except:)` — returns `{ redacted: String, matches: Array<Hash> }` where each match contains `:tag` (Symbol), `:name` (pattern name String), `:value` (matched text), `:start` (byte offset into original), `:length` (byte length). Accepts the same `only:`/`except:` tag filters as `redact`. Includes both built-in and custom pattern matches.
- `pattern_names[]` array in the C extension mapping each built-in pattern index to a stable snake_case name string (e.g. `"aws_access_key_id"`, `"email"`, `"iban_de"`).

## [0.4.0] - 2026-05-02

### Added
- `placeholder:` keyword argument on `DataRedactor.redact`.
  - Plain string (default `"[REDACTED]"`): `placeholder: "***"`
  - Tagged: `placeholder: :tagged` → `[REDACTED:CONTACT]`, `[REDACTED:CREDENTIALS]`, etc.
  - Deterministic hash: `placeholder: :hash` → `[CONTACT_a3f9]` (4-hex djb2 suffix, same value always produces the same token — useful for correlating redactions across log lines).
- `PH_MODE_PLAIN`, `PH_MODE_TAGGED`, `PH_MODE_HASH` integer constants exposed from C.
- `DataRedactor::PLACEHOLDER_DEFAULT` constant (`"[REDACTED]"`).

### Changed
- `DataRedactor._redact` now takes 4 arguments: `(text, mask, ph_mode, ph_str)`. The public `DataRedactor.redact` API is fully backward compatible.

## [0.3.0] - 2026-05-02

### Added
- User-supplied custom patterns via `DataRedactor.add_pattern(name:, regex:, tag: :custom, boundary: false)`.
- `DataRedactor.remove_pattern(name)` — remove a named custom pattern (returns `true`/`false`).
- `DataRedactor.custom_patterns` — list all registered custom patterns as an array of hashes.
- `DataRedactor.clear_custom_patterns!` — remove all custom patterns (useful in test suites).
- New `:custom` tag and `TAG_CUSTOM` bitmask constant for custom patterns. Works with `only:`/`except:`.
- `DataRedactor::InvalidPatternError` raised when a pattern fails `regcomp` or uses unsupported Ruby-only syntax (`\d`, `\s`, `\w`, `\b`, lookaround, non-greedy quantifiers, named groups).
- Capture groups rejected at registration when `boundary: true` (group indices would shift).
- Name collisions replace the existing pattern (the old compiled `regex_t` is freed).

## [0.2.0] - 2026-05-02

### Added
- Tag system: every pattern now belongs to one of 8 tags (`:credentials`, `:financial`, `:tax_id`, `:national_id`, `:contact`, `:network`, `:travel`, `:other`).
- `DataRedactor.redact(text, only: [...])` to redact only patterns in the given tags.
- `DataRedactor.redact(text, except: [...])` to redact every tag except the given ones.
- `DataRedactor.tags` returning the list of supported tags.
- `DataRedactor::TAGS` constant mapping tag symbols to bitmask values, plus `TAG_*` integer constants exposed from C for advanced use.
- `DataRedactor::UnknownTagError` raised when an unknown tag symbol is passed.

### Changed
- The C-level entry point is now `DataRedactor._redact(text, mask)` (two-arg, mask is an integer bitmask). The public API is the Ruby wrapper `DataRedactor.redact`, which remains backward compatible: `redact(text)` with no keyword arguments runs every pattern exactly as before.

## [0.1.0] - 2026-05-02

### Added
- Initial release.
- C extension (`ext/data_redactor/data_redactor.c`) using POSIX `regex.h` for high-throughput scanning.
- 79 redaction patterns across cloud secrets, API keys, IBANs, national IDs, and PII for 15+ countries.
- Patterns ordered most-specific to most-generic to prevent shorter patterns from consuming parts of longer matches.
- Boundary-wrapping mechanism for generic digit/alphanum sequences so they only match at word boundaries.
- `DataRedactor.redact(text)` module function returning the input with every match replaced by `[REDACTED]`.
- RSpec suite with one example per pattern.

[Unreleased]: https://github.com/danielefrisanco/data_redactor/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/danielefrisanco/data_redactor/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/danielefrisanco/data_redactor/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/danielefrisanco/data_redactor/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/danielefrisanco/data_redactor/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.5.0...v0.6.0
[0.2.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielefrisanco/data_redactor/releases/tag/v0.1.0
