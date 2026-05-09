# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1] - 2026-05-09

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

[Unreleased]: https://github.com/danielefrisanco/data_redactor/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/danielefrisanco/data_redactor/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/danielefrisanco/data_redactor/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.5.0...v0.6.0
[0.2.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielefrisanco/data_redactor/releases/tag/v0.1.0
