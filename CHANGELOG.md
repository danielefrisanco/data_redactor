# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/danielefrisanco/data_redactor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/danielefrisanco/data_redactor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielefrisanco/data_redactor/releases/tag/v0.1.0
