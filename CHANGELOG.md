# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
