# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-02

### Added
- Initial release.
- C extension (`ext/data_redactor/data_redactor.c`) using POSIX `regex.h` for high-throughput scanning.
- 79 redaction patterns across cloud secrets, API keys, IBANs, national IDs, and PII for 15+ countries.
- Patterns ordered most-specific to most-generic to prevent shorter patterns from consuming parts of longer matches.
- Boundary-wrapping mechanism for generic digit/alphanum sequences so they only match at word boundaries.
- `DataRedactor.redact(text)` module function returning the input with every match replaced by `[REDACTED]`.
- RSpec suite with one example per pattern.

[Unreleased]: https://github.com/danielefrisanco/data_redactor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/danielefrisanco/data_redactor/releases/tag/v0.1.0
