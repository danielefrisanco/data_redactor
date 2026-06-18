# Contributing to data_redactor

Thanks for your interest in contributing. This gem redacts PII and secrets, so
correctness and false-negative avoidance matter more than features — a missed
pattern is a leaked secret. Please read this guide before opening a PR.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you agree to uphold it.

## Reporting security issues

Do **not** open a public issue for a vulnerability (including a pattern that
fails to redact a real secret format). See [SECURITY.md](SECURITY.md).

## Getting set up

```sh
git clone https://github.com/danielefrisanco/data_redactor
cd data_redactor
bundle install
bundle exec rake compile   # builds the C extension
bundle exec rspec          # must be green
```

Requirements:

- Ruby >= 2.7 (CI tests 3.1–3.4 on Linux glibc + musl).
- A C compiler (the extension uses POSIX `regex.h` from libc — no other native
  dependency).

## Workflow

- **Always branch.** Never commit feature work directly to `main`.
  - `feat/<short-description>` — new feature
  - `fix/<short-description>` — bug fix
  - `ci/<short-description>` — CI / workflow changes
- **One logical change per commit.** Don't batch unrelated changes.
- **Run the suite before every commit.** `bundle exec rspec` must be green —
  never commit red tests.
- **Open a PR against `main`.** CI must pass (specs on the Ruby matrix, the musl
  load test, the zero-allocation gate, and the throughput gate).

## Adding a redaction pattern

Built-in patterns live entirely in `ext/data_redactor/patterns.{h,c}`. Adding one
means editing **only** those two files (plus specs). The four parallel arrays
(`boundary_wrapped`, `pattern_tags`, `pattern_names`, `pattern_strings`) and the
`NUM_PATTERNS` count must stay in sync — same index = same pattern.

Pattern ordering runs most-specific → most-generic; pick the right tier (the
comment block at the top of `patterns.c` documents the seven tiers). A pattern
with a distinctive prefix (e.g. `AKIA`, `sk-ant-`) sets `boundary_wrapped = 0`;
a generic digit/alphanumeric run sets `boundary_wrapped = 1` so it is wrapped
with `(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)`.

Every new pattern needs:

- At least one **positive** match test (token in realistic context, e.g.
  `"key=#{token} end"`).
- At least one **negative** test (below minimum length, wrong prefix, etc.)
  where the false-positive risk is non-trivial.

Use the `redacted?(input, sensitive)` helper for match assertions. All tests live
in `spec/data_redactor_spec.rb`.

> There is a guided `rs-add-pattern` workflow if you use Claude Code — it keeps
> the parallel arrays and `NUM_PATTERNS` in sync and scaffolds the specs.

## Code style

### Ruby

- Keyword arguments for every public method taking more than one parameter.
- `# frozen_string_literal: true` on every new Ruby file.
- Full YARD docs (`@param`, `@return`, `@raise`, `@example`) on every public
  method — the gem is 100% documented and must stay that way.
- No runtime gem dependencies. The gem installs with zero extra gems.
- Pure-Ruby code lives in `lib/data_redactor/`; integrations live in
  `lib/data_redactor/integrations/` and soft-require `data_redactor` themselves.

### C extension

- All pattern data stays in `ext/data_redactor/patterns.{h,c}`.
- The hot path allocates **zero** times per scan — the CI alloc gate enforces
  this. Don't reintroduce per-scan allocation.

### General

- No unnecessary comments — add one only when the *why* is non-obvious (a hidden
  constraint, a subtle invariant, a libc workaround).
- No "added for X" trailing summaries; that belongs in the commit message.
- No speculative abstractions or backwards-compat shims for things that don't
  exist yet.

## Versioning, CHANGELOG, and docs

This project follows SemVer. In the **same commit** as a user-visible change:

- Bump `lib/data_redactor/version.rb`:
  - **patch** (`0.x.Y`) — bug fixes, new patterns, docs, CI;
  - **minor** (`0.X.0`) — new public API, new integration, new tag;
  - **major** (`X.0.0`) — breaking change to existing public API.
- Add an entry under `## [Unreleased]` in `CHANGELOG.md`, in the right
  `### Added / Changed / Fixed / Removed` subsection.

Releases are cut on `main` (see the `rs-release` workflow); the 6-platform native
build and RubyGems publish are automated.

## What not to do

- Don't add runtime gem dependencies.
- Don't add a pattern without a distinctive prefix unless it is boundary-wrapped
  (false-positive risk).
- Don't skip `bundle exec rspec` before committing.
- Don't commit feature work directly to `main`.

Open an issue first if you're unsure whether a change fits — especially for new
patterns (false-positive trade-offs) or anything touching the C matching engine.
