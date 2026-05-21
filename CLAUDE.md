# CLAUDE.md — data_redactor conventions

Project-specific rules for Claude Code. These override Claude's defaults.

---

## Security

- NEVER read files listed in `.gitignore` (`.env`, `*.key`, `*.pem`, etc.).
- NEVER echo credentials, secrets, or API keys in responses.

---

## Workflow

- **Always branch** for new features and bug fixes. Branch naming:
  - `feat/<short-description>` — new feature
  - `fix/<short-description>` — bug fix
  - `ci/<short-description>` — CI / workflow changes
- **Think before executing.** Plan the change, identify affected files, ask design questions before writing code.
- **Ask when unclear.** If a design decision is not covered here or in TODO.md, ask rather than assume.
- **Step by step.** Do not batch unrelated changes into one commit. One logical change = one commit.
- **Run tests before committing.** Always `bundle exec rspec` before `git commit`. Do not commit red tests.

---

## Versioning (SemVer)

- **Patch** (`0.x.Y`) — bug fixes, pattern additions, documentation, CI.
- **Minor** (`0.X.0`) — new public API methods, new integrations, new tags.
- **Major** (`X.0.0`) — breaking changes to existing public API.
- Update `lib/data_redactor/version.rb` and `CHANGELOG.md` (`[Unreleased]` section) in the same commit as the feature.

---

## Changelog

- Every user-visible change goes under `## [Unreleased]` in `CHANGELOG.md`.
- Format: `### Added / Changed / Fixed / Removed` subsections.
- On release: rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD` and add the diff link at the bottom.

---

## Code style

### General
- No unnecessary comments. Only add one when the **why** is non-obvious (hidden constraint, subtle invariant, POSIX workaround).
- No trailing summaries or "added for X" comments — those belong in the commit message.
- No speculative abstractions. Three similar lines beats a premature helper. Build for now, not for hypothetical futures.
- No backwards-compatibility shims for things that don't exist yet.

### Ruby
- Keyword arguments for all public methods that take more than one parameter.
- `module_function` for the `DataRedactor` module (stateless, no instance state).
- Pure-Ruby code lives in `lib/data_redactor/`. Integrations live in `lib/data_redactor/integrations/`.
- Soft-require pattern for integrations: each file does its own `require "data_redactor"` — callers opt in with `require "data_redactor/integrations/foo"`.
- No runtime dependencies beyond Ruby stdlib. The gem must install with zero extra gems.
- Frozen string literals (`# frozen_string_literal: true`) on every new Ruby file.
- YARD `@param`, `@return`, `@raise`, `@example` on every public method. 100% documented.

### C extension
- All pattern data lives in `ext/data_redactor/patterns.{h,c}`. Adding a pattern = editing those two files only (plus specs).
- `NUM_PATTERNS` in `patterns.h` must always equal the actual array lengths in `patterns.c`. Update it atomically.
- Pattern ordering tiers (most-specific → most-generic):
  1. Full URLs
  2. Long prefixed tokens (API keys, PATs)
  3. IBANs (longest → shortest)
  4. Structured formats (dots, dashes, slashes, @)
  5. Letter-anchored patterns
  6. Boundary-wrapped structured
  7. Boundary-wrapped pure digits
- `boundary_wrapped[i] = 0` for patterns with a distinctive prefix (no boundary needed).
- `boundary_wrapped[i] = 1` for generic digit/alphanum patterns (wrap with `(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)`).
- New patterns go in Tier 2 if they have a long distinctive prefix, tagged `TAG_CREDENTIALS`.
- All four parallel arrays (`boundary_wrapped`, `pattern_tags`, `pattern_names`, `pattern_strings`) must stay in sync — same index = same pattern.

---

## Testing

- Test file: `spec/data_redactor_spec.rb`. All tests in one file for now.
- Every new pattern gets:
  - At least one positive match test (token in context, e.g. `"key=#{token} end"`).
  - At least one negative test (below minimum length, wrong prefix, etc.) where false-positive risk is non-trivial.
- Every new public Ruby method gets unit tests covering: happy path, edge cases, error cases (`raise` paths).
- Use the `redacted?(input, sensitive)` helper for pattern match assertions.
- `bundle exec rspec` must be green before every commit.

---

## Design principles

- **Single Responsibility** — each file/class/module does one thing. Integrations do not contain redaction logic; `DataRedactor` does not know about HTTP frameworks.
- **Open/Closed** — new patterns slot into the existing array structure without touching the C redaction engine. New integrations are new files, not edits to existing ones.
- **Dependency Inversion** — integrations depend on `DataRedactor.redact`, never on C internals. The C layer is an implementation detail.
- **Fail fast** — validate at registration time (`add_pattern`), not at redaction time. Raise with a clear message rather than silently producing wrong output.
- **No mutation of caller data** — `redact`, `redact_deep`, `redact_json` always return copies. Never mutate the input.
- **Performance** — the C extension is the gem's selling point. Pure-Ruby traversal (e.g. `redact_deep`) is acceptable because it calls the C `redact` on each string leaf — the hot path stays in C.

---

## What NOT to do

- Do not add runtime gem dependencies.
- Do not add patterns without a distinctive prefix unless they are boundary-wrapped (false-positive risk).
- Do not skip `bundle exec rspec` before committing.
- Do not commit directly to `main` for feature work.
- Do not read `.gitignore`d files.
- Do not add `rescue`/fallbacks for impossible states inside the gem's own code (trust the C layer).
- Do not create intermediate planning docs or analysis files — work from conversation and TODO.md.
