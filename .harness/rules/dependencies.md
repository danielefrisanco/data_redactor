# Dependency & versioning rules

## Adding a library

Never add a new dependency without asking the user first (see `coding.md`), and never on a hunch
about its license. Before proposing one:

1. **Prefer the standard library / what's already a dependency** over adding something new.
2. **Check the license** with `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/license_check.py" check <pkg> --eco pypi|npm|cargo`.
   - `allowed` → fine to propose.
   - `review_required` or `disallowed` → tell the user which license and what it obligates
     (e.g. LGPL requires dynamic linking / source availability on distribution; GPL/AGPL require
     the whole work to be GPL-compatible or network-served source). Do not add it without their
     explicit go-ahead, and record the decision (task note or commit body) so it's traceable.
   - `unknown` → the registry didn't return a resolvable SPDX id; treat like `review_required` and
     say so — never assume permissive.
3. **Check it's actually maintained**: a recent release, no pile of unresolved security issues,
   a reasonable number of dependents/downloads. Prefer the most maintained option, not the newest.
4. **Prefer permissive, widely-used libraries** (MIT/Apache-2.0/BSD/ISC) over niche or copyleft
   ones when there's a realistic choice — it keeps the project's own licensing options open.
5. **Pin the version** the way the ecosystem's tooling expects (lockfile, `==`, exact `Cargo.lock`
   entry) rather than an open range, unless the project's convention is otherwise.

The lists that `license_check.py` checks against live in `harness.yaml` → `dependencies.*` and are
the project's real policy — `/harness:rules` shows and edits them.

## Versioning

- The project follows [Semantic Versioning 2.0.0](https://semver.org/): `MAJOR.MINOR.PATCH`,
  bump MAJOR on incompatible changes, MINOR on backwards-compatible features, PATCH on
  backwards-compatible fixes. Pre-1.0 (`0.y.z`), anything may change — say so if it matters.
- The version's source of truth is the annotated git tag (`versioning.tag_pattern`), not a
  hand-edited number. `/harness:release` computes it deterministically from Conventional
  Commits since the last tag — never hand-guess or hand-edit the next version.
- A commit that breaks compatibility must say so: `type(scope)!: summary` or a `BREAKING CHANGE:`
  footer. This is how the release process knows to bump MAJOR — get it right when you commit,
  don't leave it for release time.
- Changelog entries are generated from commits (Keep a Changelog format); write commit subjects
  that make sense standalone to a reader of the changelog, not just to a reviewer of the diff.
