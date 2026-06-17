---
name: rs-release
description: Cut a data_redactor release locally. Use when releasing, shipping, or publishing a new gem version ("let's ship 0.X.0", "cut a release", "release the gem", "bump the version and tag"). Infers the SemVer bump from CHANGELOG, edits version.rb, promotes [Unreleased] to a dated section, refreshes README, updates Gemfile.lock, runs specs, commits, and tags. The 6-platform native build + RubyGems publish is already automated by release-binaries.yml — this skill prepares and tags; the workflow publishes.
---

# rs-release

Prepare a release of `data_redactor` up to the tag. Publishing the source +
6 native gems to RubyGems is handled **automatically** by
`.github/workflows/release-binaries.yml` on `release.published` (or manual
`workflow_dispatch`). This skill does the local prep that must be right before
that workflow runs.

## Decide the version bump (SemVer)

Read the `## [Unreleased]` section of `CHANGELOG.md` and infer the bump from
what it contains (CLAUDE.md rules):

- **Patch** `0.x.Y` — bug fixes, pattern additions, docs, CI only.
- **Minor** `0.X.0` — new public API methods, new integrations, new tags.
- **Major** `X.0.0` — breaking changes to the existing public API.

State the inferred bump and the target version to the user and confirm before
editing. If `[Unreleased]` is empty, stop and say there's nothing to release.

## Steps

1. **Pre-flight:** confirm a clean tree on a non-`main` release branch
   (`git status`, `git branch --show-current`). If on `main`, branch first
   (`release/X.Y.Z` or `chore/release-X.Y.Z`).
2. **Bump** `lib/data_redactor/version.rb` `VERSION = "X.Y.Z"`.
3. **Promote CHANGELOG:** rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`
   (today's date), add a fresh empty `## [Unreleased]` above it, and add the
   version diff link at the bottom of the file in the existing link-reference
   style (compare previous tag → new tag).
4. **Refresh README** if the release changes user-facing facts the README
   states: the pattern count (grep `NUM_PATTERNS` in `ext/data_redactor/patterns.h`
   vs the README's claimed count) and the benchmark table if perf changed.
5. **Update Gemfile.lock:** run `bundle install` (or `bundle update data_redactor`)
   so the lock records the new version.
6. **Verify:** `bundle exec rake` (compile + full spec suite) must be green.
   Do not proceed on red.
7. **Commit** as one logical change: `chore: release X.Y.Z`
   (version.rb + CHANGELOG + README + Gemfile.lock together).
8. **Tag:** `git tag vX.Y.Z` and report the push commands. Remind the user that
   the GitHub Release (or `release.published`) triggers `release-binaries.yml`,
   which builds + publishes all 7 gems atomically — do **not** `gem push` by hand.

## Do not

- Do not `gem push` manually — release-binaries.yml does the atomic publish
  (a partial manual publish caused the yanked 0.7.1 release).
- Do not release with a red `bundle exec rake`.
- Do not bundle unrelated changes into the release commit.
- Do not commit the release directly to `main`.
