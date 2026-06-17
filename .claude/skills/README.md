# Claude Code skills — data_redactor

Project skills for repeated, error-prone workflows. Claude sees each skill's
`name` + `description` at session start and runs it when you ask or describe a
matching task; you can also invoke one explicitly as `/rs-<name>`.

| Skill | Use it when |
|---|---|
| `rs-add-pattern` | Adding a built-in redaction pattern (keeps the parallel arrays + `NUM_PATTERNS` in sync, picks the tier, scaffolds specs). |
| `rs-release` | Cutting a release (SemVer bump, CHANGELOG promote, README/Gemfile.lock refresh, tag). Publishing is automated by `release-binaries.yml`. |

## Pre-push gate (git hook, not a skill)

`.githooks/pre-push` runs `bundle exec rake` and warns if a `feat:`/`fix:` push
lacks a CHANGELOG touch. It is **not** automatic on clone — enable it once:

```sh
git config core.hooksPath .githooks
```

Bypass a single push with `git push --no-verify`.
