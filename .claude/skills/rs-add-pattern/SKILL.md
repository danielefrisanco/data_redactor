---
name: rs-add-pattern
description: Add a built-in redaction pattern end-to-end. Use when adding/registering a new secret, credential, token, PII, or financial pattern to the C engine (patterns.c/patterns.h) — keeps all parallel arrays and NUM_PATTERNS in sync, picks the correct ordering tier, scaffolds positive/negative specs, and runs the suite. Triggers: "add a pattern for X", "redact Stripe/Slack/IBAN keys", "support detecting Y tokens".
---

# rs-add-pattern

Add one built-in pattern to the C engine without desyncing the parallel arrays.
This is error-prone by hand: a pattern lives as **one index across six arrays**
plus `NUM_PATTERNS`, and a wrong tier or interval can silently break matching
or fail to compile on musl. Encode the steps; don't improvise.

## Inputs to gather first

Ask the user (or infer from the request) before editing:

1. **Pattern name** — snake_case, matches the existing `pattern_names` style
   (e.g. `stripe_secret_key`).
2. **POSIX ERE regex source** — the C engine uses `<regex.h>` POSIX ERE, *not*
   PCRE. No `\d`, `\b`, lookaround, or non-greedy. Use `[0-9]`, `[A-Za-z]`, etc.
3. **Tag** — one of `TAG_CREDENTIALS`, `TAG_FINANCIAL`, `TAG_CONTACT`, `TAG_PII`
   (grep `pattern_tags` for the exact set in use).
4. **Distinctive prefix?** — does the token start with a fixed literal
   (`sk-`, `ghp_`, `AKIA`)? This decides tier, boundary-wrapping, and the
   required-literal pre-filter.

## The six parallel arrays (all in `ext/data_redactor/patterns.{c,h}`)

Same index `i` = same pattern in every one. Adding a pattern means inserting at
the **same position** in all of these and bumping the count:

| File | Symbol | What to set |
|---|---|---|
| patterns.h | `NUM_PATTERNS` | increment by 1 |
| patterns.c | `pattern_strings[]` | the regex source string |
| patterns.c | `pattern_names[]` | the snake_case name |
| patterns.c | `pattern_tags[]` | the `TAG_*` value |
| patterns.c | `boundary_wrapped[]` | `0` if distinctive prefix, `1` for generic digit/alphanum |
| patterns.c | `keyname_anchored[]` | `1` only for KEY<sep>VALUE patterns; mutually exclusive with `boundary_wrapped` (`0` otherwise) |
| patterns.c | `pattern_required_literal[]` | a literal the regex *provably requires* (memmem pre-filter), else `NULL` |

> ⚠️ The number of arrays drifts over time (`keyname_anchored` and
> `pattern_required_literal` were added after CLAUDE.md was written). **Re-read
> `patterns.h` at the start of every run** and sync *every* array declared
> there with `[NUM_PATTERNS]`, not just the ones listed above. If you find a new
> one, handle it and mention it.

## Tier ordering (most-specific → most-generic)

Insert the new index inside the matching tier block (the arrays carry
`/* N: name */` tier comments — keep them accurate after insertion):

1. Full URLs
2. Long prefixed tokens (API keys, PATs) ← **most new patterns land here**
3. IBANs (longest → shortest)
4. Structured formats (dots, dashes, slashes, @)
5. Letter-anchored patterns
6. Boundary-wrapped structured
7. Boundary-wrapped pure digits

A pattern with a long distinctive prefix goes in **Tier 2**, `boundary_wrapped=0`,
tagged `TAG_CREDENTIALS`. A generic digit/alphanum pattern goes in a lower tier
with `boundary_wrapped=1`.

## musl / POSIX traps (these have shipped bugs before)

- **`{m,n}` intervals must have `n <= 255`** (`RE_DUP_MAX`). glibc accepts larger;
  musl's `regcomp` rejects them at module init → the gem fails to load on Alpine.
  Cap greedy/large counts. (See the `hvb` token fix, 0.10.0.)
- Prefer **bounded** quantifiers over unbounded `+`/`*` tails where possible —
  redaction only needs to neutralize the token, not match all of it.

## Steps

1. **Read** `ext/data_redactor/patterns.h` and the relevant tier block of
   `ext/data_redactor/patterns.c`. Confirm current `NUM_PATTERNS` and the full
   set of `[NUM_PATTERNS]` arrays.
2. **Decide** tier, `boundary_wrapped`, `keyname_anchored`, required-literal,
   tag — from the inputs above. State the decisions back to the user.
3. **Edit** `patterns.h` (bump `NUM_PATTERNS`) and `patterns.c` (insert the new
   entry at the chosen index in **every** parallel array; renumber the
   `/* N: ... */` comments below the insertion point so they stay correct).
4. **Add specs** in `spec/data_redactor_spec.rb` using the `redacted?(input, sensitive)`
   helper: at least one positive match (token in realistic context, e.g.
   `"key=#{token} end"`) and — where false-positive risk is non-trivial — one
   negative (below min length / wrong prefix / boundary).
5. **Run** `bundle exec rake` (compile + specs). Report green/red with output.
   If you can run Docker, optionally invoke the **rs-musl-check** sibling skill
   to confirm the new interval compiles under musl before release.
6. **Update** `CHANGELOG.md` `[Unreleased]` → `### Added` with a one-line note,
   per CLAUDE.md (pattern additions are a **patch** bump).

## Do not

- Do not add a generic digit/alphanum pattern without `boundary_wrapped=1`
  (false-positive risk).
- Do not commit before `bundle exec rake` is green.
- Do not desync `NUM_PATTERNS` from the array lengths — update atomically.
