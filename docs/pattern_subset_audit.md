# Pattern Subset Audit

**Prep 1 of the combined-matcher project** (see
[`combined_matcher_plan.md`](combined_matcher_plan.md)). Verifies that every
one of the 88 built-in patterns in `ext/data_redactor/patterns.c` uses only
the regex features the planned combined matcher will support (per the
"Scope" section of
[`standalone_matcher_design.md`](standalone_matcher_design.md)).

**Date:** 2026-05-23.

## Result

**All 88 patterns pass.** No backreferences, no lookaround, no non-greedy
quantifiers, no Ruby-only escapes (`\d`/`\s`/`\w`/`\b`), no named groups,
no atomic groups. **No scope adjustment is needed.**

Verified two ways:
1. Automated grep over `patterns.c` for disallowed syntax — found zero
   instances of `\d|\D|\w|\W|\s|\S|\h|\H|\b|\B`, `(?<|(?!|(?=|(?P<|(??|(?>`,
   `\1`-`\9`, or `*?|+?`.
2. Manual classification of each pattern's features against the supported
   set (table below).

## Feature usage across the 88 patterns

| Feature | Count | Notes |
|---|---|---|
| Character class `[...]` | 84 | Supported. |
| Exact-count quantifier `{n}` | 70 | Supported, bounded. |
| Escape `\.` `\\` `\(` etc. | 17 | Supported. |
| Unbounded `+` | 12 | **Supported but flagged** — see "Unbounded quantifiers" below. |
| Optional `?` | 8 | Supported. |
| Unbounded min `{n,}` | 8 | **Supported but flagged.** |
| Bounded range `{n,m}` | 8 | Supported, bounded. |
| Group `(...)` | 7 | Supported (capturing — the matcher only needs to remember pattern boundaries, not capture sub-groups). |
| Alternation `|` | 5 | Supported. |
| Negated class `[^...]` | 4 | Supported. |
| POSIX bracket `[[:space:]]` | 3 | Supported. |
| Unbounded `*` | 3 | **Supported but flagged.** |
| Anchor `^` `$` | 0 | None of our patterns use them — simplifies the matcher. |

## Unbounded quantifiers — flagged for matcher design

12 patterns use `+`, 8 use `{n,}`, 3 use `*` — all "unbounded repetition."
The combined-matcher design (Thompson NFA → DFA) handles them correctly,
but unbounded repetition is what makes some regex engines vulnerable to
catastrophic backtracking. Thompson construction does **not** backtrack
(it tracks multiple states simultaneously), so this is not a correctness
issue — but it's the reason the design doc explicitly chose Thompson over
PCRE-style backtracking.

Patterns using unbounded `+`:

| # | Name | Pattern | Notes |
|---|---|---|---|
| 0 | `aws_s3_presigned_url` | `https://[a-z0-9.-]+\.s3\.amazonaws\.com/[^[:space:]?]+\?[^[:space:]]*X-Amz-Signature=[^[:space:]]+` | 4× unbounded |
| 1 | `microsoft_teams_webhook` | `https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/.../[^/ ]+/...` | 2× unbounded |
| 3 | `mongodb_connection_string` | `mongodb(\+srv)?://[^[:space:]'"<>/:@]+:[^[:space:]'"<>/@]+@[^[:space:]?'"]+` | 3× unbounded |
| 4 | `sentry_dsn` | `https://[a-f0-9]{32}(:[a-f0-9]{32})?@[a-zA-Z0-9.-]+\.ingest\.sentry\.io/[0-9]+` | 2× unbounded |
| 5 | `uri_with_password` | `[A-Za-z][A-Za-z0-9+_-]*://[^[:space:]/?#:@]+:[^[:space:]/?#@]+@[A-Za-z0-9.-]+` | 3× unbounded |
| 7 | `jwt` | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+` | 1× `+`, 2× `{n,}` |
| 9 | `ssh_public_key` | `ssh-(rsa\|ed25519\|ecdsa) [a-zA-Z0-9/+=]{20,}` | 1× `{n,}` |
| 10 | `bearer_token` | `[Bb]earer [a-zA-Z0-9_.=/+:-]{12,}` | 1× `{n,}` |
| 15 | `aws_secret_access_key` | `[A-Za-z0-9/+=]{40}` | bounded only — listed for completeness |
| 50 | `email` | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | 2× `+`, 1× `{n,}` |
| 66 | `finnish_hetu` | `[0-9]{6}[-+A][0-9]{3}[0-9A-Y]` | the `+` here is inside `[-+A]` — literal `+`, not a quantifier (false positive in the count) |
| 67 | `swedish_personnummer` | `[0-9]{6}[-+][0-9]{4}` | same — literal `+`, not a quantifier |

Corrected unbounded-quantifier count: **10 patterns** actually use `+` as a
quantifier (`finnish_hetu` and `swedish_personnummer` had literal `+`
characters inside character classes). All 10 are well-behaved under
Thompson construction.

## Patterns with the more interesting features

These are the ones to keep an eye on during matcher implementation —
their structure exercises the less-trivial parts of the engine.

### Alternation (`|`)

| # | Name | Pattern |
|---|---|---|
| 9 | `ssh_public_key` | `ssh-(rsa\|ed25519\|ecdsa) ...` |
| 14 | `aws_access_key_id` | `(A3T[A-Z0-9]\|AKIA\|ABIA\|ACCA\|AGPA\|AIDA\|ANPA\|ANVA\|APKA\|AROA\|ASCA\|ASIA)[A-Z2-7]{16}` |
| 18 | `launchdarkly_api_key` | `(api\|sdk)-...` |
| 55 | `ipv4` | 4-way alternation per octet, applied 4× |
| 56 | `credit_card` | 8-way alternation over card-prefix patterns |

The `aws_access_key_id` 12-way alternation is the widest; `credit_card` has
the deepest sub-pattern complexity inside each branch.

### POSIX bracket classes (`[[:space:]]`)

| # | Name |
|---|---|
| 0 | `aws_s3_presigned_url` |
| 3 | `mongodb_connection_string` |
| 5 | `uri_with_password` |

All three use `[[:space:]]` (or its negation). POSIX `[:digit:]`,
`[:alpha:]`, `[:alnum:]`, `[:xdigit:]`, `[:upper:]`, `[:lower:]` are
designed into the parser per the design doc but **not actually used** by
any built-in pattern. We must still support them (for user-supplied
custom patterns).

### Negated character class (`[^...]`)

| # | Name |
|---|---|
| 0 | `aws_s3_presigned_url` |
| 1 | `microsoft_teams_webhook` |
| 3 | `mongodb_connection_string` |
| 5 | `uri_with_password` |

All four are URL/connection-string patterns where the negation excludes
URL delimiters (`/`, `?`, `#`, etc.) or whitespace.

### `*` (zero-or-more)

| # | Name | Pattern |
|---|---|---|
| 0 | `aws_s3_presigned_url` | `...X-Amz-Signature=[^[:space:]]*...` |
| 5 | `uri_with_password` | `[A-Za-z][A-Za-z0-9+_-]*://...` |
| 27 | `pem_private_key` | `-----BEGIN [A-Z ]*PRIVATE KEY-----` |

All three are well-behaved (the `*` is constrained by surrounding literals).

## Features required to support that *no* built-in pattern currently uses

- **Anchors** `^` and `$` — the gem applies its own boundary wrapper
  `(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)` to certain patterns at compile
  time (see `wrap_boundary()` in `ext/data_redactor/redact.c`). The
  matcher must support `^`/`$` for those wrapped patterns and for
  user-supplied custom patterns.
- **POSIX classes other than `[:space:]`** — `[[:digit:]]`, `[[:alnum:]]`,
  etc. Custom patterns may use them.

## Custom patterns (user-supplied via `add_pattern`)

Custom patterns are **not classified here** — they're known only at runtime.
But two observations:

1. **Today's `add_pattern` already enforces the subset.** The Ruby
   `RUBY_ONLY_SYNTAX_RE` regex in `lib/data_redactor.rb:72` rejects
   `\d`/`\s`/`\w`/`\b`/lookaround/non-greedy/inline-flag syntax at
   registration time with `InvalidPatternError`. Any pattern that survives
   `add_pattern` is already POSIX ERE.
2. **The combined matcher will need its own per-pattern feature validation
   at registration time** to catch anything POSIX ERE allows but the
   matcher doesn't (initially: anchors-only-in-specific-positions, no
   nested groups beyond what Thompson handles cleanly, etc.). Final list
   to be determined when the parser is written.
3. **A future Ruby `DataRedactor.pattern_features(name)` introspection
   API** could classify any registered pattern (built-in or custom) on
   demand. Useful for debugging custom patterns and for keeping this
   audit doc current. Deferred to its own PR after the matcher ships —
   not blocking.

## Conclusion

The combined matcher's planned regex subset is **sufficient for all 88
built-in patterns**. No pattern rewriting required. The parser must
handle: literals, character classes (including negated and POSIX bracket
classes), alternation, capturing groups, bounded and unbounded
quantifiers (`*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`), and escapes for
regex metacharacters. Anchors (`^`, `$`) must be supported for the
boundary-wrapper and for custom patterns even though no built-in uses
them directly.

Next prep step: lock down overlap-resolution policy (Prep 2 in the plan).
