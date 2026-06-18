# Security Policy

`data_redactor` is a privacy tool: its job is to remove PII and secrets from text
before that text is logged or sent to a third party. A redaction failure is a
security issue, not just a bug.

## Supported versions

The gem is pre-1.0 and ships fixes on the latest minor line. Security fixes are
released against the most recent published version. Please upgrade to the latest
release before reporting.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security report.**

Report privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/danielefrisanco/data_redactor/security/advisories/new)
  (Security → Report a vulnerability), or
- email **daniele.frisanco@gmail.com** with `[data_redactor security]` in the
  subject.

Please include:

- the gem version and Ruby/libc (glibc or musl) version;
- a minimal input that reproduces the problem;
- the expected vs. actual redacted output.

You can expect an acknowledgement within a few days. Once a fix is released, the
report will be credited (unless you prefer to remain anonymous) in the CHANGELOG.

## What counts as a vulnerability

- A real secret/PII format that is **not** redacted (a false negative on a
  documented pattern category).
- A redaction that **leaks** part of the sensitive value (e.g. a partial token
  surviving in the output).
- A crash, out-of-bounds read/write, or hang in the C extension triggerable by
  attacker-controlled input.
- A pattern with catastrophic backtracking / quadratic blowup on crafted input.

## What is not a vulnerability

- A new pattern request for a format the gem doesn't yet claim to support — open
  a normal feature issue or PR (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- False **positives** (over-redaction) — these reduce noise but don't leak data;
  file a normal issue.
- Misuse where secrets are read from a source the gem was never given (it only
  redacts the text you pass to `redact`/`scan`).

## Defense-in-depth note

No pattern set catches every secret. Treat `data_redactor` as one layer, not a
guarantee. Use `scan` to audit what is and isn't being caught for your data, and
add `add_pattern` rules for formats specific to your organization.
