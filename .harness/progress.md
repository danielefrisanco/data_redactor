# Progress log

Append-only. Newest entry at the bottom. Written by `/harness:handoff` and `/harness:complete-task`.

## 2026-10-31 — TASK-003 done: Fix embedded NUL truncating redact and scan output
- `redact`/`scan` results built with explicit lengths; custom patterns run `regexec` per NUL-delimited segment (musl has no `REG_STARTEND`).
- NUL specs for built-in, custom, `boundary: true` and `scan` offsets; CHANGELOG, README, TODO → DONE updated.
- Commits: 855d3d2 (fix), plus task bookkeeping. Branch `fix/003-fix-embedded-nul-truncating-redact-and-s` — user to push and open the PR.

## 2026-11-20 — TASK-004 done: Fix boundary-wrapped token leaking after a one-byte separator
- `scan_one` and `scan_digit_group` now resume at the end of the core token, so a single separator byte is the boundary for both neighbours; the digit group's `\n` special case is gone. Deliberate break from `gsub` parity, only redacts more.
- `patterns_spec.rb`: the three repro strings, a left-boundary negative, and 14 winning shapes × `" "`/`","`/`"\n"` checking name, tag and offset (41/46 fail on the old engine). README limitation removed, CHANGELOG Fixed, TODO → DONE.
- Commits: 5ce456a (fix), plus task bookkeeping. Branch `fix/004-fix-boundary-wrapped-token-leaking-after` — user to push and open the PR.
