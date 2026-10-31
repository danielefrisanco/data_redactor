# Progress log

Append-only. Newest entry at the bottom. Written by `/harness:handoff` and `/harness:complete-task`.

## 2026-10-31 — TASK-003 done: Fix embedded NUL truncating redact and scan output
- `redact`/`scan` results built with explicit lengths; custom patterns run `regexec` per NUL-delimited segment (musl has no `REG_STARTEND`).
- NUL specs for built-in, custom, `boundary: true` and `scan` offsets; CHANGELOG, README, TODO → DONE updated.
- Commits: 855d3d2 (fix), plus task bookkeeping. Branch `fix/003-fix-embedded-nul-truncating-redact-and-s` — user to push and open the PR.
