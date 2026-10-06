# Coding rules

- Read before you write: understand the existing code, naming and patterns and match them.
- Smallest change that satisfies the acceptance criteria. No drive-by refactors, no unrelated cleanup.
- No new dependencies without asking, and only after a license/maintenance check — see `dependencies.md`.
- Keep functions small and named for what they do; avoid clever code.
- Write or update tests for every behaviour change. Run the project's test command before declaring done.
- Comments explain *why*, not *what*. Do not leave commented-out code.
- Handle errors explicitly; never swallow exceptions silently.
- Never hardcode secrets, tokens or credentials. Use environment variables and reference them by name only.
