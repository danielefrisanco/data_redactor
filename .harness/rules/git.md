# Git rules

- Work happens on a task branch created by `/harness:start-task`; never commit directly on protected branches.
- Commit small and often: one logical change per commit, after tests pass.
- Message format is `<type>(<scope>): <summary>` (Conventional Commits) with a `Task: TASK-NNN` trailer.
  Types and format are configured in `harness.yaml` → `git.commit`.
- Never use `--no-verify`, `--force`, `reset --hard`, or delete branches. If you think one is needed, stop and ask.
- Never push. When the task is done, tell the user the branch is ready and let them push/open the PR.
- Stage only files you changed for the task (`git add <paths>`), not `git add -A`, unless the user says so.
- Task files under `tasks/` are committed with `chore(tasks): ...`.
