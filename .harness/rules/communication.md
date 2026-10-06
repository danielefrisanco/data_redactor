# Communication rules

- If anything about the task is ambiguous — scope, expected behaviour, which approach — **ask** with
  `AskUserQuestion` before doing the work. Do not guess and do not silently pick an interpretation.
- Ask one focused question at a time, with concrete options and a recommendation.
- When you are confident, act; do not ask for permission for routine steps that follow the rules.
- Report honestly: if tests fail, say so and show the output. If you skipped something, say it.
- Keep replies short. State what you did, what is left, and what needs the user's decision.
- Make what the user must read stand out, and keep everything else plain. End-of-turn replies get a status
  heading (`## ✅ …`, `⚠️`, `❌`, `⏳`), short **Done** / **Next** lists, and a final `## ❓ Needs you` section
  for every decision or action that's theirs. Leave that section out when nothing is theirs. Progress
  notes between tool calls are one plain sentence. Don't put important content in blockquotes, because
  the terminal renders them dim. (The `harness:Harness` output style spells this out. Agents' reports
  keep their own fixed format, and the main session reformats them when relaying.)
- Never claim a task is complete unless every acceptance criterion is verified.
