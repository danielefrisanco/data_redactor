# Benchmarks

Performance benchmarks for `data_redactor`. **Repo-only** — this directory is
not packaged into the published gem (the gemspec's `files` list does not include
`benchmark/`).

## Running

From the repo root, after compiling the C extension:

```sh
bundle install           # pulls benchmark-ips, benchmark-memory (dev deps)
bundle exec rake compile # build the .so for the current Ruby
bundle exec ruby benchmark/throughput.rb
```

Use `bundle exec ruby` — a bare `ruby` may resolve to a different Ruby than the
one the `.so` was compiled for and fail with `incompatible library version`.

## Scripts

| Script             | Measures |
|--------------------|----------|
| `throughput.rb`    | MB/s of `redact` on a log line, JSON blob, and 1MB/10MB log files; plus `redact_deep` and `scan`. The headline "how fast is it" numbers. |
| `vs_pure_ruby.rb`  | The C extension vs a pure-Ruby `gsub` loop running the **same 88 patterns**. Prints the speedup factor — the C-extension value proposition. |
| `scaling.rb`       | Runtime vs input size (1 KB → 50 MB). MB/s should stay roughly flat, confirming linear scaling. |
| `per_pattern.rb`   | Per-pattern scan cost over a 1 MB payload, sorted slowest-first. Surfaces expensive patterns to target in optimization work. |

## How the comparison stays honest

`vs_pure_ruby.rb` and `per_pattern.rb` do not hard-code pattern strings. They
read `DataRedactor::BUILTIN_PATTERN_SOURCES` / `BUILTIN_PATTERN_BOUNDARY` live
from the compiled extension, so the pure-Ruby baseline runs exactly the same
patterns — boundary wrapper included — as the C engine. No drift from
`ext/data_redactor/patterns.c`.

## Notes

- Numbers are machine-dependent. Run on the target hardware; don't compare
  across machines.
- `benchmark-memory` counts Ruby object allocations only. The C path allocates
  its working buffers in C, invisible to that counter — it understates the C
  path's allocation advantage.
