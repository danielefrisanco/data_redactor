# Examples

Runnable, copy-pasteable usage for `data_redactor`. Each script is self-contained
and depends only on the gem plus the Ruby standard library — no extra gems, not
even `rack` or `rails` (the framework examples call the adapters directly so they
run anywhere).

## Running

From the repo root, after building the C extension:

```sh
bundle exec rake compile
bundle exec ruby examples/basic_redact.rb
```

Use `bundle exec ruby` so the `.so` matches the Ruby it was compiled for. With
the gem installed system-wide (`gem install data_redactor`) you can run a bare
`ruby examples/basic_redact.rb` instead.

## Scripts

| Script | Shows |
|--------|-------|
| `basic_redact.rb`    | `redact` — the one method you need most. Tag filters (`only:`/`except:`) and all three placeholder modes. |
| `scan_report.rb`     | `scan` dry-run: what *would* be redacted, with byte offsets back into the original. |
| `custom_pattern.rb`  | `add_pattern` for internal IDs and `name_pattern` for people's names (diacritics-aware). |
| `deep_and_json.rb`   | `redact_deep` (nested Hash/Array) and `redact_json` — string leaves only, input never mutated. |
| `logger.rb`          | `Logger::Formatter` integration — scrub every log line automatically. |
| `rack_middleware.rb` | Rack middleware scrubbing response body + sensitive headers (runs without the `rack` gem). |
| `rails_filter.rb`    | `config.filter_parameters` adapter for scrubbing Rails request params in logs. |
| `llm_payload.rb`     | Claude / OpenAI message + response redaction before calling the API or logging. |
