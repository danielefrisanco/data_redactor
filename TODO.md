# TODO

## References
- https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- https://github.com/advanced-security/secret-scanning-custom-patterns
- https://github.com/gitleaks/gitleaks/tree/master

## Additional patterns to add (from former plan.md)

Distinctive-prefix API keys with low false-positive risk — easy wins once the tag system (item 1 below) lands so they can be grouped under `:credentials`:

- Anthropic API Key (`sk-ant-api03-...`)
- OpenAI API Key (`sk-proj-...`)
- GitLab PAT (`glpat-...`)
- DigitalOcean PAT (`dop_v1_...`)
- Heroku API Key
- Databricks API Token (`dapi...`)
- Okta API Token
- Azure SQL hostname
- DataDog API Key (needs context prefix to avoid FPs)
- Sentry DSN
- PagerDuty API Key

## Roadmap to a usable gem

### 1. Tagged categories (highest impact)
Group every pattern by a tag (`:credentials`, `:tax_id`, `:national_id`, `:financial`, `:contact`, `:network`, `:travel`, `:other`) and let callers opt in/out:

```ruby
DataRedactor.redact(text, only:   [:credentials, :financial])
DataRedactor.redact(text, except: [:contact])
```

Implementation note: the tier comments in `ext/data_redactor/data_redactor.c` already group patterns — add a parallel `pattern_tags[]` array and an active-mask the Ruby side passes down to `rb_data_redactor_redact`. Per the existing TODO note: an active/inactive array the user toggles.

### 2. User-supplied custom patterns
Every team has internal IDs (employee numbers, customer codes, internal URLs) the gem can't ship.

```ruby
DataRedactor.add_pattern(name: "employee_id", regex: /EMP-\d{6}/, tag: :other)
```

Compile on add, store in a separate dynamic array alongside the static ones.

### 3. Configurable placeholder
Default stays `[REDACTED]`. Allow:
- Plain string: `placeholder: "***"`
- Tagged: `[REDACTED:EMAIL]` (which pattern fired)
- Deterministic hash: `[EMAIL_a3f9]` so log pipelines can correlate redactions without leaking the value

### 4. Report / dry-run mode
Return matches alongside (or instead of) the redacted string — required for audit/compliance and for tuning false positives.

```ruby
DataRedactor.scan(text)
# => { redacted: "...", matches: [{tag: :credentials, name: "aws_access_key", span: [42, 62]}, ...] }
```

### 5. Hash / JSON / object traversal
Pure-Ruby walker on top of the C `redact`:

```ruby
DataRedactor.redact_deep(params_hash)
DataRedactor.redact_json(json_string)
```

### 6. Allowlist / ignore list
Escape hatch for the broad patterns we already flag (40-char base64, 9-digit passport, etc.):

```ruby
DataRedactor.redact(text, ignore: [/example\.com/, "test@foo.com"])
```

### 7. Checksum validation
Massive false-positive killer. Apply only when the structural regex matches:
- Luhn for credit cards
- mod-97 for IBANs
- Italian Codice Fiscale check character
- Spanish DNI letter
- Brazilian CPF/CNPJ check digits
- PESEL, CNP, etc.

Probably an opt-in flag per call (`strict: true`) since validation costs CPU.

### 8. Streaming API
Defer until 1+2 land. Chunk boundaries can split a match — needs an overlap/lookback window equal to the longest pattern.

```ruby
DataRedactor.redact_stream(input_io, output_io)
```

### 9. Rails / Rack integration
What turns "neat gem" into "we put it in production":
- `Logger` formatter that wraps messages
- `Rails.application.config.filter_parameters` adapter
- Rack middleware that scrubs request/response bodies

### 10. Distribution / quality of life
- Publish to RubyGems (we are still 0.1.0, unpublished)
- CI matrix: Ruby 2.7, 3.0, 3.1, 3.2, 3.3 on Linux + macOS
- Precompiled binaries via `rake-compiler-dock` so `gem install` doesn't need a C toolchain — biggest reason people skip C-extension gems
- CHANGELOG.md + semver commitment
- Thread-safety note in README (compiled `regex_t` array is read-only after init)

## Benchmarks

Add a `benchmark/` directory with scripts using `benchmark-ips` and `benchmark/memory`:

- `benchmark/throughput.rb` — MB/s on representative payloads (log line, JSON blob, 1MB log file, 10MB log file)
- `benchmark/per_pattern.rb` — cost of each pattern in isolation, to spot the expensive ones
- `benchmark/vs_pure_ruby.rb` — head-to-head against a pure-Ruby `gsub` loop with the same patterns, to demonstrate the C extension's value
- `benchmark/vs_alternatives.rb` — vs. existing gems (e.g. `pii-redactor`, `personally_identifiable_information`) on the same input
- `benchmark/scaling.rb` — runtime vs. input size (1KB → 100MB) to confirm linear scaling

Publish numbers in the README — the C extension is the differentiator and the current README does not show it off.
