# DataRedactor

[![Gem Version](https://badge.fury.io/rb/data_redactor.svg)](https://rubygems.org/gems/data_redactor)
[![CI](https://github.com/danielefrisanco/data_redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/danielefrisanco/data_redactor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Ruby gem with a C extension for high-performance regex-based redaction of sensitive data from strings.

## What it does

DataRedactor scans text for sensitive data — API keys and cloud secrets, IBANs,
credit cards, national IDs, emails, phone numbers, IPs, and more — and replaces
each match with a placeholder. The scanning runs in a C extension backed by POSIX
`regex.h`, so the heavy lifting happens outside the Ruby VM and stays fast enough
to run inline on large payloads.

It ships **88 built-in patterns** across 15+ countries, grouped into tags
(`:credentials`, `:financial`, `:contact`, ...) so you can redact only what you
care about. Beyond plain strings it can walk nested Hashes, Arrays, and JSON,
audit a payload without mutating it (`scan`), and plug into Logger, Rails, and
Rack. You can also register your own patterns at boot.

### Use cases

- **Log scrubbing** — drop the `Logger` formatter in so no secret or PII ever
  reaches disk or your log aggregator.
- **Rails parameter filtering** — feed `filter_parameters` a redactor-backed proc
  to keep request params out of logs and error reports.
- **HTTP request/response sanitising** — Rack middleware scrubs response bodies
  and sensitive headers in flight.
- **Sanitising LLM / API payloads** — run `redact_deep` over a params hash or
  `redact_json` over a JSON body before it leaves the process.
- **Compliance & auditing** — `scan` reports every match with byte offsets, tag,
  and pattern name without changing the text, for false-positive tuning.
- **Internal identifiers** — register company-specific patterns (`add_pattern`)
  or generate them from a person's name (`name_pattern`).

## Usage

```ruby
require "data_redactor"

text = "User CF is RSSMRA85M01H501Z and key is AKIAIOSFODNN7EXAMPLE"
DataRedactor.redact(text)
# => "User CF is [REDACTED] and key is [REDACTED]"
```

### Filtering by tag or pattern name

`only:` and `except:` both accept a single value or an Array, mixing **Symbols** (tag names) and **Strings** (specific pattern names).

```ruby
DataRedactor.tags
# => [:credentials, :financial, :tax_id, :national_id, :contact, :network, :travel, :other, :custom]

DataRedactor.pattern_names
# => ["aws_s3_presigned_url", "aws_access_key_id", "email", "phone_e164", "ipv4", ...]

# Tag-level filtering
DataRedactor.redact(text, only: [:credentials])
DataRedactor.redact(text, except: :contact)

# Single specific pattern
DataRedactor.redact(text, only: ["aws_access_key_id"])

# Mix — every credentials pattern PLUS aws_access_key_id (even if it lived in another tag)
DataRedactor.redact(text, only: [:credentials, "aws_access_key_id"])

# Combine — every contact pattern EXCEPT email
DataRedactor.redact(text, only: :contact, except: ["email"])
```

**Precedence:** a pattern is redacted iff `(only is nil OR matches only:)` AND `(does not match except:)`. `except:` always wins when the two overlap, so `only: :contact, except: :contact` produces a no-op (everything is excluded).

**Errors:** an unknown tag Symbol raises `DataRedactor::UnknownTagError`; an unknown pattern name String raises `DataRedactor::UnknownPatternError`.

### Configurable placeholder

By default every match is replaced with `[REDACTED]`. Use the `placeholder:` keyword to change this:

```ruby
# Plain string — any replacement text
DataRedactor.redact(text, placeholder: "***")
DataRedactor.redact(text, placeholder: "")

# Tagged — embeds the pattern's tag name so you know what was redacted
DataRedactor.redact(text, placeholder: :tagged)
# "user@example.com"  → "[REDACTED:CONTACT]"
# "AKIAIOSFODNN7EXAMPLE" → "[REDACTED:CREDENTIALS]"
# "DE89370400440532013000" → "[REDACTED:FINANCIAL]"

# Hash — deterministic 4-hex suffix of the matched value
# Same value always produces the same token — useful for correlating
# redactions across log lines without leaking the original.
DataRedactor.redact(text, placeholder: :hash)
# "user@example.com"  → "[CONTACT_3d7a]"
# "user@example.com"  → "[CONTACT_3d7a]"  (same every time)
# "other@example.com" → "[CONTACT_91fc]"  (different value, different hash)
```

All three modes compose with `only:` and `except:`:

```ruby
DataRedactor.redact(text, only: :contact, placeholder: :tagged)
```

### Scan / dry-run mode

`DataRedactor.scan` returns every match alongside the redacted string — useful for auditing, tuning false positives, and compliance pipelines:

```ruby
result = DataRedactor.scan("User AKIAIOSFODNN7EXAMPLE logged in from 192.168.1.1")
# => {
#   redacted: "User [REDACTED] logged in from [REDACTED]",
#   matches: [
#     { tag: :credentials, name: "aws_access_key_id", value: "AKIAIOSFODNN7EXAMPLE", start: 5,  length: 20 },
#     { tag: :network,     name: "ipv4",              value: "192.168.1.1",          start: 35, length: 11 }
#   ]
# }

# :start and :length are byte offsets into the original string
m = result[:matches].first
original_text.byteslice(m[:start], m[:length])  # => "AKIAIOSFODNN7EXAMPLE"

# Accepts the same filters as redact (tags + specific pattern names)
DataRedactor.scan(text, only: :credentials)
DataRedactor.scan(text, except: :network)
DataRedactor.scan(text, only: :contact, except: ["email"])
```

### Hash / JSON traversal

Redact every string value inside a nested Hash or Array — useful for params hashes, Sidekiq job payloads, webhook bodies, and anything that isn't a flat string:

```ruby
# Hash — returns a deep copy, never mutates the input
result = DataRedactor.redact_deep({
  "user"  => { "email" => "alice@example.com" },
  "count" => 3,
  "tags"  => ["admin", "alice@example.com"]
})
# => { "user" => { "email" => "[REDACTED]" }, "count" => 3, "tags" => ["admin", "[REDACTED]"] }

# Hash keys are never touched — only values are redacted
# Non-string scalars (Integer, Float, nil, Boolean) pass through unchanged

# Accepts the same filters as redact
DataRedactor.redact_deep(params, only: :credentials)
DataRedactor.redact_deep(payload, except: :network, placeholder: :tagged)
```

```ruby
# JSON string — parse → redact_deep → re-serialise
safe_json = DataRedactor.redact_json('{"email":"alice@example.com","count":3}')
# => '{"email":"[REDACTED]","count":3}'

# Raises JSON::ParserError on invalid input
DataRedactor.redact_json("not json")  # => JSON::ParserError
```

### Custom patterns

Teams often have internal IDs that the gem can't ship. Register them at boot:

```ruby
# String (POSIX ERE) or Regexp — both accepted
DataRedactor.add_pattern(name: "employee_id", regex: "EMP-[0-9]{6}")
DataRedactor.add_pattern(name: "ticket_ref",  regex: /TICKET-[A-Z]{2}[0-9]{4}/, boundary: true)

# Custom patterns are tagged :custom by default; pass any built-in tag to group differently
DataRedactor.add_pattern(name: "internal_key", regex: "INT-[A-Z]{3}", tag: :credentials)

DataRedactor.redact(text)                         # runs all patterns including custom
DataRedactor.redact(text, only: [:custom])         # only user patterns
DataRedactor.redact(text, only: [:custom, :credentials]) # mix

DataRedactor.custom_patterns   # => [{name:, source:, tag:, boundary:}, ...]
DataRedactor.remove_pattern("employee_id")
DataRedactor.clear_custom_patterns!               # mostly for test suites
```

**Regex rules** — patterns must be POSIX ERE (the same engine used for built-ins). Not supported: `\d`, `\s`, `\w`, `\b`, lookahead/lookbehind, non-greedy quantifiers, named groups. Violations raise `DataRedactor::InvalidPatternError` at registration time, never at redaction time. Use `[0-9]` instead of `\d`, `[[:space:]]` instead of `\s`, etc.

**`boundary: true`** — wraps the pattern with `(^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)` so it only fires when the token is not embedded in a longer alphanumeric string. Incompatible with patterns that contain capture groups.

### Name patterns

Personal names can't ship as built-ins — every team has different ones — but the regex
boilerplate to match a name across its written variations is the same every time.
`name_pattern` generates that regex for you, ready to hand to `add_pattern`:

```ruby
DataRedactor.add_pattern(
  name:  "person_mario_rossi",
  regex: DataRedactor.name_pattern("Mario", "Rossi"),
  tag:   :contact
)

DataRedactor.redact("ticket from Mario Rossi about ...")
# => "ticket from [REDACTED] about ..."
```

A single generated pattern matches all of these:

- **Case** — `Mario Rossi`, `mario rossi`, `MARIO ROSSI`
- **Order** — `Mario Rossi`, `Rossi Mario`, `Rossi, Mario`, `Rossi,Mario`
- **Initials** — `M. Rossi`, `M Rossi`, `Mario R.`, `M.R.`, `MR`
- **Diacritics** — `name_pattern("Jose", "Munoz")` also matches `José Muñoz` (and vice versa)
- **Separators** — spaces and hyphens are interchangeable. `name_pattern("Anne-Marie", "Berg")`
  matches `Anne-Marie Berg`, `Anne Marie Berg`, `AnneMarie Berg`, and each half alone
  (`Anne Berg`, `Marie Berg`). Multi-word parts like `"Van der Berg"` tolerate any
  space/hyphen separator between words.

It does **not** match a name embedded in a longer word — `Mario` will not fire inside
`Mariolino` — because the generated pattern is boundary-wrapped. For that reason, register
it with the default `boundary: false` (the wrapper is already baked into the returned
string; `boundary: true` would double-wrap and reject its capture groups).

Pass `middle:` to also cover a middle name — both the no-middle and with-middle forms match:

```ruby
DataRedactor.name_pattern("Mario", "Rossi", middle: "Luigi")
# matches "Mario Rossi" AND "Mario Luigi Rossi" AND "Rossi Mario Luigi"
```

## Integrations

Optional adapters for Logger, Rails, and Rack. None are loaded automatically — `require` only what you use, and the gem adds zero runtime dependencies in the gemspec.

### Logger formatter

Drop-in `Logger::Formatter` replacement that scrubs every emitted line:

```ruby
require "data_redactor/integrations/logger"

logger = Logger.new($stdout)
logger.formatter = DataRedactor::Integrations::Logger.new
logger.info("Auth failed for alice@example.com")
# => I, [...] -- : Auth failed for [REDACTED]
```

Wraps an inner formatter (defaults to `Logger::Formatter`), so it composes with structured loggers. Forwards `only:`, `except:`, `placeholder:` to `DataRedactor.redact`. Exception messages and arbitrary objects are scrubbed too — the wrapped object is passed unchanged to the inner formatter so the exception cause chain is preserved; only the rendered string is redacted.

### Rails `filter_parameters` adapter

```ruby
# config/initializers/filter_parameter_logging.rb
require "data_redactor/integrations/rails"

Rails.application.config.filter_parameters += [
  DataRedactor::Integrations::Rails.filter
]
```

Returns a `(key, value)` proc compatible with Rails' parameter filter. String values are mutated in place via `String#replace` so Rails sees the redacted value. Non-strings are left alone. Accepts the same `only:`/`except:`/`placeholder:` kwargs.

### Rack middleware

```ruby
# config.ru
require "data_redactor/integrations/rack"

use DataRedactor::Integrations::Rack, scrub: [:body, :headers]
run MyApp
```

`scrub:` selects which surfaces to redact (default `[:body, :headers]`):

- **`:body`** — buffers the response body, runs `DataRedactor.redact` over it, returns it as a single chunk. Drops the `Content-Length` header so the server recomputes (the redacted body may differ in byte length).
- **`:headers`** — scrubs sensitive **response** headers (`Set-Cookie`, `Authorization`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`) in place, and sensitive **request** headers (`HTTP_AUTHORIZATION`, `HTTP_PROXY_AUTHORIZATION`, `HTTP_COOKIE`, `HTTP_X_API_KEY`, `HTTP_X_AUTH_TOKEN`, `HTTP_X_ACCESS_TOKEN`) in the env hash so any downstream middleware that logs them sees redacted values.

Pass an empty subset (e.g. `scrub: [:headers]`) to opt out of body wrapping. Forwards `only:`/`except:`/`placeholder:` to `DataRedactor.redact`. Unknown surfaces raise `ArgumentError` at boot.

> **Body wrapping is buffering.** The middleware reads the entire response body into memory before scanning. For streaming endpoints (SSE, large file downloads, Rack::Hijack) use `scrub: [:headers]` and rely on the Logger formatter for application logs instead.

## Detected patterns (88 total)

The table below is a representative sample. Use `DataRedactor.pattern_names` for the canonical, machine-readable list — it stays in sync with the C extension automatically.

### Cloud & API secrets

| # | Pattern | Example |
|---|---|---|
| — | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| — | AWS Secret Access Key | 40-character base64 string |
| — | Google API Key | `AIzaSyXXXX...` |
| — | GitHub Personal Access Token | `github_pat_XXXX...` |
| — | GitHub Classic PAT / OAuth | `ghp_XXXX...` / `gho_XXXX...` |
| — | Slack Webhook URL | `https://hooks.slack.com/services/T.../B.../...` |
| — | Stripe Secret Key | `sk_live_XXXX...` |
| — | Anthropic API Key | `sk-ant-api03-XXXX...` |
| — | OpenAI Project API Key | `sk-proj-XXXX...` |
| — | GitLab Personal Access Token | `glpat-XXXX...` |
| — | DigitalOcean PAT | `dop_v1_XXXX...` |
| — | Databricks API Token | `dapiXXXX...` |
| — | Sentry DSN | `https://KEY@oNNN.ingest.sentry.io/PID` |
| — | PEM Private Key header | `-----BEGIN RSA PRIVATE KEY-----` |
| — | Scaleway Access Key | `SCW12345ABCDE6789FGHIJ` |
| — | UUID v4 / Scaleway Secret Key | `550e8400-e29b-41d4-a716-446655440000` |

### Travel documents

| # | Pattern | Example |
|---|---|---|
| 2 | Italian Codice Fiscale (basic) | `RSSMRA85M01H501Z` |
| 3 | Passport — letter prefix + digits | `AB1234567` |
| 4 | Passport — 9 consecutive digits ¹ | `123456789` |
| 22 | Italian Codice Fiscale (omocodia) | `RSSMRALPMNLH5LMZ` |

### Payment & network

| # | Pattern | Example |
|---|---|---|
| 11 | Credit card — Visa, Mastercard, Amex, Discover, JCB | `4111111111111111` |
| 12 | IPv4 address | `192.168.1.100` |

### IBANs

| # | Country | Example |
|---|---|---|
| 10 | Italy | `IT60X0542811101000000123456` |
| 15 | France | `FR7630006000011234567890189` |
| 16 | Germany | `DE89370400440532013000` |
| 17 | Spain | `ES9121000418450200051332` |
| 18 | Netherlands | `NL91ABNA0417164300` |
| 19 | Belgium | `BE68539007547034` |
| 20 | Portugal | `PT50000201231234567890154` |
| 21 | Ireland | `IE29AIBK93115212345678` |
| 28 | Sweden | `SE4550000000058398257466` |
| 29 | Denmark | `DK5000400440116243` |
| 30 | Norway | `NO9386011117947` |
| 31 | Finland | `FI2112345600000785` |
| 37 | Poland | `PL61109010140000071219812874` |
| 38 | Austria | `AT611904300234573201` |
| 39 | Switzerland | `CH9300762011623852957` |
| 40 | Czechia | `CZ6508000000192000145399` |
| 41 | Hungary | `HU42117730161111101800000000` |
| 42 | Romania | `RO49AAAA1B31007593840000` |

### National personal identifiers

| # | Country | Type | Example |
|---|---|---|---|
| 23 | France | NIR / Social Security ¹ | `185126203450342` |
| 24 | Spain | DNI ¹ | `12345678Z` |
| 25 | Spain | NIE | `X1234567L` |
| 26 | Netherlands | BSN ¹ | `123456789` |
| 27 | Poland | PESEL ¹ | `85121612345` |
| 32 | Belgium | National Number ¹ | `85121612345` |
| 33 | Sweden | Personnummer ¹ | `850101-1234` |
| 34 | Denmark | CPR Number ¹ | `010185-1234` |
| 35 | Norway | Fødselsnummer ¹ | `01018512345` |
| 36 | Finland | HETU ¹ | `010185-123A` |
| 43 | Poland | PESEL (alt slot) ¹ | `90010112345` |
| 44 | Austria | Abgabenkontonummer ¹ | `123456789` |
| 45 | Switzerland | AHV Number ¹ | `756.1234.5678.90` |
| 46 | Czechia | Rodné číslo ¹ | `856121/1234` |
| 47 | Hungary | Tax ID ¹ | `8012345678` |
| 48 | Romania | CNP ¹ | `1850101123456` |

> ¹ **Word-boundary protected** — these patterns are wrapped with `(^|[^0-9A-Za-z])(PATTERN)([^0-9A-Za-z]|$)` at compile time so they do not fire when the digit sequence appears inside a longer alphanumeric token.

## Directory structure

```
redactor/
├── data_redactor.gemspec
├── Gemfile
├── Rakefile
├── lib/
│   ├── data_redactor.rb          # Ruby entry point, loads the .so
│   └── data_redactor/
│       ├── version.rb
│       ├── name_pattern.rb        # name_pattern helper — generates a name regex for add_pattern
│       └── integrations/          # soft-required Logger / Rails / Rack adapters
├── ext/
│   └── data_redactor/
│       ├── extconf.rb            # Checks for C headers, generates Makefile (globs *.c)
│       ├── data_redactor.c       # Entry point: Init_data_redactor only
│       ├── patterns.{c,h}        # Built-in pattern table + compiled regex_t array
│       ├── placeholder.{c,h}     # write_placeholder, djb2 hash, tag_name_for_bit
│       ├── redact.{c,h}          # _redact + replace_all_matches + wrap_boundary
│       ├── scan.{c,h}            # _scan + byte-offset replacement-log macros
│       ├── custom_patterns.{c,h} # Dynamic registry: add/remove/clear/list
│       └── tags.h                # TAG_* bit constants
├── spec/
│   └── data_redactor_spec.rb     # RSpec tests — at least one example per pattern, plus filter / placeholder / custom-pattern coverage
├── benchmark/                    # Repo-only perf scripts (not packaged in the gem)
│   ├── README.md                 # How to run, what each script measures
│   ├── support/corpus.rb         # Shared payload builders + pure-Ruby baseline redactor
│   ├── throughput.rb             # MB/s on representative payloads
│   ├── vs_pure_ruby.rb           # C extension vs pure-Ruby gsub (same 88 patterns)
│   ├── scaling.rb                # Runtime vs input size 1KB → 50MB
│   └── per_pattern.rb            # Per-pattern scan cost
└── docs/                         # Design and execution docs for future work
    ├── standalone_matcher_design.md
    └── combined_matcher_plan.md
```

## Requirements

- Ruby >= 2.7
- A C compiler (`gcc` or `clang`) — only required when installing the source gem
- POSIX `regex.h` — only required when installing the source gem (standard on Linux and macOS)

## Installation

```ruby
# Gemfile
gem "data_redactor"
```

```bash
bundle install
```

That's it — there is nothing extra to configure for precompiled binaries. Bundler/RubyGems looks at your platform and Ruby version and picks the right gem automatically.

### What you'll see

- **On a supported platform** (Linux glibc/musl, macOS Intel/ARM): bundler downloads a precompiled gem with the C extension already built. Install is near-instant — **no compiler, no `make`, no `regex.h` headers needed**. Especially valuable in slim Docker images (`ruby:3.x-alpine`, `ruby:3.x-slim`) that don't ship `gcc`.
- **On any other platform** (FreeBSD, OpenBSD, etc.): bundler downloads the source gem and compiles the C extension on install — the same behavior as before 0.7.1. You'll need a C compiler and POSIX `regex.h` available.

### Supported precompiled targets

Each precompiled gem ships compiled binaries for Ruby 3.1, 3.2, 3.3, and 3.4.

| Platform | Targets |
|---|---|
| Linux (glibc) | `x86_64-linux`, `aarch64-linux` |
| Linux (musl / Alpine) | `x86_64-linux-musl`, `aarch64-linux-musl` |
| macOS | `x86_64-darwin` (Intel), `arm64-darwin` (Apple Silicon) |

### Bundler-locked deploys

If your `Gemfile.lock` was generated on one platform but you deploy to another, run `bundle lock --add-platform <target>` so bundler resolves the right native gem at deploy time. Example for Alpine deploys built from a glibc dev box:

```bash
bundle lock --add-platform x86_64-linux-musl aarch64-linux-musl
```

## Compile the C extension (source / development install only)

```bash
bundle exec rake compile
```

This runs `extconf.rb` via `rake-compiler`, which generates a `Makefile` and compiles `data_redactor.c` into a `.so` shared library placed under `lib/data_redactor/`.

## Building precompiled gems locally

Maintainers can rebuild the full set of native gems with one command (requires Docker):

```bash
bundle exec rake gem:all
```

This invokes `rake-compiler-dock` to cross-compile every supported (platform × Ruby ABI) combination. Output lands in `pkg/`.

## Run the tests

```bash
bundle exec rake spec
```

Or compile and test in one step:

```bash
bundle exec rake
```

## Benchmarks

The `benchmark/` directory holds four scripts that measure the C engine under
different angles. They are **not** packaged with the gem.

```bash
bundle install                                   # pulls benchmark-ips, benchmark-memory (dev deps)
bundle exec rake compile
bundle exec ruby benchmark/vs_pure_ruby.rb       # head-to-head vs pure-Ruby gsub, same 88 patterns
bundle exec ruby benchmark/throughput.rb         # MB/s on a log line, JSON, 1MB and 10MB log files
bundle exec ruby benchmark/scaling.rb            # runtime vs input size (1KB → 50MB), confirms linear scaling
bundle exec ruby benchmark/per_pattern.rb        # per-pattern scan cost over a 1MB payload
```

See [`benchmark/README.md`](benchmark/README.md) for what each script measures
and how the pure-Ruby baseline is kept honest (it reads the same patterns the
C engine uses, via `DataRedactor::BUILTIN_PATTERN_SOURCES`).

### Where we are today (May 2026)

Recorded so we know where we started when the next round of perf work lands.

| Payload                     | C extension     | Pure-Ruby `gsub` | C vs Ruby      |
|-----------------------------|-----------------|------------------|----------------|
| log line (168 B)            | 0.30 ms / call  | 0.07 ms / call   | 3.4× slower    |
| JSON blob (~580 B)          | 0.92 ms / call  | 0.18 ms / call   | 5.0× slower    |
| 100 log lines (~17 KB)      | 26.5 ms / call  | 6.1 ms / call    | 4.4× slower    |
| 1 MB log                    | 1.62 s / call   | 0.38 s / call    | 4.25× slower   |
| 10 MB log                   | ~15 s           | ~3.8 s           | ~4× slower     |

The C extension is currently **3-5× slower than pure-Ruby `gsub` at every
size measured.** The cause is structural — glibc's POSIX `regexec` lacks
the Boyer-Moore literal pre-filter that Ruby's Onigmo engine has built in —
and is documented in detail under [Known limitations](#known-limitations).
Two perf fixes have already shipped (a `strstr` literal pre-filter and
chunked input above 64 KB), which got us 25-30% faster and restored linear
scaling, but the absolute gap remains.

The long-term plan is a combined multi-pattern matcher
([design doc](docs/standalone_matcher_design.md),
[execution plan](docs/combined_matcher_plan.md)) that compiles all 88
patterns into one automaton and walks the input once. That's expected to
make the C extension genuinely the fastest option in Ruby; until it ships,
use the gem on small payloads where absolute latency is acceptable
(< 1 ms for typical log lines).

## How it works

1. At load time, `Init_data_redactor` compiles all 85 regex patterns once using `regcomp` (POSIX ERE) and stores them as static `regex_t` structs. Patterns marked as boundary-wrapped are expanded with `wrap_boundary()` before compilation.
2. `DataRedactor.redact(text)` receives a Ruby `String`, converts it to a C `char*` via `StringValueCStr`, and runs each compiled pattern in sequence on a working buffer.
3. For each pattern, `replace_all_matches` iterates using `regexec`, copies non-matching segments to a fresh output buffer, and inserts `[REDACTED]` in place of each match. For boundary-wrapped patterns, `regexec` is called with `nmatch=4` and sub-match groups `[1]`/`[3]` identify the boundary characters so they are preserved verbatim.
4. The output buffer is grown with `realloc` as needed. After all patterns are applied the result is returned as a Ruby `String` via `rb_str_new_cstr`. All intermediate `malloc`/`strdup` allocations are explicitly `free`d.

## Memory management

All C-side buffers are heap-allocated with `malloc`/`strdup` and freed before the function returns. The only Ruby-managed allocation is the final return value from `rb_str_new_cstr`. No Ruby objects are created mid-processing, so GC cannot collect anything out from under the C code.

## Thread safety

`DataRedactor.redact` and `DataRedactor.scan` are safe to call concurrently from multiple threads. Built-in patterns are compiled into a static `regex_t` array at load time and never mutated afterward, and each call allocates its own working buffers. POSIX `regexec` is documented as thread-safe.

`DataRedactor.add_pattern`, `remove_pattern`, and `clear_custom_patterns!` mutate a shared dynamic array and are **not** thread-safe. Register custom patterns once at boot — before spawning worker threads or forking — and they will be visible (read-only) to every subsequent `redact`/`scan` call.

## Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Until `1.0.0`, minor versions may introduce breaking changes; from `1.0.0` onward, breaking changes will only land in major versions. See [CHANGELOG.md](CHANGELOG.md) for the release history.

## License

Released under the [MIT License](LICENSE).

## Known limitations

- **Pattern ordering matters** — patterns run sequentially. An early broad pattern (e.g. the 9-digit passport) may consume digits that a later pattern (e.g. credit card) depends on. Boundary wrapping mitigates this for pure-digit patterns.
- **AWS Secret Key (pattern 1)** — 40 consecutive base64 characters is a broad match. It can produce false positives in base64-encoded content such as embedded images or binary blobs.
- **Duplicate digit patterns** — several national ID formats share the same digit-length (11 digits: PESEL, Norwegian Fødselsnummer, Belgian National Number). They are kept as separate slots for clarity but the practical effect is that any 11-digit boundary-delimited number will be redacted.
- **Performance is currently slower than pure-Ruby `gsub`.** A May 2026 investigation found the C extension is 3–5× slower than a pure-Ruby `gsub` loop running the same 88 patterns, across input sizes from 168 bytes to 1 MB. The root cause is glibc's POSIX `regexec()`: each call allocates an O(input-length) state buffer before any matching begins, and the gem calls it once per pattern in sequence. Ruby's Onigmo engine wins by using a built-in Boyer-Moore literal pre-filter that this gem can only approximate. Two perf fixes have shipped (buffer-sizing in `replace_all_matches`, a `strstr` literal pre-filter, and input chunking for large payloads), which gave ~25-30% improvement and made scaling linear, but the absolute gap remains. Use the gem on small payloads where the absolute latency is still acceptable (< 1 ms for typical log lines); for high-throughput pipelines, hold off until the next major release. See `docs/standalone_matcher_design.md` for the long-term plan.
