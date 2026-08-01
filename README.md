# DataRedactor

[![Gem Version](https://badge.fury.io/rb/data_redactor.svg)](https://rubygems.org/gems/data_redactor)
[![CI](https://github.com/danielefrisanco/data_redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/danielefrisanco/data_redactor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Ruby gem with a C extension for high-performance regex-based redaction of sensitive data from strings.

📚 **Deeper docs live in the [wiki](https://github.com/danielefrisanco/data_redactor/wiki):** the full [pattern catalogue](https://github.com/danielefrisanco/data_redactor/wiki/Pattern-Catalogue), [C engine internals](https://github.com/danielefrisanco/data_redactor/wiki/C-Engine-Internals), [integration guides](https://github.com/danielefrisanco/data_redactor/wiki/Integration-Guides) (incl. [RubyLLM](https://github.com/danielefrisanco/data_redactor/wiki/RubyLLM-Integration)), [benchmark methodology](https://github.com/danielefrisanco/data_redactor/wiki/Performance-and-Benchmarks), and [FAQ](https://github.com/danielefrisanco/data_redactor/wiki/FAQ). The [API reference](https://danielefrisanco.github.io/data_redactor/) is on GitHub Pages.

> 📄 The engineering behind the v19 matching engine is written up as an experience
> report, *"The Fastest Engine Is Not the Shippable Engine: Replacing a Regex Engine
> for Data Redaction Under Production Constraints,"* currently under review at
> *Software: Practice and Experience* (Manuscript ID 7985366). Source and the
> reproducibility bundle are in [`paper/`](paper/).

## What it does

DataRedactor scans text for sensitive data — API keys and cloud secrets, IBANs,
credit cards, national IDs, emails, phone numbers, IPs, and more — and replaces
each match with a placeholder. The scanning runs in a C extension backed by a
zero-dependency Thompson NFA → lazy-DFA multi-pattern engine (v19) that scans
every built-in pattern in a single pass — 2–2.5× faster than pure-Ruby `gsub`
on large payloads, with no external library dependencies.

It ships **89 built-in patterns** across 15+ countries, grouped into tags
(`:credentials`, `:financial`, `:contact`, ...) so you can redact only what you
care about. Beyond plain strings it can walk nested Hashes, Arrays, and JSON,
audit a payload without mutating it (`scan`), and plug into Logger, Rails, and
Rack. You can also register your own patterns — at boot or at runtime from any thread.

### Use cases

- **Log scrubbing** — drop the `Logger` formatter in so no secret or PII ever
  reaches disk or your log aggregator.
- **Rails, zero-config** — one Gemfile line wires both the log formatter and
  `filter_parameters`; unlike `filter_parameters` alone, it also catches secrets
  in free text you can't enumerate by key.
- **HTTP request/response sanitising** — Rack middleware scrubs response bodies
  and sensitive headers in flight.
- **Scrubbing prompts before an LLM** — with [RubyLLM](#rubyllm--redact-before-it-reaches-the-model), redact every
  prompt, system instruction, and tool result before it reaches the model —
  per-call, or transparently across every request. Also `redact_deep` /
  `redact_json` over any params hash or JSON body before it leaves the process.
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

Prefer runnable code? The [`examples/`](examples/) directory has self-contained,
copy-pasteable scripts for every feature below — core redaction, scan/dry-run,
custom patterns, deep/JSON traversal, and the Logger / Rack / Rails / LLM
integrations. Run any of them with `bundle exec ruby examples/<name>.rb` (see
[examples/README.md](examples/README.md)).

### RubyLLM — redact before it reaches the model

[RubyLLM](https://rubyllm.com) is a unified Ruby client for every major LLM provider — Anthropic, OpenAI, Gemini, Bedrock, and more — and a perfect match for `data_redactor`: anything you send to a model is exactly the kind of free text that leaks secrets and PII. Because RubyLLM takes plain strings, you can scrub them with `DataRedactor.redact` before they leave the process — no extra integration required:

```ruby
require "ruby_llm"
require "data_redactor"

chat = RubyLLM.chat(model: "claude-opus-4-8")
chat.with_instructions(DataRedactor.redact("You are a support agent for ACME Corp."))

user_input = "My card is 4111 1111 1111 1111 and my email is alice@example.com"
chat.ask(DataRedactor.redact(user_input))
# the model receives: "My card is [REDACTED] and my email is [REDACTED]"
```

Wrap each prompt (and any `with_instructions` system prompt) in `DataRedactor.redact` before passing it to `ask`. This is a per-call step you opt into, and it's the recommended approach.

#### Transparent mode (every request, no per-call wrapping)

If you'd rather redact **every** outbound request automatically — including the system prompt, tool definitions, and any file contents or shell-command output an agent feeds back as a tool result — opt into the monkeypatch:

```ruby
require "ruby_llm"
require "data_redactor/integrations/ruby_llm"

DataRedactor::Integrations::RubyLLM.install!   # once, at boot

chat = RubyLLM.chat(model: "claude-opus-4-8")
chat.ask("my card is 4111111111111111")        # sent as "my card is [REDACTED]"
```

`install!` prepends a patch onto `RubyLLM::Protocol#render` — the one point where every provider (Anthropic, OpenAI, Gemini, Bedrock, Responses) has assembled its final request — and deep-redacts the payload before it's posted. It forwards `only:`/`except:`/`placeholder:`, is idempotent, and **fails fast** at `install!` if an unsupported `ruby_llm` version is loaded or the internal API has moved (so it never silently leaks).

Two caveats, by design:

- **It's a monkeypatch on RubyLLM internals**, pinned to a supported version range. Prefer per-call `DataRedactor.redact` (above) unless you specifically need transparency. RubyLLM does not yet expose a public request hook ([crmne/ruby_llm#765](https://github.com/crmne/ruby_llm/issues/765) tracks the connection-middleware hook that would let us drop the patch).
- **Base64 attachments** (PDFs, images, audio sent inline) and **URL-referenced files** are not redacted — the sensitive bytes are encoded or remote, so patterns cannot see them.

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

# Length — embeds the byte length of the redacted value, so readers can
# gauge what was there without seeing it.
DataRedactor.redact(text, placeholder: :length)
# "user@example.com"  → "[REDACTED:16]"

# Tagged length — tag name plus byte length.
DataRedactor.redact(text, placeholder: :tagged_length)
# "user@example.com"  → "[REDACTED:CONTACT:16]"
```

All modes compose with `only:` and `except:`:

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

### `#redact` refinements (opt-in)

Prefer `"text".redact` over `DataRedactor.redact("text")`? Opt into the refinement. It adds `#redact` to `String` (via `redact`) and to `Hash`/`Array` (via `redact_deep`) **only in the files that `using` it** — refinements are lexically scoped, so the core classes are never monkey-patched globally and there is no collision risk for apps that don't opt in. `DataRedactor.redact` remains the primary API.

```ruby
require "data_redactor/refinements"
using DataRedactor::Refinements

"email alice@example.com".redact            # => "email [REDACTED]"
{ token: "AKIAIOSFODNN7EXAMPLE" }.redact    # => { token: "[REDACTED]" }
["a@b.com", 3].redact                       # => ["[REDACTED]", 3]

# Handy right before sending text to an LLM:
chat.ask(user_input.redact)
```

`#redact` forwards `only:`/`except:`/`placeholder:` and never mutates the receiver. Without `using DataRedactor::Refinements` in the current file, `#redact` is not defined.

### Custom patterns

Teams often have internal IDs that the gem can't ship. Register them at boot — or at runtime from any thread (registration is thread-safe, see [Thread safety](#thread-safety)):

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

### Rails (zero-config)

One Gemfile line wires both Rails surfaces — the log formatter and `filter_parameters`:

```ruby
# Gemfile
gem "data_redactor", require: "data_redactor/railtie"
```

That's the whole setup. `filter_parameters` on its own only redacts the keys you name; data_redactor also catches the card number sitting inside an exception message or a free-text field you can't enumerate in advance.

Tune it from an initializer:

```ruby
# config/initializers/data_redactor.rb
Rails.application.configure do
  config.data_redactor.only        = [:credentials, :financial]
  config.data_redactor.placeholder = :tagged
  config.data_redactor.logger      = false   # leave the logger alone
end
```

| Option | Default | Effect |
| --- | --- | --- |
| `logger` | `true` | Wrap the Rails logger's formatter |
| `filter_parameters` | `true` | Append a redacting `filter_parameters` entry |
| `only` / `except` | `nil` | Forwarded to `DataRedactor.redact` |
| `placeholder` | `"[REDACTED]"` | Forwarded to `DataRedactor.redact` |

The logger initializer runs after Rails' own, so it **wraps** whatever formatter your app ended up with (lograge, a JSON formatter) rather than replacing it, and it descends into `ActiveSupport::BroadcastLogger` to wrap each sink. Rails stays a development dependency — the Railtie file is only loaded when you require it.

Prefer wiring the two surfaces by hand? Both are documented below.

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

### Claude / OpenAI LLM payloads

Sanitize LLM message payloads before they leave the process, and scrub responses before they're logged or stored. Both adapters operate on plain Ruby Hashes/Arrays (String **or** Symbol keys), so they work with the `anthropic`/`openai` gems, a raw HTTP client, or parsed JSON — no runtime dependency on any SDK. They **return a deep copy and never mutate your input**, and forward `only:`/`except:`/`placeholder:` to `DataRedactor.redact`.

```ruby
require "data_redactor/integrations/claude"

# Redact a messages array before sending to Claude
safe_messages = DataRedactor::Integrations::Claude.redact_messages(messages)
client.messages.create(model: "claude-opus-4-8", max_tokens: 1024, messages: safe_messages)

# Redact the response (assistant content blocks) before logging
safe_response = DataRedactor::Integrations::Claude.redact_response(response)
```

```ruby
require "data_redactor/integrations/openai"

# Redact a messages array before sending to OpenAI
safe_messages = DataRedactor::Integrations::OpenAI.redact_messages(messages)
client.chat(parameters: { model: "gpt-4o", messages: safe_messages })

# Redact the response (choices[].message.content) before logging
safe_response = DataRedactor::Integrations::OpenAI.redact_response(response)
```

`content` may be a plain String or an array of content blocks/parts (`{ type: "text", text: "..." }`) — only the `text` of `text` blocks is redacted; image and other block types pass through untouched. For Claude, a top-level `system:` String is also redacted; for OpenAI, a `{ role: "system" }` message in the array is redacted like any other. Pass a bare `messages` array or the whole request Hash (with a `messages` key) — either works. For [RubyLLM](#rubyllm--redact-before-it-reaches-the-model) — a unified client across every provider — see the dedicated section above, including transparent `install!` mode.

## Detected patterns (89 total)

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
│       ├── railtie.rb             # opt-in Rails Railtie — wires logger + filter_parameters
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
├── examples/                     # Repo-only runnable usage scripts (not packaged in the gem)
│   ├── README.md                 # Index + how to run
│   ├── basic_redact.rb           # redact, tag filters, placeholder modes
│   ├── scan_report.rb            # scan dry-run with byte offsets
│   ├── custom_pattern.rb         # add_pattern + name_pattern
│   ├── deep_and_json.rb          # redact_deep / redact_json
│   ├── logger.rb                 # Logger::Formatter integration
│   ├── rack_middleware.rb        # Rack middleware (body + headers)
│   ├── rails_filter.rb           # filter_parameters adapter
│   ├── rails_logger.rb           # Rack middleware + redacting Logger, end-to-end
│   └── llm_payload.rb            # Claude / OpenAI message + response redaction
├── benchmark/                    # Repo-only perf scripts (not packaged in the gem)
│   ├── README.md                 # How to run, what each script measures
│   ├── support/corpus.rb         # Shared payload builders + pure-Ruby baseline redactor
│   ├── throughput.rb             # MB/s on representative payloads
│   ├── vs_pure_ruby.rb           # C extension vs pure-Ruby gsub (same patterns)
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
bundle exec ruby benchmark/vs_pure_ruby.rb       # head-to-head vs pure-Ruby gsub, same patterns
bundle exec ruby benchmark/throughput.rb         # MB/s on a log line, JSON, 1MB and 10MB log files
bundle exec ruby benchmark/scaling.rb            # runtime vs input size (1KB → 50MB), confirms linear scaling
bundle exec ruby benchmark/per_pattern.rb        # per-pattern scan cost over a 1MB payload
```

See [`benchmark/README.md`](benchmark/README.md) for what each script measures
and how the pure-Ruby baseline is kept honest (it reads the same patterns the
C engine uses, via `DataRedactor::BUILTIN_PATTERN_SOURCES`).

### Performance (0.10.0 — v19 multi-pattern engine)

Measured on the v19 engine ([How it works](#how-it-works)) vs a pure-Ruby `gsub`
loop over the same patterns:

| Payload               | v19 engine (0.10.0) | Pure-Ruby `gsub` | Ratio           |
|-----------------------|---------------------|------------------|-----------------|
| log line (168 B)      | 41 µs / call        | 71 µs / call     | **1.7× faster** |
| JSON blob (~580 B)    | 81 µs / call        | 132 µs / call    | **1.6× faster** |
| 8 log lines (1.3 KB)  | 175 µs / call       | 399 µs / call    | **2.3× faster** |
| 100 log lines (17 KB) | 2.0 ms / call       | 4.6 ms / call    | **2.3× faster** |
| 1 MB log              | 138 ms / call       | 294 ms / call    | **2.1× faster** |
| 10 MB log             | 1.44 s / call       | —                | 6.9 MB/s        |

All payload sizes pass a correctness check (redaction count matches pure-Ruby `gsub`).
The previous engine (per-pattern `regexec`) was **4.25× slower** than pure Ruby on the
1 MB payload — a ~9× swing. Old numbers are in git history (`CHANGELOG.md` [0.9.0]).

#### Linear scaling

Throughput stays flat as input grows — the single-pass engine is O(N), so a 10×
larger payload takes ~10× longer and MB/s holds steady. The old per-pattern
`regexec` engine was O(N²) and fell off a cliff on large inputs (a 10 MB log took
tens of seconds); v19 redacts the same 10 MB in ~1.4 s.

| Size   | Time     | MB/s    |
|--------|----------|---------|
| 1 KB   | 0.14 ms  | 7.1     |
| 100 KB | 13.4 ms  | 7.3     |
| 1 MB   | 142 ms   | 7.0     |
| 10 MB  | 1.42 s   | 7.0     |
| 50 MB  | 7.14 s   | 7.0     |

No published benchmarks exist for comparable Ruby PII-redaction gems, so the
numbers above are absolute (vs pure-Ruby `gsub`), not a head-to-head against
another gem. Run `benchmark/scaling.rb` on your own hardware — absolute MB/s is
machine-dependent, but the flat curve is not.

## How it works

1. At load time, `mm_init()` compiles every built-in pattern from a Thompson NFA into bytecode, lazily building each pattern's DFA on first use (interned and cached). Boundary-wrapped patterns are expanded with the word-boundary group before compilation.
2. `DataRedactor.redact(text)` / `scan(text)` hand the input to the v19 engine, which scans it **once** and emits `(pattern_id, start, length)` events for every enabled pattern. Two selective-merge passes (a pure-digit group and an IBAN union) collapse the most common pattern classes into shared scans. The single pass over the original buffer is what makes the engine O(N).
3. The raw events are resolved by `mm_resolve` under the **longest-match-wins** policy: overlapping spans are reduced to a non-overlapping set keeping the longest match at each position, with the lower pattern index breaking equal-length ties.
4. `redact` rewrites the surviving spans to placeholders in one buffer build (preserving the boundary characters of boundary-wrapped matches); `scan` returns the event list with byte offsets into the original string. Custom patterns (`add_pattern`) run on the glibc `regexec` path afterward — required for correct UTF-8 diacritic matching.

## Memory management

All C-side working buffers are heap-allocated and freed before the call returns; the only Ruby-managed allocation is the final result `String`. No Ruby objects are created mid-scan, so GC cannot collect anything out from under the C code. Per-thread engine scratch (NFA state, lazy-DFA cache) is freed automatically when the thread exits — see [Thread safety](#thread-safety).

## Thread safety

`DataRedactor.redact` and `DataRedactor.scan` are safe to call concurrently from multiple threads. The v19 engine keeps its compiled patterns immutable and shared (read-only after `mm_init()` at load time) and all per-scan mutable state — NFA scratch and the lazy DFA cache — in per-thread storage, so concurrent scans never touch each other's state. For inputs above a few KB, `redact` **releases the GVL** (`rb_thread_call_without_gvl`) around the built-in scan, so a large redaction on one thread no longer blocks other Ruby threads from running. Small inputs keep the GVL (the release bookkeeping would cost more than the scan). Each call allocates its own working buffers. A thread's per-thread state is freed automatically when the thread exits, so processes that spawn many short-lived scanning threads do not accumulate memory.

`DataRedactor.add_pattern`, `remove_pattern`, and `clear_custom_patterns!` are also thread-safe: the shared custom-pattern array is guarded by a mutex that writers take around the mutation and `redact`/`scan` take around their custom-pattern loop. You can register, remove, or clear custom patterns from any thread at any time — including from request handlers in a running server — without coordinating with in-flight redactions. (Registration is still a rare operation; the lock is uncontended in practice.)

## Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Until `1.0.0`, minor versions may introduce breaking changes; from `1.0.0` onward, breaking changes will only land in major versions. See [CHANGELOG.md](CHANGELOG.md) for the release history.

## License

Released under the [MIT License](LICENSE).

## Known limitations

- **AWS Secret Key (pattern 1)** — 40 consecutive base64 characters is a broad match. It can produce false positives in base64-encoded content such as embedded images or binary blobs.
- **Duplicate digit patterns** — several national ID formats share the same digit-length (11 digits: PESEL, Norwegian Fødselsnummer, Belgian National Number). They are kept as separate slots for clarity but the practical effect is that any 11-digit boundary-delimited number will be redacted.
- **Overlap resolution is longest-match-wins** — when two patterns match overlapping spans the engine keeps the longer span; equal-length ties go to the lower pattern index. This favours redacting *more* when uncertain (a 40-char secret is redacted whole rather than leaking the bytes past a shorter prefix match). When two secrets abut with **no separator** between them, a boundary-wrapped pattern can fail to match because the original buffer has no word boundary where one token meets the next, leaving the abutting token unredacted. This is rare in real text (secrets are almost always separator-delimited).
