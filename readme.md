# DataRedactor

A Ruby gem with a C extension for high-performance regex-based redaction of sensitive data from strings.

## What it does

DataRedactor scans text for sensitive patterns and replaces matches with `[REDACTED]`. It uses a C extension backed by POSIX `regex.h` so the heavy lifting happens outside the Ruby VM, making it fast enough for large payloads.

## Usage

```ruby
require "data_redactor"

text = "User CF is RSSMRA85M01H501Z and key is AKIAIOSFODNN7EXAMPLE"
DataRedactor.redact(text)
# => "User CF is [REDACTED] and key is [REDACTED]"
```

## Detected patterns (49 total)

### Cloud & API secrets

| # | Pattern | Example |
|---|---|---|
| 0 | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| 1 | AWS Secret Access Key | 40-character base64 string |
| 5 | Google API Key | `AIzaSyXXXX...` |
| 6 | GitHub Personal Access Token | `github_pat_XXXX...` |
| 7 | Slack Webhook URL | `https://hooks.slack.com/services/T.../B.../...` |
| 8 | Stripe Secret Key | `sk_live_XXXX...` |
| 9 | PEM Private Key header | `-----BEGIN RSA PRIVATE KEY-----` |
| 13 | Scaleway Access Key | `SCW12345ABCDE6789FGHIJ` |
| 14 | UUID v4 / Scaleway Secret Key | `550e8400-e29b-41d4-a716-446655440000` |

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
│       └── version.rb
├── ext/
│   └── data_redactor/
│       ├── extconf.rb         # Checks for C headers, generates Makefile
│       └── data_redactor.c       # C extension: regex compilation + redaction
└── spec/
    └── data_redactor_spec.rb     # RSpec tests (61 examples, one per pattern)
```

## Requirements

- Ruby >= 2.7
- A C compiler (`gcc` or `clang`)
- POSIX `regex.h` (standard on Linux and macOS)

## Setup

```bash
bundle install
```

## Compile the C extension

```bash
bundle exec rake compile
```

This runs `extconf.rb` via `rake-compiler`, which generates a `Makefile` and compiles `data_redactor.c` into a `.so` shared library placed under `lib/data_redactor/`.

## Run the tests

```bash
bundle exec rake spec
```

Or compile and test in one step:

```bash
bundle exec rake
```

## How it works

1. At load time, `Init_data_redactor` compiles all 49 regex patterns once using `regcomp` (POSIX ERE) and stores them as static `regex_t` structs. Patterns marked as boundary-wrapped are expanded with `wrap_boundary()` before compilation.
2. `DataRedactor.redact(text)` receives a Ruby `String`, converts it to a C `char*` via `StringValueCStr`, and runs each compiled pattern in sequence on a working buffer.
3. For each pattern, `replace_all_matches` iterates using `regexec`, copies non-matching segments to a fresh output buffer, and inserts `[REDACTED]` in place of each match. For boundary-wrapped patterns, `regexec` is called with `nmatch=4` and sub-match groups `[1]`/`[3]` identify the boundary characters so they are preserved verbatim.
4. The output buffer is grown with `realloc` as needed. After all patterns are applied the result is returned as a Ruby `String` via `rb_str_new_cstr`. All intermediate `malloc`/`strdup` allocations are explicitly `free`d.

## Memory management

All C-side buffers are heap-allocated with `malloc`/`strdup` and freed before the function returns. The only Ruby-managed allocation is the final return value from `rb_str_new_cstr`. No Ruby objects are created mid-processing, so GC cannot collect anything out from under the C code.

## Known limitations

- **Pattern ordering matters** — patterns run sequentially. An early broad pattern (e.g. the 9-digit passport) may consume digits that a later pattern (e.g. credit card) depends on. Boundary wrapping mitigates this for pure-digit patterns.
- **AWS Secret Key (pattern 1)** — 40 consecutive base64 characters is a broad match. It can produce false positives in base64-encoded content such as embedded images or binary blobs.
- **Duplicate digit patterns** — several national ID formats share the same digit-length (11 digits: PESEL, Norwegian Fødselsnummer, Belgian National Number). They are kept as separate slots for clarity but the practical effect is that any 11-digit boundary-delimited number will be redacted.
