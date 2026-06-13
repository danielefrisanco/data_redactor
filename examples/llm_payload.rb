# frozen_string_literal: true

# LLM integration: strip PII from prompts before they leave your process, and
# from responses before you log them. Works with the Claude (Anthropic) and
# OpenAI message shapes. Operates on plain Hashes/Arrays — no `anthropic` or
# `openai` gem required, and the input is never mutated (a deep copy is returned).
#
#   ruby examples/llm_payload.rb

require "data_redactor/integrations/claude"
require "data_redactor/integrations/openai"

# --- Claude: messages array (content may be a String or text/image blocks) ---
claude_messages = [
  { role: "user", content: "My SSN is 123-45-6789, please help" },
  { role: "user", content: [
    { type: "text",  text: "and my card is 4111111111111111" },
    { type: "image", source: { type: "base64", data: "..." } }, # passes through
  ] },
]

safe = DataRedactor::Integrations::Claude.redact_messages(claude_messages)
puts safe[0][:content]              # => My SSN is [REDACTED], please help
puts safe[1][:content][0][:text]    # => and my card is [REDACTED]

# Redact a Claude response before logging it.
resp = { "content" => [{ "type" => "text", "text" => "your IBAN DE89370400440532013000" }] }
puts DataRedactor::Integrations::Claude.redact_response(resp)["content"][0]["text"]
# => your IBAN [REDACTED]

# --- OpenAI: Chat Completions messages (incl. a system message) ------------
openai_messages = [
  { "role" => "system", "content" => "User key AKIAIOSFODNN7EXAMPLE" },
  { "role" => "user",   "content" => "email me at alice@example.com" },
]
safe_oai = DataRedactor::Integrations::OpenAI.redact_messages(openai_messages)
puts safe_oai.map { |m| m["content"] }.inspect
# => ["User key [REDACTED]", "email me at [REDACTED]"]

# All helpers forward only:/except:/placeholder: to DataRedactor.redact.
