# frozen_string_literal: true

# RubyLLM: scrub prompts (and the system instruction) before they reach the
# model. RubyLLM (the `ruby_llm` gem) is a unified client for every major LLM
# provider — and anything you send to a model is exactly the free text that
# leaks secrets and PII. Because RubyLLM takes plain strings, you redact them
# with DataRedactor.redact before passing them to `chat.ask`; no extra
# integration is needed.
#
# This script runs the redaction for real (the data_redactor part needs no
# gems). The `RubyLLM.chat` lines are shown commented so the example runs
# anywhere — uncomment them in a project that has `ruby_llm` installed.
#
#   bundle exec ruby examples/ruby_llm.rb

require "data_redactor"

# What the user is about to send:
system_prompt = "You are a support agent for ACME Corp. Escalate to ops@acme.com."
user_input    = "My card is 4111111111111111 and my email is alice@example.com"

# Redact BEFORE handing the strings to the model.
safe_system = DataRedactor.redact(system_prompt)
safe_input  = DataRedactor.redact(user_input)

puts safe_system
# => You are a support agent for ACME Corp. Escalate to [REDACTED].
puts safe_input
# => My card is [REDACTED] and my email is [REDACTED]

# In a project with `ruby_llm` installed, wire the redacted strings straight in:
#
#   require "ruby_llm"
#   chat = RubyLLM.chat(model: "claude-opus-4-8")
#   chat.with_instructions(DataRedactor.redact(system_prompt))
#   response = chat.ask(DataRedactor.redact(user_input))
#
# Redaction is a per-call step you opt into. To redact every outbound request
# instead — system prompt and tool results included — build the chat through
# the integration, which registers RubyLLM's public `before_request` hook
# (ruby_llm 2.0+). See examples/ruby_llm_hook.rb.

# redact forwards only:/except:/placeholder:, so you can scope or relabel:
puts DataRedactor.redact(user_input, only: [:financial])
# => My card is [REDACTED] and my email is alice@example.com  (email kept)
puts DataRedactor.redact(user_input, placeholder: :tagged)
# => My card is [REDACTED:FINANCIAL] and my email is [REDACTED:CONTACT]
#
# (Tip: an unspaced card matches the credit-card pattern; a space-grouped
# "4111 1111 1111 1111" can collide with other digit-group patterns instead.)
