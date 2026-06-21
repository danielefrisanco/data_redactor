# frozen_string_literal: true

# RubyLLM, transparent mode: redact EVERY outbound request automatically, with
# no per-call `.redact`. `DataRedactor::Integrations::RubyLLM.install!` prepends a
# patch onto `RubyLLM::Protocol#render` — the one point where every provider has
# assembled its final request Hash — and deep-redacts the payload before it's
# posted. That covers the user prompt, the system prompt, tool definitions, and
# any file contents or shell-command output an agent fed back as a tool result
# (all inlined as strings in the payload).
#
# This script runs for real WITHOUT the `ruby_llm` gem by defining a tiny
# stand-in `RubyLLM::Protocol` that mirrors the real chokepoint, so you can see
# the patch redact a realistic payload. In a real project you just
# `require "ruby_llm"` instead (see the commented block at the bottom).
#
#   bundle exec ruby examples/ruby_llm_transparent.rb

# --- stand-in for the real ruby_llm gem (so this file runs anywhere) ----------
module RubyLLM
  VERSION = "1.16.0"

  # Mirrors RubyLLM::Protocol#render: returns the fully-rendered request Hash
  # that #complete would post to the provider.
  class Protocol
    def render
      {
        model: "claude-opus-4-8",
        system: "You are a support agent for ACME Corp. Escalate to ops@acme.com.",
        messages: [
          { role: "user", content: "My card is 4111111111111111" },
          { role: "tool", content: "file contents: db password is hunter2; ssn 123-45-6789" }
        ],
        temperature: 0.7
      }
    end
  end
end
# -----------------------------------------------------------------------------

require "data_redactor/integrations/ruby_llm"

DataRedactor::Integrations::RubyLLM.install!   # once, at boot

# Every render is now redacted before it would be posted:
require "pp"
pp RubyLLM::Protocol.new.render
# => {:model=>"claude-opus-4-8",
#     :system=>"You are a support agent for ACME Corp. Escalate to [REDACTED].",
#     :messages=>
#      [{:role=>"user", :content=>"My card is [REDACTED]"},
#       {:role=>"tool", :content=>"file contents: db password is hunter2; ssn [REDACTED]"}],
#     :temperature=>0.7}
#
# Note: the user prompt, system prompt, and the SSN inside the tool result (e.g.
# a file an agent read) are all scrubbed; the model id and temperature are left
# alone. "hunter2" is not a recognised secret pattern, so it survives — redaction
# matches structured PII/secrets, not arbitrary words.

# Filters are captured at install! and apply to every request:
DataRedactor::Integrations::RubyLLM.install!(only: [:financial], placeholder: :tagged)
pp RubyLLM::Protocol.new.render[:messages][0]
# => {:role=>"user", :content=>"My card is [REDACTED:FINANCIAL]"}

# In a real project, drop the stand-in above and use the gem:
#
#   require "ruby_llm"
#   require "data_redactor/integrations/ruby_llm"
#   DataRedactor::Integrations::RubyLLM.install!
#
#   chat = RubyLLM.chat(model: "claude-opus-4-8")
#   chat.ask("my card is 4111111111111111")   # sent as "my card is [REDACTED]"
#
# Caveats: this is a monkeypatch on RubyLLM internals (version-pinned; fails fast
# at install! if the API moved), and base64 attachments / URL-referenced files
# are NOT redacted (encoded or remote). For a non-patching alternative, redact
# per call with DataRedactor.redact — see examples/ruby_llm.rb.
