# frozen_string_literal: true

# RubyLLM: redact every outbound request through the public request hook.
#
# `chat.before_request { |payload| ... }` (ruby_llm 2.0+) hands a callback the
# fully rendered request payload just before it is posted, and discards the
# callback's return value — so hooks edit the payload in place.
# `DataRedactor::Integrations::RubyLLM.chat` builds a chat with that callback
# already registered; `attach!` adds it to a chat, agent, or acts_as_chat record
# you were handed. Nothing is monkeypatched.
#
# What it covers that per-call redaction cannot: the system prompt, the whole
# history, and **tool results** — the file an agent read or the command it ran,
# inlined as a String in the next request.
#
# This script runs for real WITHOUT the `ruby_llm` gem by defining a tiny
# stand-in that mirrors the real hook contract, so you can watch it scrub a
# realistic payload. In a real project you just `require "ruby_llm"` instead
# (see the commented block at the bottom).
#
#   bundle exec ruby examples/ruby_llm_hook.rb

# --- stand-in for the real ruby_llm gem (so this file runs anywhere) ----------
module RubyLLM
  VERSION = "2.0.0"

  # Mirrors RubyLLM::Chat: before_request stores callbacks, and the rendered
  # payload is handed to each of them, in order, with the return value ignored.
  class Chat
    def initialize(**kwargs)
      @kwargs = kwargs
      @hooks = []
    end

    def before_request(&block)
      @hooks << block
      self
    end

    def render
      payload = {
        model: "claude-haiku-4-5-20251001",
        system: "You are a support agent for ACME Corp. Escalate to ops@acme.com.",
        messages: [
          { role: "user", content: "My card is 4111111111111111" },
          { role: "tool", content: "file contents: db password is hunter2; ssn 123-45-6789" }
        ],
        temperature: 0.7
      }
      @hooks.each { |hook| hook.call(payload) }
      payload
    end
  end

  def self.chat(**kwargs)
    Chat.new(**kwargs)
  end
end
# -----------------------------------------------------------------------------

require "data_redactor/integrations/ruby_llm"
require "pp"

chat = DataRedactor::Integrations::RubyLLM.chat(model: "claude-haiku-4-5")

pp chat.render
# => {:model=>"claude-haiku-4-5-20251001",
#     :system=>"You are a support agent for ACME Corp. Escalate to [REDACTED].",
#     :messages=>
#      [{:role=>"user", :content=>"My card is [REDACTED]"},
#       {:role=>"tool", :content=>"file contents: db password is hunter2; ssn [REDACTED]"}],
#     :temperature=>0.7}
#
# The user prompt, the system prompt, and the SSN inside the tool result (a file
# an agent read) are all scrubbed. The model id survives: it is skipped by
# default, because its eight-digit date suffix looks exactly like a national ID
# and a provider rejects a redacted model. "hunter2" survives too — redaction
# matches structured PII and secrets, not arbitrary words.

# Filters and skip_keys are captured per chat:
scoped = DataRedactor::Integrations::RubyLLM.chat(
  model: "claude-haiku-4-5", only: [:financial], placeholder: :tagged
)
pp scoped.render[:messages][0]
# => {:role=>"user", :content=>"My card is [REDACTED:FINANCIAL]"}

# Already have a chat, an agent, or an acts_as_chat record? Attach to it:
handed_to_you = RubyLLM.chat(model: "claude-haiku-4-5")
DataRedactor::Integrations::RubyLLM.attach!(handed_to_you, only: [:contact])
pp handed_to_you.render[:system]
# => "You are a support agent for ACME Corp. Escalate to [REDACTED]."

# Or take the callback itself and register it the way RubyLLM documents. This is
# all the two calls above do; use it when you want the hook alongside your own,
# or on anything else that grows a before_request.
own_chat = RubyLLM.chat(model: "claude-haiku-4-5")
own_chat.before_request(&DataRedactor::Integrations::RubyLLM.hook(only: [:financial]))
own_chat.before_request { |payload| payload[:metadata] = { tenant: "acme" } }
pp own_chat.render.slice(:messages, :metadata)
# => {:messages=>
#      [{:role=>"user", :content=>"My card is [REDACTED]"},
#       {:role=>"tool",
#        :content=>"file contents: db password is hunter2; ssn 123-45-6789"}],
#     :metadata=>{:tenant=>"acme"}}
#
# Hooks run in registration order and RubyLLM ignores what they return, so ours
# redacts the payload in place and yours still sees (and edits) the same Hash.
# The SSN survives here because only: [:financial] was asked for — it is tagged
# :national_id.

# In a real project, drop the stand-in above and use the gem:
#
#   require "ruby_llm"
#   require "data_redactor/integrations/ruby_llm"
#
#   chat = DataRedactor::Integrations::RubyLLM.chat(model: "claude-opus-4-8")
#   chat.ask("my card is 4111111111111111")   # sent as "my card is [REDACTED]"
#
# Needs ruby_llm 2.0+ (1.x has no request hook — redact per call there). The hook
# is per chat: one you neither built with `.chat` nor passed to `attach!` is not
# redacted. Base64 attachments and URL-referenced files are never redacted, and
# embeddings, images and transcriptions do not run request hooks at all.
