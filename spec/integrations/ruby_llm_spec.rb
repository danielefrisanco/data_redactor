require "data_redactor"

# A stand-in for ruby_llm 2.0, mirroring the parts of the real contract this
# integration depends on (verified against crmne/ruby_llm@main):
#
#   - Chat#before_request stores blocks and returns self (chat.rb).
#   - Protocol#render runs them LAST, in registration order, and discards their
#     return values — hooks are expected to mutate the payload in place
#     (protocol.rb#apply_before_request_hooks).
#   - Chat#render returns the hook-applied payload without sending it.
#   - Agent wraps a chat behind attr_reader :chat — or a chat *record* in Rails
#     mode — and delegates before_request to it (agent.rb#def_delegators, since
#     crmne/ruby_llm#876).
#   - acts_as_chat records expose a memoized #to_llm chat (chat_methods.rb).
#
# Defined before requiring the integration: the integration touches RubyLLM only
# when called, so requiring it here is inert.
module RubyLLM
  VERSION = "2.0.0"

  class Chat
    attr_reader :kwargs, :hooks

    def initialize(**kwargs)
      @kwargs = kwargs
      @hooks = []
    end

    def before_request(&block)
      @hooks << block
      self
    end

    # Mirrors Protocol#render: a freshly assembled payload, hooks applied last,
    # return values thrown away.
    def render
      payload = {
        # A dated model id, as every Anthropic/Gemini id is: the eight-digit
        # suffix is exactly what the national-ID patterns match.
        model: "claude-haiku-4-5-20251001",
        messages: [
          { role: "user", content: "my card is 4111111111111111" },
          { role: "tool", content: "shell output: token sk_live_abcdef0123456789abcdef01" }
        ],
        system: "You are a support agent. Caller email alice@example.com.",
        temperature: 0.7
      }
      @hooks.each { |h| h.call(payload) }
      payload
    end
  end

  # Mirrors Agent: wraps a chat — or, in Rails mode, a chat *record* — and
  # delegates the Chat API to it, `before_request` included (crmne/ruby_llm#876).
  # The delegation is unconditional, so a Rails-mode agent answers respond_to?
  # with true while the call lands on a record that has no such method.
  class Agent
    attr_reader :chat

    def initialize(chat = Chat.new)
      @chat = chat
    end

    def before_request(&block)
      @chat.before_request(&block)
    end
  end

  # Mirrors an acts_as_chat record: #to_llm builds once and memoizes.
  class Record
    def to_llm
      @to_llm ||= Chat.new
    end
  end

  def self.chat(**kwargs)
    Chat.new(**kwargs)
  end
end

require "data_redactor/integrations/ruby_llm"

RSpec.describe DataRedactor::Integrations::RubyLLM do
  describe ".chat" do
    it "returns a chat with the redaction hook registered" do
      chat = described_class.chat(model: "claude-opus-4-8")
      expect(chat).to be_a(RubyLLM::Chat)
      expect(chat.hooks.size).to eq(1)
    end

    it "forwards RubyLLM's own arguments untouched, and none of ours" do
      chat = described_class.chat(model: "gpt-5.4", provider: "openai", only: [:financial])
      expect(chat.kwargs).to eq({ model: "gpt-5.4", provider: "openai" })
    end

    it "redacts the user prompt, the system prompt, and tool results" do
      payload = described_class.chat(model: "claude-opus-4-8").render

      expect(payload[:messages][0][:content]).to eq("my card is [REDACTED]")
      expect(payload[:messages][1][:content]).to eq("shell output: token [REDACTED]")
      expect(payload[:system]).to eq("You are a support agent. Caller email [REDACTED].")
    end

    it "leaves the dated model id intact — a redacted one is rejected by the provider" do
      payload = described_class.chat(model: "claude-haiku-4-5").render

      expect(payload[:model]).to eq("claude-haiku-4-5-20251001")
      expect(payload[:temperature]).to eq(0.7)
    end

    it "redacts the model id when the caller clears the default skip list" do
      payload = described_class.chat(model: "claude-haiku-4-5", skip_keys: []).render

      expect(payload[:model]).to eq("claude-haiku-4-5-[REDACTED]")
    end

    it "accepts extra skip_keys for provider fields the app relies on" do
      payload = described_class.chat(model: "claude-haiku-4-5", skip_keys: [:model, :system]).render

      expect(payload[:system]).to include("alice@example.com")
      expect(payload[:messages][0][:content]).to eq("my card is [REDACTED]")
    end

    it "forwards only:/except:/placeholder: to the redaction" do
      payload = described_class.chat(only: [:financial], placeholder: :tagged).render

      expect(payload[:messages][0][:content]).to eq("my card is [REDACTED:FINANCIAL]")
      expect(payload[:system]).to include("alice@example.com")
    end
  end

  describe ".attach!" do
    it "registers the hook on a chat and returns it" do
      chat = RubyLLM::Chat.new

      expect(described_class.attach!(chat)).to equal(chat)
      expect(chat.render[:messages][0][:content]).to eq("my card is [REDACTED]")
    end

    it "registers on an agent's wrapped chat" do
      agent = RubyLLM::Agent.new

      expect(described_class.attach!(agent)).to equal(agent)
      expect(agent.chat.hooks.size).to eq(1)
      expect(agent.chat.render[:system]).to eq("You are a support agent. Caller email [REDACTED].")
    end

    it "registers on a record's memoized to_llm chat" do
      record = RubyLLM::Record.new

      expect(described_class.attach!(record)).to equal(record)
      expect(record.to_llm.hooks.size).to eq(1)
      expect(record.to_llm.render[:messages][0][:content]).to eq("my card is [REDACTED]")
    end

    it "reaches the chat through an agent that wraps a record (Rails mode)" do
      record = RubyLLM::Record.new
      agent = RubyLLM::Agent.new(record)

      described_class.attach!(agent)

      expect(record.to_llm.hooks.size).to eq(1)
    end

    it "does not route a Rails-mode agent through its own delegator" do
      # Agent delegates before_request to whatever it wraps, so respond_to? is
      # true even when that is a record without the method. Trusting the
      # delegator here would raise NoMethodError instead of redacting.
      record = RubyLLM::Record.new
      agent = RubyLLM::Agent.new(record)

      expect(agent).to respond_to(:before_request)
      expect(record).not_to respond_to(:before_request)
      expect { described_class.attach!(agent) }.not_to raise_error
      expect(record.to_llm.render[:messages][0][:content]).to eq("my card is [REDACTED]")
    end

    it "raises when no before_request hook is reachable (ruby_llm 1.x)" do
      expect { described_class.attach!(Object.new) }
        .to raise_error(ArgumentError, /no #before_request hook reachable/)
    end
  end

  describe ".hook" do
    it "redacts the payload in place, so a discarded return value still counts" do
      payload = { "prompt" => "my card is 4111111111111111" }

      expect(described_class.hook.call(payload)).to be_truthy
      expect(payload["prompt"]).to eq("my card is [REDACTED]")
    end

    it "can be registered directly on a chat" do
      chat = RubyLLM::Chat.new
      chat.before_request(&described_class.hook(only: [:contact]))

      payload = chat.render
      expect(payload[:system]).to eq("You are a support agent. Caller email [REDACTED].")
      expect(payload[:messages][0][:content]).to include("4111111111111111")
    end
  end

  describe ".install!" do
    it "raises and names the replacements" do
      expect { described_class.install! }
        .to raise_error(/install! has been removed.*attach!/m)
    end

    it "raises even when called with the old filter arguments" do
      expect { described_class.install!(only: [:financial]) }
        .to raise_error(/install! has been removed/)
    end
  end

  # The fake above can only prove we implement the contract as we understood it.
  # This runs the integration against a real ruby_llm checkout — the check to run
  # on the day 2.0 ships, before merging. Point RUBY_LLM_PATH at a clone, or
  # leave it unset once ruby_llm 2.0 is an installed gem. Runs in a subprocess:
  # the fake RubyLLM above and the real gem cannot share a process.
  describe "against a real ruby_llm (opt-in)" do
    def run_real(script)
      lib = File.expand_path("../../lib", __dir__)
      includes = ["-I#{lib}"]
      includes << "-I#{File.join(ENV['RUBY_LLM_PATH'], 'lib')}" if ENV["RUBY_LLM_PATH"]

      # Escape bundler: ruby_llm is not in this gem's Gemfile (zero runtime deps).
      env = { "BUNDLE_GEMFILE" => nil, "RUBYOPT" => nil, "RUBYLIB" => nil }
      IO.popen(env, ["ruby", *includes, "-e", script], err: [:child, :out], &:read)
    end

    let(:probe) do
      run_real(<<~RUBY)
        begin
          require "ruby_llm"
          print RubyLLM::Chat.method_defined?(:before_request) ? "ready" : "no-hook"
        rescue Exception => e
          print "unavailable: \#{e.class}: \#{e.message.lines.first}"
        end
      RUBY
    end

    it "redacts the payload a real chat would send" do
      skip "real ruby_llm with before_request not available (#{probe})" unless probe == "ready"

      out = run_real(<<~RUBY)
        require "ruby_llm"
        require "data_redactor/integrations/ruby_llm"

        RubyLLM.configure { |c| c.anthropic_api_key = "test" }

        chat = DataRedactor::Integrations::RubyLLM.chat(
          model: "claude-haiku-4-5", provider: "anthropic"
        )
        chat.with_instructions("Escalate to ops@acme.com.")
        chat.ask_later("my card is 4111111111111111")

        print chat.render.inspect
      RUBY

      expect(out).to include("[REDACTED]")
      expect(out).not_to include("4111111111111111")
      expect(out).not_to include("ops@acme.com")
      # The resolved model id keeps its eight-digit date suffix; redacting it
      # would make the provider reject every request.
      expect(out).to match(/claude-haiku-4-5-\d{8}/)
    end
  end

  describe "base64 attachments: the decoded secret is NOT redacted (documented limitation)" do
    it "does not catch a secret that only exists inside the decoded bytes" do
      # Patterns run against the base64 string, never the decoded content, so a
      # secret inside the PDF/image bytes is never seen as a secret. (The encoded
      # text may itself trip a pattern incidentally; that is not protection.)
      # Fixed literal so the spec needs no `base64` lib (gone from default gems
      # on Ruby 3.4+): this is Base64 of "secret email leaks@example.com inside
      # the pdf", which contains a recognisable email once decoded.
      blob = "c2VjcmV0IGVtYWlsIGxlYWtzQGV4YW1wbGUuY29tIGluc2lkZSB0aGUgcGRm"

      out = DataRedactor.redact_deep({ source: { type: "base64", data: blob } })

      # The email is invisible to us while encoded — never redacted as contact PII.
      expect(out[:source][:data]).not_to include("[REDACTED:CONTACT]")
      expect(out[:source][:data]).not_to include("leaks@example.com")
    end
  end
end
