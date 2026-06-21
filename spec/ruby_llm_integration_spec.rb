require "data_redactor"

# A minimal fake `RubyLLM::Protocol` stands in for the real chokepoint so these
# specs don't depend on the gem. Defined before requiring the integration: the
# integration only patches the constant inside install!, so requiring it here is
# inert until we ask for it.
module RubyLLM
  VERSION = "1.16.0"

  # Mimics ruby_llm's real Protocol#render: returns the fully-rendered,
  # provider-shaped request Hash that #complete would post.
  class Protocol
    def render(*)
      {
        model: "claude-opus-4-8",
        messages: [
          { role: "user", content: "my card is 4111111111111111" },
          { role: "tool", content: "shell output: token sk_live_abcdef0123456789abcdef01" }
        ],
        system: "You are a support agent. Caller email alice@example.com.",
        temperature: 0.7
      }
    end
  end
end

require "data_redactor/integrations/ruby_llm"

# `install!` prepends onto a constant and a prepend can't be undone, so the
# happy-path tests share one patched constant (and assert idempotency), while the
# fail-fast guards run in fresh subprocesses to avoid polluting this process.
RSpec.describe DataRedactor::Integrations::RubyLLM do
  before(:all) do
    described_class.install!
  end

  describe ".install!" do
    it "prepends the patch onto RubyLLM::Protocol" do
      expect(described_class.installed?).to be(true)
      expect(RubyLLM::Protocol.ancestors).to include(described_class::PayloadPatch)
    end

    it "is idempotent — a second call does not prepend twice" do
      before = RubyLLM::Protocol.ancestors.count { |a| a == described_class::PayloadPatch }
      described_class.install!
      after = RubyLLM::Protocol.ancestors.count { |a| a == described_class::PayloadPatch }
      expect(after).to eq(before).and eq(1)
    end
  end

  describe "redacting the rendered payload" do
    let(:payload) { RubyLLM::Protocol.new.render }

    it "redacts the user prompt" do
      expect(payload[:messages][0][:content]).to eq("my card is [REDACTED]")
    end

    it "redacts tool results (file/command output fed back to the model)" do
      expect(payload[:messages][1][:content]).to eq("shell output: token [REDACTED]")
    end

    it "redacts the system prompt" do
      expect(payload[:system]).to eq("You are a support agent. Caller email [REDACTED].")
    end

    it "leaves non-string fields (model id, temperature) intact" do
      expect(payload[:model]).to eq("claude-opus-4-8")
      expect(payload[:temperature]).to eq(0.7)
    end
  end

  describe "filters captured at install!" do
    it "forwards only:/except:/placeholder: to redact_deep" do
      # install! already ran with defaults; re-set options and confirm they apply.
      described_class.install!(only: [:financial], placeholder: :tagged)
      payload = RubyLLM::Protocol.new.render
      expect(payload[:messages][0][:content]).to eq("my card is [REDACTED:FINANCIAL]")
      # contact is excluded by only: [:financial], so the email survives
      expect(payload[:system]).to include("alice@example.com")
    ensure
      described_class.install! # restore defaults for other examples
    end
  end

  describe "fail-fast guards (fresh interpreter)" do
    def run(setup)
      script = <<~RUBY
        #{setup}
        require "data_redactor/integrations/ruby_llm"
        begin
          DataRedactor::Integrations::RubyLLM.install!
          print "NO_RAISE"
        rescue => e
          print e.message
        end
      RUBY
      `ruby -Ilib -e '#{script.gsub("'", %q('"'"'))}'`
    end

    it "raises when ruby_llm is not loaded" do
      out = run('module DataRedactor; end')
      expect(out).to include("require \"ruby_llm\" before")
    end

    it "raises on an unsupported ruby_llm version" do
      setup = 'module RubyLLM; VERSION = "2.0.0"; class Protocol; def render; end; end; end'
      out = run(setup)
      expect(out).to include("supports ruby_llm")
      expect(out).to include("2.0.0")
    end

    it "raises when Protocol#render is missing (upstream refactor)" do
      setup = 'module RubyLLM; VERSION = "1.16.0"; class Protocol; end; end'
      out = run(setup)
      expect(out).to include("RubyLLM::Protocol#render not found")
    end
  end

  describe "base64 attachments: the decoded secret is NOT redacted (documented limitation)" do
    it "does not catch a secret that only exists inside the decoded bytes" do
      # Patterns run against the base64 string, never the decoded content, so a
      # secret inside the PDF/image bytes is never seen as a secret. (The encoded
      # text may itself trip a pattern incidentally; that is not protection.)
      require "base64"
      secret = "leaks@example.com"
      blob = Base64.strict_encode64("secret email #{secret} inside the pdf")
      expect(Base64.decode64(blob)).to include(secret) # the blob really carries it

      out = DataRedactor.redact_deep({ source: { type: "base64", data: blob } })

      # We never redacted the email as an email — it was invisible to us.
      expect(out[:source][:data]).not_to include("[REDACTED:CONTACT]")
      expect(out[:source][:data]).not_to include(secret) # because it's encoded, not because we caught it
    end
  end
end
