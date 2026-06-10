require "data_redactor/integrations/openai"

RSpec.describe DataRedactor::Integrations::OpenAI do
  let(:email) { "alice@example.com" }
  let(:aws_key) { "AKIAIOSFODNN7EXAMPLE" }

  describe ".redact_messages" do
    it "redacts String content (happy path)" do
      messages = [{ role: "user", content: "my email is #{email}" }]
      out = described_class.redact_messages(messages)
      expect(out.first[:content]).to include("[REDACTED]")
      expect(out.first[:content]).not_to include(email)
    end

    it "redacts a system message in the array like any other" do
      messages = [
        { role: "system", content: "operator contact: #{email}" },
        { role: "user", content: "hi" }
      ]
      out = described_class.redact_messages(messages)
      expect(out.first[:content]).to include("[REDACTED]")
      expect(out.first[:content]).not_to include(email)
    end

    it "redacts text parts and passes non-text parts through unchanged" do
      messages = [{
        role: "user",
        content: [
          { type: "text", text: "email #{email}" },
          { type: "image_url", image_url: { url: "https://example.com/a.png" } }
        ]
      }]
      out = described_class.redact_messages(messages)
      parts = out.first[:content]
      expect(parts[0][:text]).to include("[REDACTED]")
      expect(parts[0][:text]).not_to include(email)
      expect(parts[1]).to eq(type: "image_url", image_url: { url: "https://example.com/a.png" })
    end

    it "does not mutate the input (key contract)" do
      messages = [{ role: "user", content: "my email is #{email}" }]
      described_class.redact_messages(messages)
      expect(messages.first[:content]).to include(email)
    end

    it "forwards placeholder:" do
      messages = [{ role: "user", content: "email #{email}" }]
      out = described_class.redact_messages(messages, placeholder: "***")
      expect(out.first[:content]).to include("***")
      expect(out.first[:content]).not_to include("[REDACTED]")
    end

    it "forwards only: so out-of-scope tags survive" do
      messages = [{ role: "user", content: "user #{email} key #{aws_key}" }]
      out = described_class.redact_messages(messages, only: [:credentials])
      expect(out.first[:content]).to include(email)
      expect(out.first[:content]).not_to include(aws_key)
    end

    it "handles string-keyed input" do
      messages = [{ "role" => "user", "content" => "email #{email}" }]
      out = described_class.redact_messages(messages)
      expect(out.first["content"]).to include("[REDACTED]")
      expect(out.first["content"]).not_to include(email)
    end

    it "accepts a request Hash carrying a messages key" do
      request = { model: "gpt-4o", messages: [{ role: "user", content: "email #{email}" }] }
      out = described_class.redact_messages(request)
      expect(out[:model]).to eq("gpt-4o")
      expect(out[:messages].first[:content]).not_to include(email)
    end

    it "handles an empty messages array" do
      expect(described_class.redact_messages([])).to eq([])
    end

    it "passes a message with no content key through without crashing" do
      messages = [{ role: "user" }]
      expect(described_class.redact_messages(messages)).to eq([{ role: "user" }])
    end
  end

  describe ".redact_response" do
    it "patches each choice's message content and returns the full object" do
      response = {
        id: "chatcmpl-1",
        choices: [
          { index: 0, message: { role: "assistant", content: "your email #{email}" } },
          { index: 1, message: { role: "assistant", content: "and key #{aws_key}" } }
        ],
        usage: { total_tokens: 20 }
      }
      out = described_class.redact_response(response)
      expect(out[:choices][0][:message][:content]).not_to include(email)
      expect(out[:choices][1][:message][:content]).not_to include(aws_key)
      expect(out[:id]).to eq("chatcmpl-1")
      expect(out[:usage]).to eq(total_tokens: 20)
    end

    it "does not mutate the input response (key contract)" do
      response = { choices: [{ message: { content: "email #{email}" } }] }
      described_class.redact_response(response)
      expect(response[:choices].first[:message][:content]).to include(email)
    end

    it "handles string-keyed responses" do
      response = { "choices" => [{ "message" => { "content" => "email #{email}" } }] }
      out = described_class.redact_response(response)
      expect(out["choices"].first["message"]["content"]).not_to include(email)
    end

    it "passes a response with no choices key through without crashing" do
      expect(described_class.redact_response({ id: "chatcmpl-1" })).to eq(id: "chatcmpl-1")
    end
  end
end
