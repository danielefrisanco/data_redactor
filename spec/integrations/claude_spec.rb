require "data_redactor/integrations/claude"

RSpec.describe DataRedactor::Integrations::Claude do
  let(:email) { "alice@example.com" }
  let(:aws_key) { "AKIAIOSFODNN7EXAMPLE" }

  describe ".redact_messages" do
    it "redacts String content (happy path)" do
      messages = [{ role: "user", content: "my email is #{email}" }]
      out = described_class.redact_messages(messages)
      expect(out.first[:content]).to include("[REDACTED]")
      expect(out.first[:content]).not_to include(email)
    end

    it "redacts text blocks and passes non-text blocks through unchanged" do
      messages = [{
        role: "user",
        content: [
          { type: "text", text: "email #{email}" },
          { type: "image", source: { type: "base64", data: "QUJD" } }
        ]
      }]
      out = described_class.redact_messages(messages)
      blocks = out.first[:content]
      expect(blocks[0][:text]).to include("[REDACTED]")
      expect(blocks[0][:text]).not_to include(email)
      expect(blocks[1]).to eq(type: "image", source: { type: "base64", data: "QUJD" })
    end

    it "redacts a top-level system: String in a request Hash" do
      request = {
        system: "operator contact: #{email}",
        messages: [{ role: "user", content: "hi" }]
      }
      out = described_class.redact_messages(request)
      expect(out[:system]).to include("[REDACTED]")
      expect(out[:system]).not_to include(email)
    end

    it "does not mutate the input (key contract)" do
      messages = [{ role: "user", content: "my email is #{email}" }]
      described_class.redact_messages(messages)
      expect(messages.first[:content]).to include(email)
    end

    it "does not mutate nested text blocks in the input" do
      messages = [{ role: "user", content: [{ type: "text", text: "email #{email}" }] }]
      described_class.redact_messages(messages)
      expect(messages.first[:content].first[:text]).to include(email)
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

    it "handles an empty messages array" do
      expect(described_class.redact_messages([])).to eq([])
    end

    it "passes a message with no content key through without crashing" do
      messages = [{ role: "user" }]
      expect(described_class.redact_messages(messages)).to eq([{ role: "user" }])
    end
  end

  describe ".redact_response" do
    it "patches each text block and returns the full object" do
      response = {
        id: "msg_1",
        role: "assistant",
        content: [
          { type: "text", text: "your email #{email}" },
          { type: "text", text: "and key #{aws_key}" }
        ],
        usage: { input_tokens: 10 }
      }
      out = described_class.redact_response(response)
      expect(out[:content][0][:text]).not_to include(email)
      expect(out[:content][1][:text]).not_to include(aws_key)
      expect(out[:id]).to eq("msg_1")
      expect(out[:usage]).to eq(input_tokens: 10)
    end

    it "does not mutate the input response (key contract)" do
      response = { content: [{ type: "text", text: "email #{email}" }] }
      described_class.redact_response(response)
      expect(response[:content].first[:text]).to include(email)
    end

    it "handles string-keyed responses" do
      response = { "content" => [{ "type" => "text", "text" => "email #{email}" }] }
      out = described_class.redact_response(response)
      expect(out["content"].first["text"]).not_to include(email)
    end

    it "passes a response with no content key through without crashing" do
      expect(described_class.redact_response({ id: "msg_1" })).to eq(id: "msg_1")
    end
  end
end
