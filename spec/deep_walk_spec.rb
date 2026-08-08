RSpec.describe DataRedactor do
  describe ".redact_deep" do
    let(:email) { "alice@example.com" }
    let(:key)   { "AKIAIOSFODNN7EXAMPLE" }

    it "redacts string values in a flat hash" do
      result = DataRedactor.redact_deep({ "email" => email, "count" => 3 })
      expect(result["email"]).to eq("[REDACTED]")
      expect(result["count"]).to eq(3)
    end

    it "redacts string values in a nested hash" do
      result = DataRedactor.redact_deep({ "user" => { "email" => email } })
      expect(result["user"]["email"]).to eq("[REDACTED]")
    end

    it "redacts string values inside arrays" do
      result = DataRedactor.redact_deep([email, 42, nil])
      expect(result[0]).to eq("[REDACTED]")
      expect(result[1]).to eq(42)
      expect(result[2]).to be_nil
    end

    it "redacts strings nested inside arrays inside hashes" do
      result = DataRedactor.redact_deep({ "keys" => [key, "safe"] })
      expect(result["keys"][0]).to eq("[REDACTED]")
      expect(result["keys"][1]).to eq("safe")
    end

    it "does not mutate the original structure" do
      original = { "email" => email }
      DataRedactor.redact_deep(original)
      expect(original["email"]).to eq(email)
    end

    it "leaves non-string scalars (Integer, Float, nil, Boolean) unchanged" do
      input = { "n" => 1, "f" => 3.14, "nil" => nil, "bool" => true }
      result = DataRedactor.redact_deep(input)
      expect(result).to eq(input)
    end

    it "does not redact hash keys" do
      result = DataRedactor.redact_deep({ email => "value" })
      expect(result.keys).to include(email)
    end

    it "passes only:/except:/placeholder: through to redact" do
      result = DataRedactor.redact_deep({ "email" => email, "key" => key },
                                        only: :credentials)
      expect(result["email"]).to eq(email)
      expect(result["key"]).to eq("[REDACTED]")
    end

    it "accepts a plain string as top-level input" do
      expect(DataRedactor.redact_deep(email)).to eq("[REDACTED]")
    end

    it "accepts a top-level array" do
      result = DataRedactor.redact_deep([email, key])
      expect(result).to eq(["[REDACTED]", "[REDACTED]"])
    end

    it "passes non-Hash/Array/String values through unchanged" do
      expect(DataRedactor.redact_deep(42)).to eq(42)
      expect(DataRedactor.redact_deep(nil)).to be_nil
    end

    it "raises on circular references in hashes" do
      h = {}
      h["self"] = h
      expect { DataRedactor.redact_deep(h) }.to raise_error(ArgumentError, /circular reference/)
    end

    it "raises on circular references in arrays" do
      a = []
      a << a
      expect { DataRedactor.redact_deep(a) }.to raise_error(ArgumentError, /circular reference/)
    end
  end

  describe ".redact_json" do
    let(:email) { "alice@example.com" }

    it "redacts string values and returns valid JSON" do
      input  = JSON.generate({ "email" => email, "count" => 3 })
      output = DataRedactor.redact_json(input)
      parsed = JSON.parse(output)
      expect(parsed["email"]).to eq("[REDACTED]")
      expect(parsed["count"]).to eq(3)
    end

    it "handles nested structures" do
      input  = JSON.generate({ "user" => { "email" => email } })
      output = DataRedactor.redact_json(input)
      expect(JSON.parse(output).dig("user", "email")).to eq("[REDACTED]")
    end

    it "handles arrays in JSON" do
      input  = JSON.generate([email, 1, nil])
      output = DataRedactor.redact_json(input)
      parsed = JSON.parse(output)
      expect(parsed[0]).to eq("[REDACTED]")
      expect(parsed[1]).to eq(1)
      expect(parsed[2]).to be_nil
    end

    it "raises JSON::ParserError on invalid JSON" do
      expect { DataRedactor.redact_json("not json") }.to raise_error(JSON::ParserError)
    end

    it "forwards only:/except: to redact" do
      key   = "AKIAIOSFODNN7EXAMPLE"
      input = JSON.generate({ "email" => email, "key" => key })
      output = DataRedactor.redact_json(input, only: :credentials)
      parsed = JSON.parse(output)
      expect(parsed["email"]).to eq(email)
      expect(parsed["key"]).to eq("[REDACTED]")
    end
  end
end
