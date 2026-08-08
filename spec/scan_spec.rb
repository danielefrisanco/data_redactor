RSpec.describe DataRedactor do
  describe ".scan" do
    let(:email) { "user@example.com" }
    let(:aws)   { "AKIAIOSFODNN7EXAMPLE" }
    let(:iban)  { "DE89370400440532013000" }

    it "returns a hash with :redacted and :matches keys" do
      result = DataRedactor.scan(email)
      expect(result).to be_a(Hash)
      expect(result).to have_key(:redacted)
      expect(result).to have_key(:matches)
    end

    it ":redacted contains [REDACTED] in place of matches" do
      result = DataRedactor.scan(email)
      expect(result[:redacted]).to include("[REDACTED]")
      expect(result[:redacted]).not_to include(email)
    end

    it "returns match hashes with correct keys" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m).to include(:tag, :name, :value, :start, :length)
    end

    it "reports the correct tag symbol" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m[:tag]).to eq(:contact)
    end

    it "reports the correct pattern name" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m[:name]).to eq("email")
    end

    it "reports the matched value" do
      m = DataRedactor.scan(email)[:matches].first
      expect(m[:value]).to eq(email)
    end

    it "reports correct start and length that index into the original string" do
      text = "contact: #{email} end"
      result = DataRedactor.scan(text)
      m = result[:matches].find { |x| x[:name] == "email" }
      expect(text.byteslice(m[:start], m[:length])).to eq(email)
    end

    it "returns correct positions for multiple matches from different patterns" do
      text = "k=#{aws} e=#{email} i=#{iban}"
      result = DataRedactor.scan(text)
      result[:matches].each do |m|
        expect(text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]}: byteslice mismatch"
      end
    end

    it "returns correct positions when a shorter value is replaced before a later one" do
      # email (16 bytes) fires after aws (20 bytes); replacement shifts subsequent offsets
      text = "#{aws} #{email}"
      result = DataRedactor.scan(text)
      result[:matches].each do |m|
        expect(text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]}: byteslice mismatch after earlier replacement"
      end
    end

    it "returns correct positions for repeated matches of the same pattern" do
      # Three AKIAs across three lines exercises intra-pattern repl_log
      # accumulation; before the fix the 2nd and 3rd reported start offsets
      # were off by +10 per prior match (the placeholder length).
      line = "user mario@example.com ip 192.168.0.1 key AKIAIOSFODNN7EXAMPLE\n"
      text = line * 3
      result = DataRedactor.scan(text)
      result[:matches].each do |m|
        expect(text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]} @ #{m[:start]}: byteslice mismatch (regression of multi-match offset bug)"
      end
    end

    it "returns no matches for text with nothing sensitive" do
      result = DataRedactor.scan("hello world")
      expect(result[:matches]).to be_empty
      expect(result[:redacted]).to eq("hello world")
    end

    it "accepts only: filter" do
      text = "#{email} #{aws}"
      result = DataRedactor.scan(text, only: :contact)
      names = result[:matches].map { |m| m[:name] }
      expect(names).to include("email")
      expect(names).not_to include("aws_access_key_id")
    end

    it "accepts except: filter" do
      text = "#{email} #{aws}"
      result = DataRedactor.scan(text, except: :contact)
      names = result[:matches].map { |m| m[:name] }
      expect(names).not_to include("email")
      expect(names).to include("aws_access_key_id")
    end

    it "supports combining only: and except: with mixed Symbols and pattern names" do
      text = "alice@example.com +1-202-555-0173"
      result = DataRedactor.scan(text, only: :contact, except: ["email"])
      names = result[:matches].map { |m| m[:name] }
      expect(names).not_to include("email")
      expect(names).to include("phone_e164")
    end

    it "includes custom pattern matches" do
      DataRedactor.clear_custom_patterns!
      DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
      result = DataRedactor.scan("hire EMP-123456 done")
      m = result[:matches].find { |x| x[:name] == "emp_id" }
      expect(m).not_to be_nil
      expect(m[:tag]).to eq(:custom)
      expect(m[:value]).to eq("EMP-123456")
      DataRedactor.clear_custom_patterns!
    end
  end
end
