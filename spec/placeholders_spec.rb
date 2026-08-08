RSpec.describe DataRedactor do
  describe "configurable placeholder" do
    let(:email) { "user@example.com" }
    let(:aws)   { "AKIAIOSFODNN7EXAMPLE" }
    let(:iban)  { "DE89370400440532013000" }

    describe "plain string" do
      it "uses the default [REDACTED] when no placeholder given" do
        expect(DataRedactor.redact(email)).to include("[REDACTED]")
      end

      it "uses a custom plain string" do
        result = DataRedactor.redact(email, placeholder: "***")
        expect(result).to include("***")
        expect(result).not_to include("[REDACTED]")
        expect(result).not_to include(email)
      end

      it "uses an empty string placeholder" do
        result = DataRedactor.redact(email, placeholder: "")
        expect(result).not_to include(email)
        expect(result).not_to include("[REDACTED]")
      end
    end

    describe ":tagged placeholder" do
      it "replaces with [REDACTED:TAGNAME]" do
        result = DataRedactor.redact(email, placeholder: :tagged)
        expect(result).to include("[REDACTED:CONTACT]")
        expect(result).not_to include(email)
      end

      it "uses the correct tag for each pattern" do
        text   = "email #{email} key #{aws} iban #{iban}"
        result = DataRedactor.redact(text, placeholder: :tagged)
        expect(result).to include("[REDACTED:CONTACT]")
        expect(result).to include("[REDACTED:CREDENTIALS]")
        expect(result).to include("[REDACTED:FINANCIAL]")
      end

      it "works with only: filter" do
        result = DataRedactor.redact("#{email} #{aws}", only: :contact, placeholder: :tagged)
        expect(result).to include("[REDACTED:CONTACT]")
        expect(result).to include(aws)
      end
    end

    describe ":hash placeholder" do
      it "replaces with [TAGNAME_xxxx] format" do
        result = DataRedactor.redact(email, placeholder: :hash)
        expect(result).to match(/\[CONTACT_[0-9a-f]{4}\]/)
        expect(result).not_to include(email)
      end

      it "produces the same hash for the same value" do
        result1 = DataRedactor.redact("a #{email} b", placeholder: :hash)
        result2 = DataRedactor.redact("a #{email} b", placeholder: :hash)
        expect(result1).to eq(result2)
      end

      it "produces different hashes for different values" do
        r1 = DataRedactor.redact("user@foo.com", placeholder: :hash)
        r2 = DataRedactor.redact("user@bar.com", placeholder: :hash)
        expect(r1).not_to eq(r2)
      end

      it "uses the correct tag name" do
        result = DataRedactor.redact(aws, placeholder: :hash)
        expect(result).to match(/\[CREDENTIALS_[0-9a-f]{4}\]/)
      end
    end

    describe ":length placeholder" do
      it "replaces with [REDACTED:N] where N is the byte length" do
        result = DataRedactor.redact(email, placeholder: :length)
        expect(result).to eq("[REDACTED:#{email.bytesize}]")
        expect(result).not_to include(email)
      end

      it "uses each match's own length" do
        result = DataRedactor.redact("#{email} #{aws}", placeholder: :length)
        expect(result).to eq("[REDACTED:#{email.bytesize}] [REDACTED:#{aws.bytesize}]")
      end
    end

    describe ":tagged_length placeholder" do
      it "replaces with [REDACTED:TAGNAME:N]" do
        result = DataRedactor.redact(email, placeholder: :tagged_length)
        expect(result).to eq("[REDACTED:CONTACT:#{email.bytesize}]")
        expect(result).not_to include(email)
      end

      it "uses the correct tag and length for each pattern" do
        result = DataRedactor.redact("#{email} #{aws}", placeholder: :tagged_length)
        expect(result).to include("[REDACTED:CONTACT:#{email.bytesize}]")
        expect(result).to include("[REDACTED:CREDENTIALS:#{aws.bytesize}]")
      end
    end

    describe "validation" do
      it "raises ArgumentError for an invalid placeholder value" do
        expect { DataRedactor.redact(email, placeholder: 42) }
          .to raise_error(ArgumentError, /placeholder/)
      end
    end
  end
end
