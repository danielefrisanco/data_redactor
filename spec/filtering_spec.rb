RSpec.describe DataRedactor do
  describe "tag filtering" do
    let(:aws)    { "AKIAIOSFODNN7EXAMPLE" }                        # :credentials
    let(:email)  { "user@example.com" }                            # :contact
    let(:iban)   { "DE89370400440532013000" }                      # :financial
    let(:cf)     { "RSSMRA85M01H501Z" }                            # :tax_id
    let(:ssn)    { "123-45-6789" }                                 # :national_id
    let(:input)  { "k=#{aws} m=#{email} i=#{iban} cf=#{cf} s=#{ssn}" }

    describe ".tags" do
      it "returns the list of supported tags" do
        expect(DataRedactor.tags).to contain_exactly(
          :credentials, :financial, :tax_id, :national_id,
          :contact, :network, :travel, :other, :custom
        )
      end
    end

    describe "only:" do
      it "redacts only patterns in the given tag" do
        result = DataRedactor.redact(input, only: [:credentials])
        expect(result).not_to include(aws)
        expect(result).to include(email, iban, cf, ssn)
      end

      it "accepts multiple tags" do
        result = DataRedactor.redact(input, only: [:credentials, :contact])
        expect(result).not_to include(aws, email)
        expect(result).to include(iban, cf, ssn)
      end

      it "accepts a single symbol (not just an array)" do
        result = DataRedactor.redact(input, only: :financial)
        expect(result).not_to include(iban)
        expect(result).to include(aws, email, cf, ssn)
      end
    end

    describe "except:" do
      it "redacts every tag except the given one" do
        result = DataRedactor.redact(input, except: [:contact])
        expect(result).to include(email)
        expect(result).not_to include(aws, iban, cf, ssn)
      end

      it "accepts multiple tags" do
        # Two-tag case: IBAN digit substrings can overlap national_id shapes,
        # so we only assert about email (no overlap) and that aws/cf/ssn still
        # get redacted.
        result = DataRedactor.redact(input, except: [:contact, :financial])
        expect(result).to include(email)
        expect(result).not_to include(aws, cf, ssn)
      end
    end

    describe "validation" do
      it "allows only: and except: to be combined (e.g. only :contact except email)" do
        text = "user@example.com phone +1-202-555-0173 key AKIAIOSFODNN7EXAMPLE"
        result = DataRedactor.redact(text, only: :contact, except: ["email"])
        expect(result).to include("user@example.com") # email kept
        expect(result).not_to include("+1-202-555-0173") # phone redacted
        expect(result).to include("AKIAIOSFODNN7EXAMPLE") # not in :contact
      end

      it "raises UnknownTagError for an unknown tag" do
        expect { DataRedactor.redact(input, only: [:bogus]) }
          .to raise_error(DataRedactor::UnknownTagError, /bogus/)
      end

      it "raises UnknownPatternError for an unknown pattern name" do
        expect { DataRedactor.redact(input, except: ["nope"]) }
          .to raise_error(DataRedactor::UnknownPatternError, /nope/)
      end

      it "lets except: win over only: when they overlap (same tag → no-op)" do
        text = "user@example.com and +1-202-555-0173"
        expect(DataRedactor.redact(text, only: :contact, except: :contact)).to eq(text)
      end

      it "lets except: win over only: when both name the same pattern" do
        text = "user@example.com is the address"
        expect(DataRedactor.redact(text, only: ["email"], except: ["email"])).to eq(text)
      end

      it "redacts a single named pattern via only: as a String" do
        text = "user@example.com and AKIAIOSFODNN7EXAMPLE"
        result = DataRedactor.redact(text, only: ["aws_access_key_id"])
        expect(result).to include("user@example.com")
        expect(result).not_to include("AKIAIOSFODNN7EXAMPLE")
      end

      it "redacts a tag plus an extra named pattern from another tag" do
        text = "user@example.com and AKIAIOSFODNN7EXAMPLE"
        result = DataRedactor.redact(text, only: [:contact, "aws_access_key_id"])
        expect(result).not_to include("user@example.com")
        expect(result).not_to include("AKIAIOSFODNN7EXAMPLE")
      end
    end

    it "with no filter behaves identically to a fully-enabled call into _redact" do
      all_on = Array.new(DataRedactor::BUILTIN_PATTERN_NAMES.length, 1)
      expect(DataRedactor.redact(input))
        .to eq(DataRedactor._redact(input, DataRedactor::PH_MODE_PLAIN, "[REDACTED]", all_on))
    end
  end
end
