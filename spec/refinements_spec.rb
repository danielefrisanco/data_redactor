require "data_redactor/refinements"

RSpec.describe DataRedactor::Refinements do
  using DataRedactor::Refinements

  describe "String#redact" do
    it "redacts via DataRedactor.redact (happy path)" do
      expect("email alice@example.com".redact).to eq("email [REDACTED]")
    end

    it "returns a new String and does not mutate the receiver" do
      original = "ssn 123-45-6789"
      result = original.redact
      expect(result).not_to include("123-45-6789")
      expect(original).to eq("ssn 123-45-6789")
    end

    it "forwards only:" do
      input = "card 4111111111111111 email a@b.com"
      expect(input.redact(only: [:financial])).to eq("card [REDACTED] email a@b.com")
    end

    it "forwards except:" do
      input = "card 4111111111111111 email a@b.com"
      expect(input.redact(except: [:contact])).to eq("card [REDACTED] email a@b.com")
    end

    it "forwards placeholder:" do
      expect("email a@b.com".redact(placeholder: :tagged)).to eq("email [REDACTED:CONTACT]")
    end

    it "leaves a clean String untouched" do
      expect("nothing sensitive here".redact).to eq("nothing sensitive here")
    end
  end

  describe "Hash#redact" do
    it "deep-redacts String values, never touches keys, returns a copy" do
      input = { "user" => { "email" => "a@b.com" }, "count" => 3 }
      out = input.redact
      expect(out).to eq("user" => { "email" => "[REDACTED]" }, "count" => 3)
      expect(input["user"]["email"]).to eq("a@b.com")
    end

    it "forwards filters" do
      input = { card: "4111111111111111", email: "a@b.com" }
      expect(input.redact(only: [:financial])).to eq(card: "[REDACTED]", email: "a@b.com")
    end
  end

  describe "Array#redact" do
    it "deep-redacts String elements, passes non-strings through, returns a copy" do
      input = ["a@b.com", 3, "clean"]
      out = input.redact
      expect(out).to eq(["[REDACTED]", 3, "clean"])
      expect(input.first).to eq("a@b.com")
    end
  end

  describe "lexical scoping (opt-in only)" do
    # `using` is file-lexical, so within THIS spec file #redact is active
    # everywhere. To prove the refinement is not global, check in a fresh
    # process that requires the file but never calls `using`.
    it "does not define #redact on String for code that did not `using` it" do
      script = 'require "data_redactor/refinements"; ' \
               'print "a@b.com".respond_to?(:redact)'
      out = `ruby -Ilib -e '#{script}'`.strip
      expect(out).to eq("false")
    end
  end
end
