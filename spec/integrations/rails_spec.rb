require "data_redactor/integrations/rails"

RSpec.describe DataRedactor::Integrations::Rails do
  describe ".filter" do
    let(:filter) { described_class.filter }

    it "returns a callable" do
      expect(filter).to respond_to(:call)
      expect(filter.arity).to eq(2)
    end

    it "redacts sensitive content in String values via String#replace" do
      value = +"contact alice@example.com"
      filter.call("notes", value)
      expect(value).to include("[REDACTED]")
      expect(value).not_to include("alice@example.com")
    end

    it "leaves non-String values untouched" do
      val = 42
      expect { filter.call("count", val) }.not_to raise_error
      expect(val).to eq(42)
    end

    it "leaves clean strings byte-identical (no replace called)" do
      value = +"nothing sensitive here"
      original_id = value.object_id
      filter.call("notes", value)
      expect(value).to eq("nothing sensitive here")
      expect(value.object_id).to eq(original_id)
    end

    it "honours only:/except: filters" do
      f = described_class.filter(only: [:credentials])
      value = +"user alice@example.com with key AKIAIOSFODNN7EXAMPLE"
      f.call("notes", value)
      expect(value).to include("alice@example.com")  # :contact not in only:
      expect(value).not_to include("AKIAIOSFODNN7EXAMPLE")
    end

    it "honours custom placeholder" do
      f = described_class.filter(placeholder: "***")
      value = +"contact alice@example.com"
      f.call("notes", value)
      expect(value).to include("***")
    end
  end
end
