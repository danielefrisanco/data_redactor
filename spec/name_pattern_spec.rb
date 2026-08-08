RSpec.describe DataRedactor do
  describe ".name_pattern" do
    after(:each) { DataRedactor.clear_custom_patterns! }

    # Register a generated name pattern and report whether `text` gets redacted.
    def name_redacted?(text, *args, **kwargs)
      DataRedactor.clear_custom_patterns!
      DataRedactor.add_pattern(
        name: "spec_name", regex: DataRedactor.name_pattern(*args, **kwargs), tag: :contact
      )
      DataRedactor.redact("x #{text} y").include?("[REDACTED]")
    end

    it "returns a String POSIX ERE" do
      expect(DataRedactor.name_pattern("Mario", "Rossi")).to be_a(String)
    end

    it "matches the canonical First Last form" do
      expect(name_redacted?("Mario Rossi", "Mario", "Rossi")).to be true
    end

    it "matches case-insensitively" do
      expect(name_redacted?("mario rossi", "Mario", "Rossi")).to be true
      expect(name_redacted?("MARIO ROSSI", "Mario", "Rossi")).to be true
    end

    it "matches the swapped Last First order" do
      expect(name_redacted?("Rossi Mario", "Mario", "Rossi")).to be true
    end

    it "matches the Last, First comma forms" do
      expect(name_redacted?("Rossi, Mario", "Mario", "Rossi")).to be true
      expect(name_redacted?("Rossi,Mario", "Mario", "Rossi")).to be true
    end

    it "matches initial-only forms" do
      expect(name_redacted?("M. Rossi", "Mario", "Rossi")).to be true
      expect(name_redacted?("M Rossi", "Mario", "Rossi")).to be true
      expect(name_redacted?("Mario R.", "Mario", "Rossi")).to be true
      expect(name_redacted?("M.R.", "Mario", "Rossi")).to be true
      expect(name_redacted?("MR", "Mario", "Rossi")).to be true
    end

    it "does not match a name embedded in a longer word" do
      expect(name_redacted?("Mariolino", "Mario", "Rossi")).to be false
      expect(name_redacted?("marioland", "Mario", "Rossi")).to be false
    end

    it "does not match a different name" do
      expect(name_redacted?("Maria Rossi", "Mario", "Rossi")).to be false
      expect(name_redacted?("Mario Russo", "Mario", "Rossi")).to be false
    end

    it "tolerates diacritics on the matched text" do
      expect(name_redacted?("José Muñoz", "Jose", "Munoz")).to be true
      expect(name_redacted?("JOSÉ MUÑOZ", "Jose", "Munoz")).to be true
    end

    it "matches an accented input against the bare ASCII form" do
      expect(name_redacted?("Jose Munoz", "José", "Muñoz")).to be true
    end

    it "treats spaces and hyphens interchangeably in a hyphenated part" do
      expect(name_redacted?("Anne-Marie Berg", "Anne-Marie", "Berg")).to be true
      expect(name_redacted?("Anne Marie Berg", "Anne-Marie", "Berg")).to be true
      expect(name_redacted?("AnneMarie Berg",  "Anne-Marie", "Berg")).to be true
    end

    it "matches either half of a hyphenated part alone" do
      expect(name_redacted?("Anne Berg",  "Anne-Marie", "Berg")).to be true
      expect(name_redacted?("Marie Berg", "Anne-Marie", "Berg")).to be true
    end

    it "matches a multi-word last name" do
      expect(name_redacted?("Jan Van der Berg", "Jan", "Van der Berg")).to be true
      expect(name_redacted?("Jan Van-der-Berg", "Jan", "Van der Berg")).to be true
    end

    it "matches both no-middle and with-middle forms when middle: is given" do
      expect(name_redacted?("Mario Rossi", "Mario", "Rossi", middle: "Luigi")).to be true
      expect(name_redacted?("Mario Luigi Rossi", "Mario", "Rossi", middle: "Luigi")).to be true
      expect(name_redacted?("Rossi Mario Luigi", "Mario", "Rossi", middle: "Luigi")).to be true
    end

    it "is usable through add_pattern with only:/except: filtering" do
      DataRedactor.add_pattern(
        name: "spec_name", regex: DataRedactor.name_pattern("Mario", "Rossi"), tag: :contact
      )
      expect(DataRedactor.redact("x Mario Rossi y", only: :contact)).to include("[REDACTED]")
      expect(DataRedactor.redact("x Mario Rossi y", except: :contact)).to include("Mario Rossi")
    end

    it "raises ArgumentError on an empty or non-String first name" do
      expect { DataRedactor.name_pattern("", "Rossi") }.to raise_error(ArgumentError)
      expect { DataRedactor.name_pattern(nil, "Rossi") }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError on an empty or non-String last name" do
      expect { DataRedactor.name_pattern("Mario", "  ") }.to raise_error(ArgumentError)
      expect { DataRedactor.name_pattern("Mario", 42) }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError when middle: is given but blank" do
      expect { DataRedactor.name_pattern("Mario", "Rossi", middle: "") }.to raise_error(ArgumentError)
    end
  end

  # Inputs larger than DataRedactor::CHUNK_SIZE take a different Ruby code path
  # that splits the input on newlines and runs the C engine per chunk. The
  # observable behaviour must be identical to the single-shot path.
end
