RSpec.describe DataRedactor do
  describe "thread safety (GVL serialisation)" do
    # Phase 1 does not release the GVL during mm_scan, so concurrent redact/scan
    # calls are serialised by MRI. These specs verify that N threads running
    # distinct inputs in parallel each produce the same result as single-threaded
    # execution. If the engine had unguarded shared mutable state a race would
    # produce wrong output or a crash.
    N_THREADS = 8
    N_ITERS   = 50

    it "redact is safe under concurrent threads" do
      payloads = [
        ["token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end",
         "token [REDACTED] end"],
        ["key=AKIAIOSFODNN7EXAMPLE rest",
         "key=[REDACTED] rest"],
        ["iban: DE89370400440532013000 here",
         "iban: [REDACTED] here"],
        ["email test@example.com done",
         "email [REDACTED] done"],
        ["ip 192.168.1.1 ok",
         "ip [REDACTED] ok"],
        ["card 4111111111111111 end",
         "card [REDACTED] end"],
        ["ssn 123-45-6789 here",
         "ssn [REDACTED] here"],
        ["plain text no secrets",
         "plain text no secrets"],
      ]

      errors = []
      threads = payloads.map do |(input, expected)|
        Thread.new do
          N_ITERS.times do
            got = DataRedactor.redact(input)
            errors << "#{input.inspect}: expected #{expected.inspect}, got #{got.inspect}" unless got == expected
          end
        end
      end
      threads.each(&:join)
      expect(errors).to be_empty
    end

    it "scan is safe under concurrent threads" do
      payloads = [
        ["token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end", "github_classic_pat"],
        ["key=AKIAIOSFODNN7EXAMPLE rest",                      "aws_access_key_id"],
        ["iban: DE89370400440532013000 here",                  "iban_de"],
        ["email test@example.com done",                        "email"],
        ["ip 192.168.1.1 ok",                                  "ipv4"],
      ]

      errors = []
      threads = payloads.map do |(input, expected_name)|
        Thread.new do
          N_ITERS.times do
            result = DataRedactor.scan(input)
            names  = result[:matches].map { |m| m[:name] }
            errors << "#{input.inspect}: expected [#{expected_name}], got #{names.inspect}" unless names == [expected_name]
          end
        end
      end
      threads.each(&:join)
      expect(errors).to be_empty
    end
  end
end
