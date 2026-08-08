RSpec.describe DataRedactor do
  describe "chunked path (inputs > CHUNK_SIZE)" do
    let(:line) { "user mario@example.com ip 192.168.0.1 key AKIAIOSFODNN7EXAMPLE\n" }
    # Repeat enough times to comfortably exceed CHUNK_SIZE (64 KB).
    let(:big_text) { line * 2000 }  # ~140 KB

    it "produces output identical to running the C engine on the whole input at once" do
      chunked   = DataRedactor.redact(big_text)
      direct    = DataRedactor.send(:_redact, big_text,
                                     DataRedactor::PH_MODE_PLAIN, "[REDACTED]",
                                     DataRedactor.send(:build_enable_bits, nil, nil))
      expect(chunked).to eq(direct)
    end

    it "scan preserves the byteslice invariant across chunk boundaries" do
      result = DataRedactor.scan(big_text)
      expect(result[:matches]).not_to be_empty
      result[:matches].each do |m|
        expect(big_text.byteslice(m[:start], m[:length])).to eq(m[:value]),
          "#{m[:name]} @ #{m[:start]}: byteslice mismatch across chunks"
      end
    end

    it "redacts a match that sits right at a chunk boundary (last line of chunk)" do
      # Construct an input where a match ends exactly at byte CHUNK_SIZE-1, so
      # the newline that terminates it falls on the boundary.
      cs = DataRedactor::CHUNK_SIZE
      filler = "x" * (cs - line.bytesize)
      text = filler + line + line  # match on the line straddling boundary
      result = DataRedactor.redact(text)
      expect(result.scan("[REDACTED]").size).to be >= 6  # 3 matches × 2 lines
    end
  end

  # Overlap-resolution behaviour: longest-match-wins, with pattern-id as the
  # tiebreak for equal-length matches (mm_resolve in matcher.c). When two patterns
  # match overlapping spans the LONGER span is kept; when two match the SAME span
  # the lower pattern-id wins. Rationale and worked examples in
  # docs/standalone_matcher_design.md "Overlap resolution". For a redaction gem the
  # correct failure mode when uncertain is "redact more, not less" — the AKIA case
  # below shows why: pattern-id priority (the pre-0.15 sequential-rewrite behaviour)
  # would leave a secret partly unredacted.
  describe "overlap resolution — longest-match-wins" do
    it "longest-match wins: a later-index pattern matching a LONGER span beats an earlier-index shorter one" do
      # aws_access_key_id (index 14) matches the leading 20 chars.
      # aws_secret_access_key (index 15) matches all 40 chars.
      # Longest-match: the 40-char secret wins; the whole span is redacted and
      # nothing leaks. (Pre-0.15 pattern-id priority left the trailing 20 chars.)
      input = "AKIAIOSFODNN7EXAMPLE" + ("A" * 20)  # 40 chars
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["aws_secret_access_key"])
      expect(result[:matches].first[:value]).to eq(input)
      expect(DataRedactor.redact(input)).to eq("[REDACTED]")
    end

    it "longest-match is safer when uncertain: prefers the more-thorough redaction" do
      # The safety argument: when we can't tell whether 40 alphanum bytes are
      # 'one secret' or 'two adjacent secrets', redact more rather than less.
      input = "AKIAIOSFODNN7EXAMPLE" + "B" * 20  # 40 alphanum
      expect(DataRedactor.redact(input)).to eq("[REDACTED]")
    end

    # The longest-match outcome must be independent of WHICH characters follow the
    # AKIA prefix: aws_secret_access_key is [A-Za-z0-9/+=]{40}, so any 20-char
    # suffix from that class forms a valid 40-char secret and the whole span is
    # redacted. (Pre-0.15 sequential rewrite redacted only the 20-char prefix.)
    {
      "repeated A"   => "A" * 20,
      "repeated B"   => "B" * 20,
      "repeated Z"   => "Z" * 20,
      "repeated 9"   => "9" * 20,
      "mixed alnum"  => "B3xQ7mK9pL2wR5tZ8nV4",
      "lowercase"    => "abcdefghijklmnopqrst",
      "with slashes" => "B/B/B/B/B/B/B/B/B/B/",
    }.each do |label, suffix|
      it "redacts the whole 40-char secret regardless of the following bytes (#{label})" do
        input = "AKIAIOSFODNN7EXAMPLE" + suffix
        expect(DataRedactor.redact(input)).to eq("[REDACTED]")
        result = DataRedactor.scan(input)
        expect(result[:matches].map { |m| m[:name] }).to eq(["aws_secret_access_key"])
        expect(result[:matches].first[:value]).to eq(input)
      end
    end

    it "keeps the longest secret but not bytes beyond it: AKIA + 40 trailing alnum redacts the first 40" do
      # aws_secret_access_key is exactly {40}, so on AKIA(20)+40 alnum it claims
      # [0,40) (the longest single match at start 0); the trailing 20 survive
      # because no enabled pattern matches them.
      input = "AKIAIOSFODNN7EXAMPLE" + ("x" * 40)  # 60 alphanum
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["aws_secret_access_key"])
      expect(DataRedactor.redact(input)).to eq("[REDACTED]" + ("x" * 20))
    end

    it "ties broken by pattern-id: multiple patterns matching the same exact span pick the lowest index" do
      # 11-digit number: polish_pesel (81), belgian_national_number (82),
      # norwegian_fodselsnummer (83), polish_pesel_2 (87) all match the same
      # 11-char span. Equal length → lowest pattern-id (polish_pesel) wins.
      input = "id 85121612345 end"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["polish_pesel"])
    end

    it "tie broken by pattern-id among 9-digit patterns (czech_rodne_cislo, lowest index, wins)" do
      # czech_rodne_cislo (index 69) is `[0-9]{6}/?[0-9]{3,4}` — the / is optional,
      # so it matches 9 consecutive digits, same span as passport_9digits (84),
      # dutch_bsn (85), austrian_abgabenkontonummer (86). Equal length → index 69 wins.
      input = "num 123456789 end"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["czech_rodne_cislo"])
    end

    it "the longer credit_card span beats the shorter 11-digit national-ID slices it contains" do
      # credit_card (index 56) matches a 16-digit Visa; polish_pesel/belgian/etc.
      # (81-87) would each match an 11-digit slice inside it. 16 > 11, so the
      # credit_card span wins and the shorter overlapping slices are dropped.
      input = "card=4111111111111111 end"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["credit_card"])
    end

    it "the longest github token wins over an aws_secret slice starting one byte later" do
      # github_classic_pat (ghp_ + 36 = 40 chars) matches [0,40); aws_secret_access_key
      # would match [4,44). Both are length 40, but github starts earlier, so its span
      # is offered first and claims the region. The trailing 11-digit run abuts an
      # alnum byte (no boundary), so the boundary-wrapped digit patterns can't match it.
      input = "ghp_ABCDEFGHIJabcdefghij0123456789ABCDEF85121612345"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["github_classic_pat"])
      expect(DataRedactor.redact(input)).to eq("[REDACTED]85121612345")
    end

    it "only the prefix matches when no longer span is possible; leftovers survive verbatim" do
      # Only AKIA fits (a 40-char secret needs 40 alnum after 'key='; only 39 here).
      # No overlap to resolve — aws_access_key_id claims its 20 chars.
      input = "key=AKIAIOSFODNN7EXAMPLEextrabytesfor20"
      result = DataRedactor.scan(input)
      expect(result[:matches].map { |m| m[:name] }).to eq(["aws_access_key_id"])
    end
  end

  # Two sensitive tokens that ABUT with NO separator between them. The v19 engine
  # scans the ORIGINAL buffer in one pass and cannot see a word boundary that a
  # rewrite would have created. A boundary-wrapped pattern needs a non-alnum byte
  # (or buffer edge) on each side, so when its token directly abuts an alnum run it
  # simply does not match the original text — the abutting token is left as-is.
  # These cases are rare in real text (always separator-delimited) and the surviving
  # bytes are a cryptographically-dead partial token, not a recoverable secret.
  describe "overlap resolution — directly-abutting tokens (no separator)" do
    it "an SSN abutting an IPv4 (no separator) leaves the SSN unredacted" do
      # 123-45-6789 has no boundary char after '6789' (next byte is '1'), so us_ssn
      # cannot match the original text; only ipv4 is redacted.
      input = "123-45-6789192.168.1.1"
      expect(DataRedactor.redact(input)).to eq("123-45-6789[REDACTED]")
    end

    it "a greedy match leaves a mangled half-token when a boundary is absent" do
      # ipv4 matches "192.168.1.1", leaving "123-45-6789"; but the leading digits
      # abut the ipv4 with no boundary, so only "3-45-6789" survives after [REDACTED].
      input = "192.168.1.1123-45-6789"
      expect(DataRedactor.redact(input)).to eq("[REDACTED]3-45-6789")
    end
  end
end
