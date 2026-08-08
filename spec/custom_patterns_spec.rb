RSpec.describe DataRedactor do
  describe "custom patterns" do
    before(:each) { DataRedactor.clear_custom_patterns! }
    after(:each)  { DataRedactor.clear_custom_patterns! }

    describe ".add_pattern / .redact" do
      it "redacts text matching a simple custom pattern" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        result = DataRedactor.redact("id EMP-123456 ok")
        expect(result).to include("[REDACTED]")
        expect(result).not_to include("EMP-123456")
      end

      it "accepts a Regexp and uses its source" do
        DataRedactor.add_pattern(name: "emp_id", regex: /EMP-[0-9]{6}/)
        expect(DataRedactor.redact("id EMP-999999 ok")).to include("[REDACTED]")
      end

      it "replaces an existing pattern with the same name" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{4}")
        expect(DataRedactor.custom_patterns.count { |p| p[:name] == "emp_id" }).to eq(1)
        expect(DataRedactor.redact("id EMP-1234 ok")).to include("[REDACTED]")
      end

      it "runs custom pattern only when :custom tag is included" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        expect(DataRedactor.redact("EMP-123456", only: [:custom])).to include("[REDACTED]")
        expect(DataRedactor.redact("EMP-123456", except: [:custom])).to include("EMP-123456")
      end

      it "supports boundary: true to avoid matching inside longer alphanumeric tokens" do
        DataRedactor.add_pattern(name: "emp_code", regex: "EMP[0-9]{4}", boundary: true)
        # standalone token → redacted
        expect(DataRedactor.redact("code EMP1234 ok", only: [:custom])).to include("[REDACTED]")
        # embedded inside a longer alphanumeric token → NOT redacted
        expect(DataRedactor.redact("XEMP1234Y", only: [:custom])).to include("XEMP1234Y")
      end

      it "supports a built-in tag other than :custom" do
        DataRedactor.add_pattern(name: "internal_key", regex: "INT-[A-Z]{3}", tag: :credentials)
        pattern = DataRedactor.custom_patterns.find { |p| p[:name] == "internal_key" }
        expect(pattern[:tag]).to eq(:credentials)
        expect(DataRedactor.redact("INT-ABC", only: [:credentials])).to include("[REDACTED]")
        expect(DataRedactor.redact("INT-ABC", only: [:custom])).to include("INT-ABC")
      end
    end

    describe ".remove_pattern" do
      it "removes a named pattern and returns true" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}")
        expect(DataRedactor.remove_pattern("emp_id")).to be true
        expect(DataRedactor.redact("EMP-123456")).to include("EMP-123456")
      end

      it "returns false when name is not found" do
        expect(DataRedactor.remove_pattern("nonexistent")).to be false
      end
    end

    describe ".custom_patterns" do
      it "returns an array of hashes with name, source, tag, boundary" do
        DataRedactor.add_pattern(name: "emp_id", regex: "EMP-[0-9]{6}", boundary: true)
        patterns = DataRedactor.custom_patterns
        expect(patterns.length).to eq(1)
        p = patterns.first
        expect(p[:name]).to eq("emp_id")
        expect(p[:source]).to eq("EMP-[0-9]{6}")
        expect(p[:tag]).to eq(:custom)
        expect(p[:boundary]).to be true
      end

      it "returns empty array when no custom patterns" do
        expect(DataRedactor.custom_patterns).to eq([])
      end
    end

    describe ".clear_custom_patterns!" do
      it "removes all custom patterns" do
        DataRedactor.add_pattern(name: "a", regex: "AAA-[0-9]+")
        DataRedactor.add_pattern(name: "b", regex: "BBB-[0-9]+")
        DataRedactor.clear_custom_patterns!
        expect(DataRedactor.custom_patterns).to be_empty
      end
    end

    describe "engine scan-state invalidation across pattern-set changes" do
      # The v19 engine caches per-thread scan state (NFA scratch + lazy DFA),
      # keyed by pattern slot. add_pattern/remove_pattern/clear_custom_patterns!
      # bump a generation counter that drops and rebuilds that cache. This
      # exercises the drop-and-regrow path on the same thread (warm cache, then
      # mutate the pattern set, then redact again) and asserts the built-in
      # cache stays correct and custom patterns appear/disappear as expected.
      it "redacts correctly after add/remove churn between calls" do
        text = "email a@b.com and run EMP-123456 plus card 4111 1111 1111 1111"

        # Warm the cache on built-ins only.
        warm = DataRedactor.redact(text)
        expect(warm).not_to include("a@b.com")
        expect(warm).not_to include("4111 1111 1111 1111")
        expect(warm).to include("EMP-123456") # not a built-in yet

        # Add a custom -> generation bump -> cache dropped & rebuilt next call.
        DataRedactor.add_pattern(name: "emp", regex: "EMP-[0-9]{6}")
        after_add = DataRedactor.redact(text)
        expect(after_add).not_to include("EMP-123456")  # custom now fires
        expect(after_add).not_to include("a@b.com")      # built-ins still fire
        expect(after_add).not_to include("4111 1111 1111 1111")

        # Remove it -> generation bump -> custom gone, built-ins still correct.
        DataRedactor.remove_pattern("emp")
        after_remove = DataRedactor.redact(text)
        expect(after_remove).to eq(warm)
      end

      it "keeps two customs independent after a middle removal compacts slots" do
        # remove_pattern compacts the engine array, so slot p shifts to a
        # different pattern. The generation bump must invalidate the cache so the
        # shifted slot is not served from a stale DFA.
        DataRedactor.add_pattern(name: "x", regex: "XX-[0-9]{3}")
        DataRedactor.add_pattern(name: "y", regex: "YY-[0-9]{3}")
        DataRedactor.add_pattern(name: "z", regex: "ZZ-[0-9]{3}")
        DataRedactor.redact("XX-111 YY-222 ZZ-333") # warm all three slots

        DataRedactor.remove_pattern("y") # compacts: z shifts into y's old slot
        got = DataRedactor.redact("XX-111 YY-222 ZZ-333")
        expect(got).not_to include("XX-111")
        expect(got).to include("YY-222")       # removed
        expect(got).not_to include("ZZ-333")   # still matches despite slot shift
      end
    end

    describe "validation" do
      it "raises ArgumentError for an empty name" do
        expect { DataRedactor.add_pattern(name: "", regex: "EMP-[0-9]+") }
          .to raise_error(ArgumentError, /non-empty/)
      end

      it "raises ArgumentError for a non-String/Regexp regex" do
        expect { DataRedactor.add_pattern(name: "x", regex: 42) }
          .to raise_error(ArgumentError, /String or Regexp/)
      end

      it "raises InvalidPatternError for \\d (Ruby shorthand)" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP-\\d{6}") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for \\b (word boundary)" do
        expect { DataRedactor.add_pattern(name: "x", regex: "\\bEMP\\b") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for lookahead" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP(?=[0-9])") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for non-greedy quantifier" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP-[0-9]+?") }
          .to raise_error(DataRedactor::InvalidPatternError, /POSIX ERE/)
      end

      it "raises InvalidPatternError for invalid POSIX ERE (regcomp rejects it)" do
        expect { DataRedactor.add_pattern(name: "x", regex: "[invalid") }
          .to raise_error(DataRedactor::InvalidPatternError)
      end

      it "raises InvalidPatternError for capture groups with boundary: true" do
        expect { DataRedactor.add_pattern(name: "x", regex: "(EMP)-[0-9]{6}", boundary: true) }
          .to raise_error(DataRedactor::InvalidPatternError, /capture groups/)
      end

      it "raises UnknownTagError for an invalid tag" do
        expect { DataRedactor.add_pattern(name: "x", regex: "EMP-[0-9]+", tag: :bogus) }
          .to raise_error(DataRedactor::UnknownTagError)
      end
    end

    describe "concurrent registration vs redaction" do
      # Functional guard for the custom-pattern mutex. The readers run with
      # custom patterns ENABLED (default redact/scan, no `only:`), so each call
      # iterates the shared custom array while the writer add/remove-churns it.
      #
      # Note on the GVL: this test uses a SMALL input (< the C-layer GVL-release
      # threshold), so redact keeps the GVL here and the custom-array access is
      # serialised. It guards the mutex against deadlock and asserts functional
      # correctness under churn. The large-input sibling test below crosses the
      # threshold so the built-in scan runs GVL-free in true parallel — that one
      # is the real race detector for the per-thread scan-state refactor. The
      # redacted built-ins and the always-present "stable" custom are invariant
      # to the churn, so their absence from the output is a stable assertion
      # regardless of interleaving.
      it "stays correct and crash-free while patterns churn from another thread" do
        # Keep a stable, always-present custom pattern so the reader loop has a
        # real entry to walk even between the writer's add/remove of "churn".
        DataRedactor.add_pattern(name: "stable", regex: "STABLE-[0-9]{4}")
        input = "email user@example.com card 4111 1111 1111 1111 id STABLE-7777"

        stop   = false
        errors = Queue.new

        writer = Thread.new do
          i = 0
          until stop
            DataRedactor.add_pattern(name: "churn#{i % 16}", regex: "ZZZ-[0-9]{4}")
            DataRedactor.remove_pattern("churn#{i % 16}")
            i += 1
          end
        rescue => e
          errors << e
        end

        readers = Array.new(8) do
          Thread.new do
            3_000.times do
              got = DataRedactor.redact(input)
              # Built-ins and the always-present "stable" custom must always fire,
              # regardless of how the churn interleaves.
              raise "email leaked: #{got.inspect}"  if got.include?("user@example.com")
              raise "card leaked: #{got.inspect}"   if got.include?("4111 1111 1111 1111")
              raise "stable leaked: #{got.inspect}" if got.include?("STABLE-7777")
              DataRedactor.scan(input)
            end
          rescue => e
            errors << e
          end
        end

        readers.each(&:join)
        stop = true
        writer.join

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
      end

      # The real race detector for the per-thread scan-state refactor + GVL
      # release. The input is large enough that redact releases the GVL around
      # the built-in v19 pass, so N threads run mm_scan TRULY in parallel — each
      # mutating its own per-thread scan_state_t (NFA scratch + lazy DFA cache).
      # If any of that state were still shared, concurrent scans would corrupt
      # each other's matches or crash on a concurrent realloc. A writer churns
      # the custom registry at the same time (generation-counter invalidation
      # under contention). Correctness gate: every thread's output must equal the
      # single-threaded reference for the same input.
      it "scans large inputs in parallel (GVL released) without corruption" do
        # > the C GVL_RELEASE_THRESHOLD (4 KB) so the GVL is actually released.
        line  = "log email user#{rand(1000)}@example.com ip 10.0.#{rand(255)}.#{rand(255)} " \
                "card 4111 1111 1111 1111 ssn 123-45-6789 iban DE89370400440532013000\n"
        input = line * 200  # ~16 KB, many matches per scan
        reference = DataRedactor.redact(input)
        expect(reference).not_to include("@example.com")

        stop   = false
        errors = Queue.new

        writer = Thread.new do
          i = 0
          until stop
            DataRedactor.add_pattern(name: "churn#{i % 8}", regex: "QQQ-[0-9]{5}")
            DataRedactor.remove_pattern("churn#{i % 8}")
            i += 1
          end
        rescue => e
          errors << e
        end

        readers = Array.new(8) do
          Thread.new do
            200.times do
              got = DataRedactor.redact(input)
              raise "output diverged under parallel GVL-free scan" unless got == reference
            end
          rescue => e
            errors << e
          end
        end

        readers.each(&:join)
        stop = true
        writer.join

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
      end

      # Exercises the pthread_key destructor that frees a thread's per-thread
      # scan state (NFA scratch + DFA cache) at thread exit. Each iteration
      # spawns a fresh thread that warms its own large per-thread cache, then
      # exits — firing the destructor. Many rounds must stay correct and
      # crash-free (a double-free or use-after-free in the destructor would
      # surface here). Memory reclamation itself is checked separately by an
      # RSS-stability bench, not asserted from Ruby.
      it "frees per-thread state across many short-lived threads" do
        input = ("log a@b.com ip 10.0.0.1 ssn 123-45-6789 " * 200) # > GVL threshold
        reference = DataRedactor.redact(input)
        errors = Queue.new

        50.times do
          t = Thread.new do
            5.times do
              raise "diverged" unless DataRedactor.redact(input) == reference
            end
          rescue => e
            errors << e
          end
          t.join # thread exits here -> destructor runs
        end

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
      end

      # Per-CALL re-entrancy of the selective-merge cursors (digit run + IBAN
      # union passes). Those cursors used to live in the per-thread scan cache;
      # they now live in a stack-allocated scan_ctx_t, one set per mm_scan call.
      # This test stresses exactly that: each thread redacts a batch of DISTINCT,
      # digit/IBAN-dense inputs (every input has many adjacent digit runs and
      # several IBANs, the cases the cursors arbitrate), each compared to its OWN
      # single-threaded reference. If a cursor leaked across calls or across the
      # GVL-released parallel scans, an interleaving would carry one input's
      # cursor into another and the output would diverge from its reference.
      it "keeps selective-merge cursors call-private under parallel digit/IBAN load" do
        # Each input is > the 4 KB GVL threshold and packed with the merge-pass
        # cases: spaced + unspaced card-length runs, SSNs, and multiple IBANs.
        inputs = Array.new(12) do |k|
          line = "rec#{k} card 4111 1111 1111 1111 acct 5500005555555559 " \
                 "ssn 123-45-6789 iban DE89370400440532013000 " \
                 "iban2 GB29NWBK60161331926819 nums 1234 5678 9012 3456\n"
          line * 120 # ~12 KB each
        end
        references = inputs.map { |i| DataRedactor.redact(i) }
        references.each { |r| expect(r).not_to include("4111 1111 1111 1111") }

        errors = Queue.new
        readers = Array.new(8) do
          Thread.new do
            150.times do
              k = rand(inputs.length)
              got = DataRedactor.redact(inputs[k])
              raise "merge-cursor leak: input #{k} diverged" unless got == references[k]
            end
          rescue => e
            errors << e
          end
        end
        readers.each(&:join)

        raise errors.pop until errors.empty?
        expect(errors).to be_empty
      end
    end
  end
end
