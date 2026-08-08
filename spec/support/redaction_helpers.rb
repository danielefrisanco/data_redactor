module RedactionHelpers
  def redacted?(input, sensitive)
    result = DataRedactor.redact(input)
    expect(result).to include("[REDACTED]"), "expected [REDACTED] in: #{result.inspect}"
    expect(result).not_to include(sensitive), "expected #{sensitive.inspect} to be gone"
  end
end
