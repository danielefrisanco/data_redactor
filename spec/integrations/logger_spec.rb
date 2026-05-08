require "stringio"
require "logger"
require "data_redactor/integrations/logger"

RSpec.describe DataRedactor::Integrations::Logger do
  let(:io) { StringIO.new }
  let(:logger) { ::Logger.new(io) }

  it "redacts sensitive content from string log messages" do
    logger.formatter = described_class.new
    logger.info("user alice@example.com signed in")
    expect(io.string).to include("[REDACTED]")
    expect(io.string).not_to include("alice@example.com")
  end

  it "redacts emitted exception messages without rebuilding the exception" do
    logger.formatter = described_class.new
    begin
      raise StandardError, "auth failed for token AKIAIOSFODNN7EXAMPLE"
    rescue StandardError => e
      logger.error(e)
    end
    expect(io.string).to include("[REDACTED]")
    expect(io.string).not_to include("AKIAIOSFODNN7EXAMPLE")
  end

  it "redacts inspect output of arbitrary objects (Hash)" do
    logger.formatter = described_class.new
    logger.info(user: "alice@example.com", id: 42)
    expect(io.string).to include("[REDACTED]")
    expect(io.string).not_to include("alice@example.com")
  end

  it "wraps a custom inner formatter" do
    inner = ->(severity, _time, _progname, msg) { "[#{severity}] #{msg}\n" }
    logger.formatter = described_class.new(inner: inner)
    logger.warn("api key=AKIAIOSFODNN7EXAMPLE")
    expect(io.string).to start_with("[WARN]")
    expect(io.string).to include("[REDACTED]")
  end

  it "honours only:/except: filters" do
    logger.formatter = described_class.new(only: [:credentials])
    logger.info("user alice@example.com with key AKIAIOSFODNN7EXAMPLE")
    # email is :contact, not :credentials → preserved
    expect(io.string).to include("alice@example.com")
    expect(io.string).not_to include("AKIAIOSFODNN7EXAMPLE")
  end

  it "honours custom placeholder" do
    logger.formatter = described_class.new(placeholder: "***")
    logger.info("user alice@example.com signed in")
    expect(io.string).to include("***")
    expect(io.string).not_to include("[REDACTED]")
  end
end
