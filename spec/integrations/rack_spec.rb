require "data_redactor/integrations/rack"

RSpec.describe DataRedactor::Integrations::Rack do
  let(:body_text) { "leaked: AKIAIOSFODNN7EXAMPLE and alice@example.com" }
  let(:downstream) do
    body = body_text
    ->(_env) { [200, { "Content-Type" => "text/plain", "Content-Length" => body.bytesize.to_s }, [body]] }
  end

  def call(app, env = {})
    app.call(env)
  end

  describe "argument validation" do
    it "raises on unknown scrub surface" do
      expect {
        described_class.new(downstream, scrub: [:bogus])
      }.to raise_error(ArgumentError, /unknown scrub surface/)
    end

    it "accepts symbols and strings interchangeably" do
      expect {
        described_class.new(downstream, scrub: ["body", :headers])
      }.not_to raise_error
    end
  end

  describe "scrub: [:body]" do
    let(:app) { described_class.new(downstream, scrub: [:body]) }

    it "redacts sensitive content from the response body" do
      _status, _headers, body = call(app)
      bytes = +""
      body.each { |c| bytes << c }
      expect(bytes).to include("[REDACTED]")
      expect(bytes).not_to include("AKIAIOSFODNN7EXAMPLE")
      expect(bytes).not_to include("alice@example.com")
    end

    it "drops the Content-Length header (length may have changed)" do
      _status, headers, _body = call(app)
      expect(headers.keys.map { |k| k.to_s.downcase }).not_to include("content-length")
    end
  end

  describe "scrub: [:headers]" do
    let(:downstream_with_secret_header) do
      ->(_env) {
        [200,
         { "Content-Type" => "text/plain",
           "Set-Cookie" => "session=alice@example.com; HttpOnly",
           "X-Request-Id" => "req-abc" },
         ["ok"]]
      }
    end
    let(:app) { described_class.new(downstream_with_secret_header, scrub: [:headers]) }

    it "redacts sensitive response headers" do
      _status, headers, _body = call(app)
      expect(headers["Set-Cookie"]).to include("[REDACTED]")
      expect(headers["Set-Cookie"]).not_to include("alice@example.com")
    end

    it "leaves non-sensitive headers untouched" do
      _status, headers, _body = call(app)
      expect(headers["X-Request-Id"]).to eq("req-abc")
      expect(headers["Content-Type"]).to eq("text/plain")
    end

    it "redacts sensitive request headers in the env hash" do
      env = { "HTTP_AUTHORIZATION" => "Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
      app.call(env)
      expect(env["HTTP_AUTHORIZATION"]).to include("[REDACTED]")
      expect(env["HTTP_AUTHORIZATION"]).not_to include("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    end

    it "does not touch the response body when only :headers is selected" do
      _status, _headers, body = call(app)
      bytes = +""
      body.each { |c| bytes << c }
      expect(bytes).to eq("ok")
    end
  end

  describe "scrub: [:body, :headers] (default)" do
    let(:app) { described_class.new(downstream) }

    it "scrubs both surfaces by default" do
      _status, headers, body = call(app)
      expect(headers.keys.map { |k| k.to_s.downcase }).not_to include("content-length")
      bytes = +""
      body.each { |c| bytes << c }
      expect(bytes).to include("[REDACTED]")
    end
  end

  describe "filtering options forwarded to redact" do
    it "honours only:/except:" do
      app = described_class.new(downstream, scrub: [:body], only: [:credentials])
      _status, _headers, body = call(app)
      bytes = +""
      body.each { |c| bytes << c }
      expect(bytes).to include("alice@example.com")  # :contact not in only:
      expect(bytes).not_to include("AKIAIOSFODNN7EXAMPLE")
    end

    it "honours placeholder:" do
      app = described_class.new(downstream, scrub: [:body], placeholder: "***")
      _status, _headers, body = call(app)
      bytes = +""
      body.each { |c| bytes << c }
      expect(bytes).to include("***")
    end
  end

  describe "body lifecycle" do
    it "calls close on the upstream body if it responds to it" do
      closed = false
      closeable = Object.new
      closeable.define_singleton_method(:each) { |&blk| blk.call("alice@example.com") }
      closeable.define_singleton_method(:close) { closed = true }
      upstream = ->(_env) { [200, {}, closeable] }
      app = described_class.new(upstream, scrub: [:body])
      app.call({})
      expect(closed).to be true
    end
  end
end
