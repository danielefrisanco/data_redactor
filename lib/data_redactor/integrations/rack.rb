require "data_redactor"

module DataRedactor
  # Namespace for the optional framework adapters under
  # +lib/data_redactor/integrations/+ ({Logger}, +Rails+, {Rack}).
  #
  # Each adapter is soft-required — none load with +require "data_redactor"+;
  # +require+ only the one you need. They add no runtime gem dependencies and
  # all redaction is delegated to {DataRedactor.redact}.
  module Integrations
    # Rack middleware that scrubs sensitive data from selectable surfaces of
    # the response (and request headers, for downstream loggers to see scrubbed
    # values).
    #
    # @example Both surfaces (default)
    #   use DataRedactor::Integrations::Rack, scrub: [:body, :headers]
    #
    # @example Headers only — leave the response body untouched
    #   use DataRedactor::Integrations::Rack, scrub: [:headers]
    #
    # ### Surfaces
    #
    # - `:body` — wraps the response body so emitted bytes pass through
    #   {DataRedactor.redact} before reaching the client. Drops the
    #   `Content-Length` header (the redacted body may have a different
    #   byte length, and recomputing requires buffering).
    # - `:headers` — scrubs response headers in place. Sensitive request
    #   headers (`Authorization`, `Cookie`, `X-Api-Key`, etc.) are redacted in
    #   the env hash so any downstream middleware that logs them sees scrubbed
    #   values.
    class Rack
      # Surfaces scrubbed when +scrub:+ is not given to {#initialize}.
      # @return [Array<Symbol>]
      DEFAULT_SCRUB = [:body, :headers].freeze

      # Request-header env keys redacted in place when +:headers+ is scrubbed,
      # so downstream middleware that logs the env sees scrubbed values.
      # @return [Array<String>] Rack env keys (HTTP_-prefixed, upper-case).
      SENSITIVE_REQUEST_HEADERS = %w[
        HTTP_AUTHORIZATION
        HTTP_PROXY_AUTHORIZATION
        HTTP_COOKIE
        HTTP_X_API_KEY
        HTTP_X_AUTH_TOKEN
        HTTP_X_ACCESS_TOKEN
      ].freeze

      # Response headers whose values are redacted when +:headers+ is scrubbed.
      # Matched case-insensitively (Rack 2 capitalises, Rack 3 lower-cases).
      # @return [Array<String>]
      SENSITIVE_RESPONSE_HEADERS = %w[
        Set-Cookie
        Authorization
        X-Api-Key
        X-Auth-Token
        X-Access-Token
      ].freeze

      # @param app [#call] the Rack app
      # @param scrub [Array<Symbol>] which surfaces to redact. Subset of
      #   `[:body, :headers]`. Defaults to `[:body, :headers]`.
      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      def initialize(app, scrub: DEFAULT_SCRUB, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        @app = app
        @scrub = Array(scrub).map(&:to_sym)
        unknown = @scrub - [:body, :headers]
        unless unknown.empty?
          raise ArgumentError, "unknown scrub surface(s) #{unknown.inspect}; valid: [:body, :headers]"
        end
        @only = only
        @except = except
        @placeholder = placeholder
      end

      # Rack entry point. Scrubs the configured surfaces of the request and
      # response and returns the standard Rack response triple.
      #
      # @param env [Hash] the Rack environment.
      # @return [Array(Integer, Hash, #each)] the +[status, headers, body]+
      #   triple, with sensitive data redacted from the surfaces named in
      #   +scrub:+. When +:body+ is scrubbed, +Content-Length+ is dropped.
      def call(env)
        scrub_request_headers(env) if @scrub.include?(:headers)
        status, headers, body = @app.call(env)
        headers = scrub_response_headers(headers) if @scrub.include?(:headers)
        if @scrub.include?(:body)
          body, headers = wrap_body(body, headers)
        end
        [status, headers, body]
      end

      private

      def redact(s)
        DataRedactor.redact(s, only: @only, except: @except, placeholder: @placeholder)
      end

      def scrub_request_headers(env)
        SENSITIVE_REQUEST_HEADERS.each do |key|
          value = env[key]
          env[key] = redact(value) if value.is_a?(String) && !value.empty?
        end
      end

      def scrub_response_headers(headers)
        # Rack 3 uses lower-case header names; Rack 2 uses Capitalized.
        # Match case-insensitively against our known list.
        sensitive_lc = SENSITIVE_RESPONSE_HEADERS.map(&:downcase)
        headers.each_with_object({}) do |(key, value), out|
          if sensitive_lc.include?(key.to_s.downcase)
            out[key] = scrub_header_value(value)
          else
            out[key] = value
          end
        end
      end

      def scrub_header_value(value)
        case value
        when String then redact(value)
        when Array  then value.map { |v| v.is_a?(String) ? redact(v) : v }
        else value
        end
      end

      def wrap_body(body, headers)
        # Buffer the body, redact, return as a single-element array.
        # Stripping Content-Length because the redacted body may differ in
        # byte length; downstream servers will recompute or chunk-encode.
        buffered = +""
        body.each { |chunk| buffered << chunk.to_s }
        body.close if body.respond_to?(:close)

        scrubbed = redact(buffered)
        new_headers = headers.reject { |k, _| k.to_s.downcase == "content-length" }
        [[scrubbed], new_headers]
      end
    end
  end
end
