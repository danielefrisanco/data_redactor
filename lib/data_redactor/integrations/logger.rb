# Ruby 4.0 demoted logger from a default gem to a bundled one: it still ships
# with Ruby, but under Bundler it only resolves when something declares it, and
# this gem declares no runtime dependencies. Swallowing the LoadError costs
# nothing — anyone assigning this formatter holds a ::Logger instance already,
# so their own require has defined the constant this file needs.
begin
  require "logger"
rescue LoadError
  nil
end

require "data_redactor"

module DataRedactor
  module Integrations
    # Logger formatter that runs every log message through {DataRedactor.redact}
    # before delegating to an inner formatter.
    #
    # @example Drop-in replacement for Ruby's default formatter
    #   logger = Logger.new($stdout)
    #   logger.formatter = DataRedactor::Integrations::Logger.new
    #   logger.info("Auth failed for user alice@example.com")
    #   # => "I, [...] -- : Auth failed for user [REDACTED]"
    #
    # @example Wrapping an existing formatter (e.g. Rails JSON logger)
    #   logger.formatter = DataRedactor::Integrations::Logger.new(
    #     inner: Rails.logger.formatter,
    #     only:  [:credentials, :contact]
    #   )
    class Logger
      # @param inner [#call, nil] formatter to wrap. Defaults to {::Logger::Formatter}.
      # @param only [Symbol, String, Array, nil] forwarded to {DataRedactor.redact}.
      # @param except [Symbol, String, Array, nil] forwarded to {DataRedactor.redact}.
      # @param placeholder forwarded to {DataRedactor.redact}.
      def initialize(inner: ::Logger::Formatter.new, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        @inner = inner
        @only = only
        @except = except
        @placeholder = placeholder
      end

      # Formatter contract — called by Logger for every emitted line.
      # Lets the inner formatter render whatever it likes (string, exception,
      # arbitrary object) and scrubs the resulting line in one pass. Keeps the
      # exception cause chain intact so downstream formatters still see it.
      def call(severity, time, progname, msg)
        line = @inner.call(severity, time, progname, msg)
        DataRedactor.redact(line.to_s, only: @only, except: @except, placeholder: @placeholder)
      end
    end
  end
end
