# frozen_string_literal: true

require "rails/railtie"
require "data_redactor"
require "data_redactor/integrations/logger"
require "data_redactor/integrations/rails"

module DataRedactor
  # Rails wiring for data_redactor. Requiring this file installs a Railtie that
  # wraps the Rails logger's formatter and appends a `filter_parameters` entry,
  # so an app gets redaction without writing either integration by hand.
  #
  # Rails is never a runtime dependency of the gem: this file is only loaded
  # when the application requires it, following the same opt-in pattern as
  # every other integration.
  #
  # @example Enable everything with the defaults
  #   # Gemfile
  #   gem "data_redactor", require: "data_redactor/railtie"
  #
  # @example Tune it from an initializer
  #   # config/initializers/data_redactor.rb
  #   Rails.application.configure do
  #     config.data_redactor.only        = [:credentials, :financial]
  #     config.data_redactor.placeholder = :tagged
  #     config.data_redactor.logger      = false   # leave the logger alone
  #   end
  class Railtie < ::Rails::Railtie
    config.data_redactor = ActiveSupport::OrderedOptions.new
    config.data_redactor.logger = true
    config.data_redactor.filter_parameters = true
    config.data_redactor.placeholder = DataRedactor::PLACEHOLDER_DEFAULT

    # `only`/`except` are read with `[]` rather than the OrderedOptions reader:
    # `only` and `except` are Enumerable methods, so the reader would return a
    # Method-backed result instead of nil when the app never set them.
    #
    # @api private
    # @param config [ActiveSupport::OrderedOptions] the `config.data_redactor` options
    # @return [Hash] kwargs for {DataRedactor.redact}
    def self.redaction_options(config)
      {
        only: config[:only],
        except: config[:except],
        placeholder: config.placeholder
      }
    end

    initializer "data_redactor.filter_parameters" do |app|
      options = app.config.data_redactor
      next unless options.filter_parameters

      app.config.filter_parameters += [
        Integrations::Rails.filter(**Railtie.redaction_options(options))
      ]
    end

    # Runs after `initialize_logger` so we wrap whatever formatter the app
    # ended up with (Rails' own, lograge, a JSON formatter) rather than
    # replacing it.
    initializer "data_redactor.logger", after: :initialize_logger do |app|
      options = app.config.data_redactor
      next unless options.logger

      Railtie.wrap_logger(::Rails.logger, Railtie.redaction_options(options))
    end

    # A BroadcastLogger writes to each of its sinks directly, so a formatter set
    # on the broadcast itself never runs — each sink has to be wrapped instead.
    #
    # @api private
    # @param logger [#formatter, ActiveSupport::BroadcastLogger, nil] logger to wrap
    # @param options [Hash] kwargs forwarded to {Integrations::Logger}
    # @return [void]
    def self.wrap_logger(logger, options)
      return if logger.nil?

      if logger.respond_to?(:broadcasts)
        logger.broadcasts.each { |sink| wrap_logger(sink, options) }
        return
      end

      return unless logger.respond_to?(:formatter) && logger.respond_to?(:formatter=)

      inner = logger.formatter || ::Logger::Formatter.new
      return if inner.is_a?(Integrations::Logger)

      logger.formatter = Integrations::Logger.new(inner: inner, **options)
    end
  end
end
