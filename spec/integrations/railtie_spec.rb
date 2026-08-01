require "tmpdir"
require "rails"
require "data_redactor/railtie"

RSpec.describe DataRedactor::Railtie do
  # Each example boots a throwaway Rails application so the real initializer
  # chain runs. Rails memoizes `Rails.application`, so every app needs its own
  # anonymous class and a reset of the global handles between examples.
  # `formatter:` stands in for `config.log_formatter`: assigning `config.logger`
  # makes Rails' `initialize_logger` skip the branch that would apply
  # `log_formatter`, so the spec applies it to the supplied logger directly.
  def boot(logger_io = StringIO.new, formatter: nil, &configure)
    logger = ::Logger.new(logger_io)
    logger.formatter = formatter if formatter

    # `root` points at a temp dir so booting these apps doesn't create a `log/`
    # directory in the repo.
    root = Dir.mktmpdir("data_redactor-railtie-spec")
    app_class = Class.new(::Rails::Application) do
      config.eager_load = false
      config.logger = logger
      config.active_support.to_time_preserves_timezone = :zone
      config.root = root
    end
    app_class.configure(&configure) if configure
    app_class.initialize!
    app_class.instance
  end

  # Rails keeps application state in class-level globals, and `set_autoload_paths`
  # freezes `ActiveSupport::Dependencies.autoload_paths` on the first `initialize!`
  # — a second boot in the same process would then `unshift` onto a frozen array.
  # Reset both the globals and those arrays around every example.
  around do |example|
    previous_app = ::Rails.application
    previous_logger = ::Rails.logger
    previous_autoload = ActiveSupport::Dependencies.autoload_paths
    previous_autoload_once = ActiveSupport::Dependencies.autoload_once_paths

    # `initialize_logger` is `Rails.logger ||= config.logger`, so a leftover
    # global from a previous example would win over this example's logger.
    ::Rails.logger = nil
    # The Railtie declares `config.data_redactor` once in its class body, so a
    # single OrderedOptions instance is shared by every app booted in this
    # process. Real apps boot once; specs must restore the defaults each time.
    shared = DataRedactor::Railtie.config.data_redactor
    shared.clear
    shared.logger = true
    shared.filter_parameters = true
    shared.placeholder = DataRedactor::PLACEHOLDER_DEFAULT
    ::Rails.app_class = nil
    ::Rails.application = nil
    ::Rails::Application.instance_variable_set(:@instance, nil)
    ActiveSupport::Dependencies.autoload_paths = previous_autoload.dup
    ActiveSupport::Dependencies.autoload_once_paths = previous_autoload_once.dup

    example.run
  ensure
    ::Rails.app_class = previous_app&.class
    ::Rails.application = previous_app
    ::Rails.logger = previous_logger
    ActiveSupport::Dependencies.autoload_paths = previous_autoload
    ActiveSupport::Dependencies.autoload_once_paths = previous_autoload_once
  end

  # `Rails.logger` is a BroadcastLogger on modern Rails; the redacting formatter
  # is installed on each sink, not on the broadcast itself.
  def formatter_for(logger)
    logger.respond_to?(:broadcasts) ? logger.broadcasts.first.formatter : logger.formatter
  end

  describe "logger wiring" do
    it "wraps the existing formatter in the redacting formatter" do
      io = StringIO.new
      boot(io)

      expect(formatter_for(::Rails.logger)).to be_a(DataRedactor::Integrations::Logger)

      ::Rails.logger.info("auth failed for alice@example.com")
      expect(io.string).to include("[REDACTED]")
      expect(io.string).not_to include("alice@example.com")
    end

    it "preserves the app's own formatter as the inner formatter" do
      custom = ->(_severity, _time, _progname, msg) { "CUSTOM #{msg}\n" }
      io = StringIO.new
      boot(io, formatter: custom)

      ::Rails.logger.info("token AKIAIOSFODNN7EXAMPLE here")
      expect(io.string).to start_with("CUSTOM ")
      expect(io.string).to include("[REDACTED]")
      expect(io.string).not_to include("AKIAIOSFODNN7EXAMPLE")
    end

    it "leaves the logger alone when disabled" do
      io = StringIO.new
      boot(io) { config.data_redactor.logger = false }

      expect(formatter_for(::Rails.logger)).not_to be_a(DataRedactor::Integrations::Logger)

      ::Rails.logger.info("auth failed for alice@example.com")
      expect(io.string).to include("alice@example.com")
    end

    it "does not double-wrap an already-wrapped formatter" do
      io = StringIO.new
      boot(io, formatter: DataRedactor::Integrations::Logger.new)

      formatter = formatter_for(::Rails.logger)
      expect(formatter).to be_a(DataRedactor::Integrations::Logger)
      inner = formatter.instance_variable_get(:@inner)
      expect(inner).not_to be_a(DataRedactor::Integrations::Logger)
    end
  end

  describe "filter_parameters wiring" do
    it "appends a redacting filter" do
      app = boot

      filter = app.config.filter_parameters.last
      expect(filter).to respond_to(:call)

      value = +"card 4111111111111111"
      filter.call("notes", value)
      expect(value).to include("[REDACTED]")
      expect(value).not_to include("4111111111111111")
    end

    it "preserves filters the app already configured" do
      app = boot { config.filter_parameters += [:password] }

      expect(app.config.filter_parameters).to include(:password)
      expect(app.config.filter_parameters.last).to respond_to(:call)
    end

    it "appends nothing when disabled" do
      app = boot { config.data_redactor.filter_parameters = false }

      expect(app.config.filter_parameters.none? { |f| f.respond_to?(:call) }).to be(true)
    end
  end

  describe "redaction options" do
    it "forwards only: to both surfaces" do
      io = StringIO.new
      app = boot(io) { config.data_redactor.only = :financial }

      ::Rails.logger.info("card 4111111111111111 and alice@example.com")
      expect(io.string).to include("[REDACTED]")
      expect(io.string).to include("alice@example.com")

      value = +"card 4111111111111111 and alice@example.com"
      app.config.filter_parameters.last.call("notes", value)
      expect(value).to include("alice@example.com")
      expect(value).not_to include("4111111111111111")
    end

    it "forwards except: to both surfaces" do
      io = StringIO.new
      app = boot(io) { config.data_redactor.except = ["email"] }

      ::Rails.logger.info("alice@example.com and card 4111111111111111")
      expect(io.string).to include("alice@example.com")
      expect(io.string).not_to include("4111111111111111")

      value = +"alice@example.com and card 4111111111111111"
      app.config.filter_parameters.last.call("notes", value)
      expect(value).to include("alice@example.com")
      expect(value).not_to include("4111111111111111")
    end

    it "forwards placeholder: to both surfaces" do
      io = StringIO.new
      app = boot(io) { config.data_redactor.placeholder = :tagged }

      ::Rails.logger.info("contact alice@example.com")
      expect(io.string).to include("[REDACTED:CONTACT]")

      value = +"contact alice@example.com"
      app.config.filter_parameters.last.call("notes", value)
      expect(value).to include("[REDACTED:CONTACT]")
    end
  end
end
