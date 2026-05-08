require "data_redactor"

module DataRedactor
  module Integrations
    # Rails `config.filter_parameters` adapter. Returns a `Proc` that Rails
    # invokes with `(key, value)` for every leaf in the params tree; we redact
    # the value in place when it is a String.
    #
    # @example
    #   # config/initializers/filter_parameter_logging.rb
    #   require "data_redactor/integrations/rails"
    #   Rails.application.config.filter_parameters += [
    #     DataRedactor::Integrations::Rails.filter
    #   ]
    #
    # @example Restricting to specific tags
    #   Rails.application.config.filter_parameters += [
    #     DataRedactor::Integrations::Rails.filter(only: [:credentials, :financial])
    #   ]
    module Rails
      module_function

      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      # @return [Proc] a `(key, value)` proc compatible with `config.filter_parameters`
      def filter(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        lambda do |_key, value|
          next unless value.is_a?(String)
          # Rails' Parameter Filter mutates the value in place. We can't
          # reassign `value` here, so use String#replace.
          redacted = DataRedactor.redact(value, only: only, except: except, placeholder: placeholder)
          value.replace(redacted) if redacted != value
        end
      end
    end
  end
end
