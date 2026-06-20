# frozen_string_literal: true

require "data_redactor"

module DataRedactor
  # Opt-in refinements that add a `#redact` method to `String`, `Hash`, and
  # `Array` as sugar over {DataRedactor.redact} / {DataRedactor.redact_deep}.
  #
  # Refinements are lexically scoped: `#redact` exists only in files that
  # `using DataRedactor::Refinements`, so loading this file never pollutes the
  # core classes globally. Apps that don't opt in are unaffected, and there is
  # no collision risk with other libraries' `String#redact`.
  #
  # `DataRedactor.redact` remains the primary API; this is convenience only.
  #
  # @example
  #   require "data_redactor/refinements"
  #   using DataRedactor::Refinements
  #
  #   "email alice@example.com".redact            #=> "email [REDACTED]"
  #   { token: "AKIAIOSFODNN7EXAMPLE" }.redact    #=> { token: "[REDACTED]" }
  #   chat.ask(user_input.redact)                 # scrub before sending to an LLM
  module Refinements
    refine String do
      # Redact this String via {DataRedactor.redact}. Returns a new String; the
      # receiver is not mutated.
      #
      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      # @return [String] the redacted copy.
      # @example
      #   "ssn 123-45-6789".redact #=> "ssn [REDACTED]"
      def redact(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        DataRedactor.redact(self, only: only, except: except, placeholder: placeholder)
      end
    end

    refine Hash do
      # Deep-redact this Hash's String values via {DataRedactor.redact_deep}.
      # Returns a deep copy; the receiver is not mutated and keys are untouched.
      #
      # @param only forwarded to {DataRedactor.redact_deep}
      # @param except forwarded to {DataRedactor.redact_deep}
      # @param placeholder forwarded to {DataRedactor.redact_deep}
      # @return [Hash] a deep copy with String leaves redacted.
      # @example
      #   { email: "a@b.com" }.redact #=> { email: "[REDACTED]" }
      def redact(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        DataRedactor.redact_deep(self, only: only, except: except, placeholder: placeholder)
      end
    end

    refine Array do
      # Deep-redact this Array's String elements via {DataRedactor.redact_deep}.
      # Returns a deep copy; the receiver is not mutated.
      #
      # @param only forwarded to {DataRedactor.redact_deep}
      # @param except forwarded to {DataRedactor.redact_deep}
      # @param placeholder forwarded to {DataRedactor.redact_deep}
      # @return [Array] a deep copy with String leaves redacted.
      # @example
      #   ["a@b.com", 3].redact #=> ["[REDACTED]", 3]
      def redact(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        DataRedactor.redact_deep(self, only: only, except: except, placeholder: placeholder)
      end
    end
  end
end
