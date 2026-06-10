require "data_redactor"

module DataRedactor
  module Integrations
    # Shared helpers for the LLM payload adapters ({Claude}, {OpenAI}).
    #
    # Both adapters operate on plain Ruby Hashes/Arrays whose keys may be
    # String or Symbol, never mutate the caller's input, and redact only the
    # `text` field of text content blocks. This module holds that common,
    # non-trivial logic; the per-provider modules keep only their own
    # provider-specific shape walking.
    #
    # @!visibility private
    module LLMSupport
      module_function

      # Read a key from a Hash that may use String or Symbol keys.
      # @return the value under the Symbol or String form of `key`, or nil.
      def fetch(hash, key)
        hash.key?(key) ? hash[key] : hash[key.to_s]
      end

      # Write a value back under whichever key form (String/Symbol) the Hash
      # already uses for `key`, defaulting to the Symbol form.
      # @return [void]
      def put(hash, key, value)
        if hash.key?(key.to_s)
          hash[key.to_s] = value
        else
          hash[key] = value
        end
      end

      # Recursively copy a Hash/Array/String structure so the original is never
      # mutated. Non-container, non-String leaves are returned as-is.
      # @return a deep copy of `obj`.
      def deep_copy(obj)
        case obj
        when Hash   then obj.each_with_object({}) { |(k, v), o| o[k] = deep_copy(v) }
        when Array  then obj.map { |v| deep_copy(v) }
        when String then obj.dup
        else obj
        end
      end

      # Redact the `text` field of each `text` content block in `blocks`,
      # passing non-text blocks (e.g. images) through untouched. Mutates the
      # blocks in `blocks` (call on an already-copied structure).
      # @param blocks [Array] content blocks.
      # @param redact [#call] a String -> String redaction lambda.
      # @return [Array] the same `blocks` array, with text blocks redacted.
      def redact_text_blocks(blocks, redact)
        blocks.map do |block|
          next block unless block.is_a?(Hash)

          text = fetch(block, :text)
          put(block, :text, redact.call(text)) if text.is_a?(String)
          block
        end
      end
    end
  end
end
