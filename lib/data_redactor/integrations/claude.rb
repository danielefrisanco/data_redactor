require "data_redactor"
require "data_redactor/integrations/llm_support"

module DataRedactor
  module Integrations
    # Adapter for Anthropic Claude (Messages API) payloads. Scrubs PII and
    # secrets from a request's `messages` (and top-level `system:` prompt)
    # before they leave the process, and from a response's `content` blocks
    # before they're logged or stored.
    #
    # Operates on plain Ruby Hashes/Arrays with either String or Symbol keys,
    # so it works with the `anthropic` gem, a raw HTTP client, or parsed JSON —
    # no runtime dependency on any SDK. Inputs are never mutated; a deep copy
    # is returned.
    #
    # @example Scrub a request before sending
    #   require "data_redactor/integrations/claude"
    #
    #   messages = [{ role: "user", content: "my email is alice@example.com" }]
    #   safe = DataRedactor::Integrations::Claude.redact_messages(messages)
    #   client.messages.create(model: "claude-opus-4-8", max_tokens: 1024,
    #                          messages: safe)
    #
    # @example Scrub a response before logging
    #   resp = client.messages.create(...)
    #   logger.info DataRedactor::Integrations::Claude.redact_response(resp)
    module Claude
      module_function

      # Redact a Claude `messages` array (and an optional top-level `system:`
      # String) before sending the request. Returns a deep copy; the input is
      # not mutated.
      #
      # Each message's `content` may be a String or an array of content blocks
      # (`{ type: "text", text: "..." }`); only the `text` field of `text`
      # blocks is redacted. Non-text blocks (e.g. `image`) pass through
      # untouched.
      #
      # @param messages [Array<Hash>, Hash] either a bare array of
      #   `{ role:, content: }` hashes, or a request Hash containing a
      #   `messages` key and an optional `system` key. Keys may be String or
      #   Symbol.
      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      # @return [Array<Hash>, Hash] a deep copy of the input with text leaves
      #   redacted; an Array if an Array was given, a Hash if a Hash was given.
      # @example
      #   Claude.redact_messages([{ role: "user", content: "ssn 123-45-6789" }])
      #   #=> [{ role: "user", content: "ssn [REDACTED]" }]
      def redact_messages(messages, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        redact = ->(s) { DataRedactor.redact(s, only: only, except: except, placeholder: placeholder) }

        if messages.is_a?(Hash)
          out = LLMSupport.deep_copy(messages)
          sys = LLMSupport.fetch(out, :system)
          LLMSupport.put(out, :system, redact.call(sys)) if sys.is_a?(String)
          list = LLMSupport.fetch(out, :messages)
          LLMSupport.put(out, :messages, redact_message_list(list, redact)) if list.is_a?(Array)
          out
        else
          redact_message_list(LLMSupport.deep_copy(messages), redact)
        end
      end

      # Redact a Claude Messages API response before logging or storing it.
      # Returns a deep copy; the input is not mutated.
      #
      # Walks the response's `content` array and redacts the `text` field of
      # each `text` block, leaving the rest of the response (id, role, usage,
      # non-text blocks) intact.
      #
      # @param response [Hash] a Claude response Hash with a `content` array of
      #   blocks. Keys may be String or Symbol.
      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      # @return [Hash] a deep copy of the response with text blocks redacted.
      # @example
      #   Claude.redact_response(
      #     "content" => [{ "type" => "text", "text" => "card 4111111111111111" }]
      #   )
      #   #=> {"content"=>[{"type"=>"text", "text"=>"card [REDACTED]"}]}
      def redact_response(response, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        redact = ->(s) { DataRedactor.redact(s, only: only, except: except, placeholder: placeholder) }
        out = LLMSupport.deep_copy(response)
        return out unless out.is_a?(Hash)

        content = LLMSupport.fetch(out, :content)
        LLMSupport.put(out, :content, LLMSupport.redact_text_blocks(content, redact)) if content.is_a?(Array)
        out
      end

      # @!visibility private
      # Redact each message's content (String or array of blocks) in place.
      # Expects an already-deep-copied list.
      def redact_message_list(messages, redact)
        messages.map do |msg|
          next msg unless msg.is_a?(Hash)

          content = LLMSupport.fetch(msg, :content)
          case content
          when String
            LLMSupport.put(msg, :content, redact.call(content))
          when Array
            LLMSupport.put(msg, :content, LLMSupport.redact_text_blocks(content, redact))
          end
          msg
        end
      end
    end
  end
end
