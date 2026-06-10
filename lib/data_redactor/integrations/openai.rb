require "data_redactor"
require "data_redactor/integrations/llm_support"

module DataRedactor
  module Integrations
    # Adapter for OpenAI Chat Completions payloads. Scrubs PII and secrets from
    # a request's `messages` before they leave the process, and from a
    # response's `choices[].message.content` before they're logged or stored.
    #
    # Operates on plain Ruby Hashes/Arrays with either String or Symbol keys,
    # so it works with the `openai` gem, a raw HTTP client, or parsed JSON — no
    # runtime dependency on any SDK. Inputs are never mutated; a deep copy is
    # returned.
    #
    # @example Scrub a request before sending
    #   require "data_redactor/integrations/openai"
    #
    #   messages = [{ role: "user", content: "my email is alice@example.com" }]
    #   safe = DataRedactor::Integrations::OpenAI.redact_messages(messages)
    #   client.chat(parameters: { model: "gpt-4o", messages: safe })
    #
    # @example Scrub a response before logging
    #   resp = client.chat(parameters: { ... })
    #   logger.info DataRedactor::Integrations::OpenAI.redact_response(resp)
    module OpenAI
      module_function

      # Redact an OpenAI `messages` array before sending the request. Returns a
      # deep copy; the input is not mutated.
      #
      # Each message's `content` may be a String or an array of parts
      # (`{ type: "text", text: "..." }`); only the `text` field of `text`
      # parts is redacted. Non-text parts (e.g. `image_url`) pass through
      # untouched. A `{ role: "system", content: ... }` entry is redacted like
      # any other message (OpenAI carries the system prompt in the array).
      #
      # @param messages [Array<Hash>, Hash] either a bare array of
      #   `{ role:, content: }` hashes, or a request Hash containing a
      #   `messages` key. Keys may be String or Symbol.
      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      # @return [Array<Hash>, Hash] a deep copy of the input with text leaves
      #   redacted; an Array if an Array was given, a Hash if a Hash was given.
      # @example
      #   OpenAI.redact_messages([{ role: "user", content: "ssn 123-45-6789" }])
      #   #=> [{ role: "user", content: "ssn [REDACTED]" }]
      def redact_messages(messages, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        redact = ->(s) { DataRedactor.redact(s, only: only, except: except, placeholder: placeholder) }

        if messages.is_a?(Hash)
          out = LLMSupport.deep_copy(messages)
          list = LLMSupport.fetch(out, :messages)
          LLMSupport.put(out, :messages, redact_message_list(list, redact)) if list.is_a?(Array)
          out
        else
          redact_message_list(LLMSupport.deep_copy(messages), redact)
        end
      end

      # Redact an OpenAI Chat Completions response before logging or storing it.
      # Returns a deep copy; the input is not mutated.
      #
      # Walks `choices[].message.content` and redacts each (String content),
      # leaving the rest of the response (id, usage, finish_reason) intact.
      #
      # @param response [Hash] a response Hash with a `choices` array, each
      #   choice carrying a `message` Hash with a `content` String. Keys may be
      #   String or Symbol.
      # @param only forwarded to {DataRedactor.redact}
      # @param except forwarded to {DataRedactor.redact}
      # @param placeholder forwarded to {DataRedactor.redact}
      # @return [Hash] a deep copy of the response with message content redacted.
      # @example
      #   OpenAI.redact_response(
      #     "choices" => [{ "message" => { "content" => "card 4111111111111111" } }]
      #   )
      #   #=> {"choices"=>[{"message"=>{"content"=>"card [REDACTED]"}}]}
      def redact_response(response, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        redact = ->(s) { DataRedactor.redact(s, only: only, except: except, placeholder: placeholder) }
        out = LLMSupport.deep_copy(response)
        return out unless out.is_a?(Hash)

        choices = LLMSupport.fetch(out, :choices)
        return out unless choices.is_a?(Array)

        choices.each do |choice|
          next unless choice.is_a?(Hash)

          message = LLMSupport.fetch(choice, :message)
          next unless message.is_a?(Hash)

          content = LLMSupport.fetch(message, :content)
          LLMSupport.put(message, :content, redact.call(content)) if content.is_a?(String)
        end
        out
      end

      # @!visibility private
      # Redact each message's content (String or array of parts) in place.
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
