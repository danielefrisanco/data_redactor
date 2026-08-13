require "data_redactor"

module DataRedactor
  module Integrations
    # Outbound redaction for the `ruby_llm` gem (crmne/ruby_llm), built on
    # RubyLLM's public request hook — nothing here monkeypatches RubyLLM.
    #
    # `chat.before_request { |payload| ... }` (ruby_llm 2.0+) hands a callback the
    # fully rendered request payload — after all RubyLLM formatting and
    # `with_provider_options` merging, immediately before it is posted — and
    # discards the callback's return value, so hooks edit the payload in place.
    # {hook} builds such a callback; {chat} and {attach!} register it for you.
    #
    # Because the payload is walked with {DataRedactor.redact_deep!}, this scrubs
    # **every String leaf** of the request: the user prompt, the system prompt,
    # the conversation history, tool definitions, and — the case per-call
    # redaction cannot reach — **tool results**. An agent that reads a file or
    # runs a command feeds that output back as a tool message, and it is inlined
    # as a String in the next request's payload; the user never typed it, so only
    # a request hook sees it before it leaves.
    #
    # Redaction is applied to the rendered payload and nothing is persisted, so
    # the conversation you keep is untouched: this scrubs the wire, per request.
    #
    # ## Limits, stated plainly
    # - **Per chat.** RubyLLM has no global callback registry, so a chat you did
    #   not build with {chat} or pass to {attach!} is *not* redacted.
    # - **Chat only.** Embeddings, moderation, image generation and transcription
    #   do not run request hooks.
    # - **Base64 attachments** (PDFs, images, audio inlined as base64) and
    #   **URL-referenced files** are not redacted — the bytes are encoded or
    #   remote, so patterns cannot see into them.
    # - Redacting tool results can break an agent that needs a value a tool
    #   returned. Scope with `only:`/`except:` when that matters.
    #
    # @example Build a redacted chat (nothing to remember later)
    #   require "ruby_llm"
    #   require "data_redactor/integrations/ruby_llm"
    #
    #   chat = DataRedactor::Integrations::RubyLLM.chat(model: "claude-opus-4-8")
    #   chat.ask("my card is 4111111111111111")  # sent as "my card is [REDACTED]"
    #
    # @example Redact a chat, agent, or acts_as_chat record you were handed
    #   DataRedactor::Integrations::RubyLLM.attach!(agent, only: [:financial])
    #
    # @example Redact an agent by handing it a chat that is already redacted
    #   chat = DataRedactor::Integrations::RubyLLM.chat(model: "claude-opus-4-8")
    #   agent = SupportAgent.new(chat: chat)   # the agent keeps that chat
    #
    #   # Every request of the agent's tool loop is redacted, tool results
    #   # included. Reaches nothing internal, so it is the tidiest spelling
    #   # for agents.
    #
    # @example Register the callback yourself
    #   chat.before_request(&DataRedactor::Integrations::RubyLLM.hook)
    module RubyLLM
      module_function

      # The `ruby_llm` line that exposes `Chat#before_request`. 1.x has no
      # request hook at all — redact per call with {DataRedactor.redact} there.
      SUPPORTED_VERSION = ">= 2.0.0.pre"

      # Payload keys left untouched by default.
      #
      # `model` is structural, not content: dated model ids carry an eight-digit
      # suffix (`claude-haiku-4-5-20251001`), which the national-ID patterns
      # match, and a redacted model id is rejected by the provider. Nothing else
      # is skipped by default — an unlisted key is always redacted, so a field we
      # have never seen cannot leak silently.
      DEFAULT_SKIP_KEYS = [:model].freeze

      # Build a chat with redaction already attached.
      #
      # A drop-in for `RubyLLM.chat`: every argument is forwarded to it
      # untouched, and the returned chat is the real thing, so the fluent API
      # keeps working (`.with_temperature(0.2).ask(...)`).
      #
      # @param only [Symbol, String, Array, nil] forwarded to {hook}.
      # @param except [Symbol, String, Array, nil] forwarded to {hook}.
      # @param placeholder [String, Symbol] forwarded to {hook}.
      # @param skip_keys [Symbol, String, Array] forwarded to {hook}.
      # @param kwargs [Hash] forwarded to `RubyLLM.chat` (`model:`, `provider:`,
      #   `protocol:`, `assume_model_exists:`, `context:`).
      # @return [RubyLLM::Chat] a chat whose every request is redacted.
      #
      # @example
      #   DataRedactor::Integrations::RubyLLM.chat(model: "gpt-5.4", only: [:financial])
      def chat(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT,
               skip_keys: DEFAULT_SKIP_KEYS, **kwargs, &block)
        attach!(::RubyLLM.chat(**kwargs, &block),
                only: only, except: except, placeholder: placeholder, skip_keys: skip_keys)
      end

      # Register {hook} on a chat you did not build.
      #
      # Accepts whatever holds the chat, so callers need not know which object
      # carries the hook: a `RubyLLM::Chat`, a `RubyLLM::Agent` (2.0 does not
      # delegate `before_request`, so the wrapped `#chat` is used), or an
      # `acts_as_chat` record (its `#to_llm` chat is memoized, so one call
      # covers the record).
      #
      # @param target [Object] a chat, agent, or `acts_as_chat` record.
      # @param only [Symbol, String, Array, nil] forwarded to {hook}.
      # @param except [Symbol, String, Array, nil] forwarded to {hook}.
      # @param placeholder [String, Symbol] forwarded to {hook}.
      # @param skip_keys [Symbol, String, Array] forwarded to {hook}.
      # @return [Object] +target+, so calls chain.
      # @raise [ArgumentError] if no chat with a `before_request` hook can be
      #   reached from +target+ — a `ruby_llm` older than {SUPPORTED_VERSION}.
      #
      # @example
      #   DataRedactor::Integrations::RubyLLM.attach!(chat).ask("...")
      def attach!(target, only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT,
                  skip_keys: DEFAULT_SKIP_KEYS)
        resolve(target).before_request(
          &hook(only: only, except: except, placeholder: placeholder, skip_keys: skip_keys)
        )
        target
      end

      # Build the `before_request` callback.
      #
      # It redacts the payload **in place**, which is what RubyLLM's contract
      # requires: hooks mutate what they are given and their return value is
      # discarded.
      #
      # @param only [Symbol, String, Array, nil] forwarded to {DataRedactor.redact_deep!}.
      # @param except [Symbol, String, Array, nil] forwarded to {DataRedactor.redact_deep!}.
      # @param placeholder [String, Symbol] forwarded to {DataRedactor.redact_deep!}.
      # @param skip_keys [Symbol, String, Array] payload keys to leave verbatim.
      #   Defaults to {DEFAULT_SKIP_KEYS}; pass more to protect provider fields
      #   your app relies on (`skip_keys: [:model, :metadata]`).
      # @return [Proc] a one-argument callback for `chat.before_request`.
      #
      # @example
      #   chat.before_request(&DataRedactor::Integrations::RubyLLM.hook)
      def hook(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT,
               skip_keys: DEFAULT_SKIP_KEYS)
        lambda do |payload|
          DataRedactor.redact_deep!(payload, only: only, except: except,
                                             placeholder: placeholder, skip_keys: skip_keys)
        end
      end

      # @deprecated Transparent app-wide mode is gone. It prepended
      #   `RubyLLM::Protocol#render`; ruby_llm 2.0 exposes a public request hook,
      #   so redaction no longer patches RubyLLM. Use {chat} or {attach!}. This
      #   method exists only to say so and will be deleted in the next minor.
      # @raise [RuntimeError] always.
      def install!(*_args, **_kwargs)
        raise "DataRedactor::Integrations::RubyLLM.install! has been removed: ruby_llm 2.0 exposes a " \
              "public request hook, so redaction no longer patches RubyLLM. Build chats with " \
              "DataRedactor::Integrations::RubyLLM.chat(...), or attach to an existing chat, agent, " \
              "or record with DataRedactor::Integrations::RubyLLM.attach!(target)."
      end

      # @!visibility private
      # Finds the object carrying `before_request`: a chat directly, an agent's
      # wrapped chat, or a record's `to_llm` chat (an agent in Rails mode wraps
      # the record, hence two hops).
      def resolve(target)
        candidate = target
        candidate = candidate.chat if !candidate.respond_to?(:before_request) && candidate.respond_to?(:chat)
        candidate = candidate.to_llm if !candidate.respond_to?(:before_request) && candidate.respond_to?(:to_llm)
        return candidate if candidate.respond_to?(:before_request)

        raise ArgumentError, "data_redactor ruby_llm integration: no #before_request hook reachable from " \
                             "#{target.class}. It needs ruby_llm #{SUPPORTED_VERSION}; on 1.x, redact per " \
                             "call with DataRedactor.redact before chat.ask."
      end
    end
  end
end
