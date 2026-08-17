require "data_redactor"

module DataRedactor
  module Integrations
    # Transparent outbound redaction for the `ruby_llm` gem (crmne/ruby_llm).
    #
    # Calling {install!} prepends a small module onto `RubyLLM::Protocol` that
    # deep-redacts the **rendered request payload** before it is posted to any
    # provider. `Protocol#render` is the single point where every provider
    # (Anthropic, OpenAI/chat_completions, Gemini, Bedrock/Converse, Responses)
    # has assembled its final request Hash, so one hook covers them all without
    # knowing any provider-specific shape.
    #
    # Because the payload is walked with {DataRedactor.redact_deep}, this scrubs
    # **every String leaf** in the request: the user prompt, the system prompt,
    # tool definitions, and — crucially — any file contents or shell-command
    # output that an agent fed back in as a tool result, since those are already
    # inlined as strings in `messages` by the time `render` runs.
    #
    # **Requires `ruby_llm` 2.0 or newer** ({SUPPORTED_VERSION}): the protocol
    # layer this hooks does not exist in the released 1.x line, which assembles
    # its payload inside `Provider#complete`. On 1.x, redact per call with
    # {DataRedactor.redact} before `chat.ask` instead.
    #
    # This is a monkeypatch (a `prepend` onto a private internal class). It is
    # opt-in and pinned: {install!} raises unless a supported `ruby_llm` version
    # is loaded and `RubyLLM::Protocol#render` still exists, so an upstream
    # refactor fails loudly at install time rather than silently leaking data.
    # Prefer this only when you need redaction to be *transparent*; otherwise
    # redact per call with {DataRedactor.redact} before `chat.ask`.
    #
    # ## What is NOT redacted
    # - **Base64 attachments** (PDFs, images, audio sent inline as base64) — the
    #   sensitive bytes are encoded, so patterns cannot see into them.
    # - **URL-referenced files/images** — the content lives on a remote server
    #   and never enters the payload.
    #
    # @example Make every ruby_llm request redacted, app-wide
    #   require "data_redactor/integrations/ruby_llm"
    #   DataRedactor::Integrations::RubyLLM.install!
    #
    #   chat = RubyLLM.chat(model: "claude-opus-4-8")
    #   chat.ask("my card is 4111111111111111")  # sent as "my card is [REDACTED]"
    #
    # @example Scope the redaction with the usual filters
    #   DataRedactor::Integrations::RubyLLM.install!(only: [:financial, :contact])
    module RubyLLM
      module_function

      # ruby_llm versions whose `Protocol#render` chokepoint this integration
      # has been verified against. Bump (and re-verify) on each ruby_llm release.
      #
      # The per-provider protocol layer landed in the 2.0 line: released 1.x has
      # no `RubyLLM::Protocol` at all (1.x assembles the payload in
      # `Provider#complete`), so there is nothing here to hook on those versions.
      SUPPORTED_VERSION = ">= 2.0.0.pre"

      # Prepend the redaction patch onto `RubyLLM::Protocol`. Idempotent: a
      # second call with the patch already installed is a no-op (the filter
      # options from the first successful install are kept).
      #
      # The `only:`/`except:`/`placeholder:` filters are captured here and
      # applied to every subsequent request.
      #
      # @param only [Symbol, String, Array, nil] forwarded to {DataRedactor.redact_deep}.
      # @param except [Symbol, String, Array, nil] forwarded to {DataRedactor.redact_deep}.
      # @param placeholder [String, Symbol] forwarded to {DataRedactor.redact_deep}.
      # @return [void]
      # @raise [RuntimeError] if `ruby_llm` is not loaded, the loaded version is
      #   outside {SUPPORTED_VERSION}, or `RubyLLM::Protocol#render` is missing
      #   (i.e. an upstream refactor moved or removed the chokepoint).
      def install!(only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT)
        ensure_compatible!

        @options = { only: only, except: except, placeholder: placeholder }
        return if installed?

        ::RubyLLM::Protocol.prepend(PayloadPatch)
      end

      # @return [Boolean] whether the redaction patch is currently on
      #   `RubyLLM::Protocol`.
      def installed?
        defined?(::RubyLLM::Protocol) &&
          ::RubyLLM::Protocol.ancestors.include?(PayloadPatch)
      end

      # @!visibility private
      # @return [Hash] the filter options captured at {install!}.
      def options
        @options ||= { only: nil, except: nil, placeholder: DataRedactor::PLACEHOLDER_DEFAULT }
      end

      # @!visibility private
      def ensure_compatible!
        unless defined?(::RubyLLM::VERSION)
          raise "data_redactor ruby_llm integration: require \"ruby_llm\" before calling install!"
        end

        unless Gem::Requirement.new(SUPPORTED_VERSION).satisfied_by?(Gem::Version.new(::RubyLLM::VERSION))
          raise "data_redactor ruby_llm integration supports ruby_llm #{SUPPORTED_VERSION}, " \
                "got #{::RubyLLM::VERSION}. On ruby_llm 1.x there is no request chokepoint to " \
                "hook — redact per call with DataRedactor.redact before chat.ask."
        end

        unless defined?(::RubyLLM::Protocol)
          raise "data_redactor ruby_llm integration: RubyLLM::Protocol not found — " \
                "the upstream request-rendering API changed. This integration needs an update."
        end

        unless ::RubyLLM::Protocol.method_defined?(:render) || ::RubyLLM::Protocol.private_method_defined?(:render)
          raise "data_redactor ruby_llm integration: RubyLLM::Protocol#render not found — " \
                "the upstream request-rendering API changed. This integration needs an update."
        end
      end

      # Prepended onto `RubyLLM::Protocol`. `Protocol#complete` calls
      # `payload = render(...)` and then posts that payload, so redacting the
      # return value of `render` redacts the request without touching anything
      # else in the send path.
      module PayloadPatch
        def render(*args, **kwargs)
          payload = super
          opts = DataRedactor::Integrations::RubyLLM.options
          DataRedactor.redact_deep(
            payload,
            only: opts[:only],
            except: opts[:except],
            placeholder: opts[:placeholder]
          )
        end
      end
    end
  end
end
