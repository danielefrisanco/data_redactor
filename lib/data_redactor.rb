require "set"
require_relative "data_redactor/version"
require_relative "data_redactor/data_redactor" # loads the compiled .so

# High-performance regex-based redactor for sensitive data.
#
# DataRedactor scans text for sensitive patterns (API keys, IBANs, national
# IDs, emails, phone numbers, etc.) and replaces matches with a configurable
# placeholder. The matching is done by a C extension backed by POSIX
# +regex.h+, so it is fast enough to run inline on large payloads.
#
# @example Basic redaction
#   DataRedactor.redact("key is AKIAIOSFODNN7EXAMPLE")
#   # => "key is [REDACTED]"
#
# @example Filter by tag or pattern name
#   DataRedactor.redact(text, only: :credentials)
#   DataRedactor.redact(text, except: [:contact, :network])
#   DataRedactor.redact(text, only: :contact, except: ["email"])
#   DataRedactor.redact(text, only: ["aws_access_key_id"])
#
# @example Custom placeholder
#   DataRedactor.redact(text, placeholder: "***")
#   DataRedactor.redact(text, placeholder: :tagged) # => "[REDACTED:CONTACT]"
#   DataRedactor.redact(text, placeholder: :hash)   # => "[CONTACT_a3f9]"
#
# @example Audit / dry-run
#   DataRedactor.scan(text)
#   # => { redacted: "...", matches: [{tag:, name:, value:, start:, length:}, ...] }
#
# @example Custom pattern
#   DataRedactor.add_pattern(name: "employee_id", regex: "EMP-[0-9]{6}")
module DataRedactor
  # Map of tag symbol to the integer bit used by the C layer.
  #
  # The keys of this hash are the canonical list of supported tags; pass any
  # of them to {redact} or {scan} via +only:+ / +except:+.
  #
  # @return [Hash{Symbol => Integer}] frozen tag-to-bit map
  TAGS = {
    credentials: TAG_CREDENTIALS,
    financial:   TAG_FINANCIAL,
    tax_id:      TAG_TAX_ID,
    national_id: TAG_NATIONAL_ID,
    contact:     TAG_CONTACT,
    network:     TAG_NETWORK,
    travel:      TAG_TRAVEL,
    other:       TAG_OTHER,
    custom:      TAG_CUSTOM
  }.freeze

  # Raised when a tag symbol passed to +only:+ / +except:+ / +tag:+ is not in {TAGS}.
  class UnknownTagError     < ArgumentError; end

  # Raised when a String passed via +only:+ / +except:+ does not match any
  # registered pattern name. See {pattern_names}.
  class UnknownPatternError < ArgumentError; end

  # Raised by {add_pattern} when the supplied regex is not valid POSIX ERE,
  # uses Ruby-only syntax (+\d+, +\s+, lookaround, non-greedy, etc.), or
  # contains capture groups while +boundary: true+ is requested.
  class InvalidPatternError < ArgumentError; end

  # @api private
  # Capture groups break boundary-wrapper group index assumptions ([1],[2],[3] shift).
  CAPTURE_GROUP_RE = /(?<!\\)\((?!\?:)/.freeze

  # @api private
  # Ruby regex syntax that has no POSIX ERE equivalent.
  RUBY_ONLY_SYNTAX_RE = /\\[dDwWsShHbB]|\(\?[<!=]|\(\?<[a-zA-Z]|\(\?[imx]|[*+?]\?/.freeze

  # Default placeholder used when +placeholder:+ is not given to {redact}.
  PLACEHOLDER_DEFAULT = "[REDACTED]"

  module_function

  # List of supported tag symbols.
  #
  # @return [Array<Symbol>] every key from {TAGS}
  def tags
    TAGS.keys
  end

  # List of every pattern name the redactor knows about.
  #
  # Includes the {BUILTIN_PATTERN_NAMES} plus any names registered via
  # {add_pattern}. Useful for discovering what String values +only:+ /
  # +except:+ accept, and for filtering / debugging.
  #
  # @return [Array<String>] built-in names first (in execution order),
  #   then custom names in registration order.
  def pattern_names
    BUILTIN_PATTERN_NAMES + _custom_patterns.map { |h| h[:name] }
  end

  # Redact every match of the configured patterns in +text+.
  #
  # +only:+ and +except:+ both accept a single value or an Array, mixing:
  # - **Symbols** — tag names from {TAGS} (e.g. +:contact+, +:credentials+).
  # - **Strings** — specific pattern names from {pattern_names} (e.g. +"email"+).
  #
  # They can be combined: +only: :contact, except: ["email"]+ means
  # "redact every contact pattern except email." Symbols give you tag-level
  # control; Strings give you per-pattern precision.
  #
  # **Precedence:** a pattern is redacted iff
  # +(only is nil OR pattern matches only:)+ AND +(pattern does not match except:)+.
  # +except:+ always wins over +only:+ when they overlap — e.g.
  # +only: :contact, except: :contact+ produces an empty redaction (no-op),
  # and +only: ["email"], except: ["email"]+ likewise skips email entirely.
  #
  # @param text [String] input string. Returned unchanged if no patterns match.
  # @param only [Symbol, String, Array, nil] include only the given tag(s)
  #   and/or pattern name(s).
  # @param except [Symbol, String, Array, nil] exclude the given tag(s)
  #   and/or pattern name(s). May be combined with +only:+.
  # @param placeholder [String, :tagged, :hash] replacement strategy.
  #   A String is used verbatim. +:tagged+ produces +[REDACTED:TAGNAME]+.
  #   +:hash+ produces a deterministic +[TAGNAME_xxxx]+ token (4-hex djb2)
  #   so the same input value always maps to the same token.
  # @return [String] a new string with every match replaced.
  # @raise [ArgumentError] if +placeholder:+ is not a String/:tagged/:hash.
  # @raise [UnknownTagError] if any Symbol in +only:+/+except:+ is not in {TAGS}.
  # @raise [UnknownPatternError] if any String in +only:+/+except:+ is not in {pattern_names}.
  #
  # @example
  #   DataRedactor.redact("token sk_live_abc123", only: :credentials)
  #   DataRedactor.redact(text, only: [:contact, "aws_access_key_id"])
  #   DataRedactor.redact(text, only: :contact, except: ["email"])
  def redact(text, only: nil, except: nil, placeholder: PLACEHOLDER_DEFAULT)
    enable_bits = build_enable_bits(only, except)
    ph_mode, ph_str = resolve_placeholder(placeholder)
    _redact(text, ph_mode, ph_str, enable_bits)
  end

  # Scan +text+ and return both the redacted string and per-match metadata.
  #
  # Useful for auditing, false-positive tuning, and compliance pipelines.
  # +:start+ and +:length+ are byte offsets into the *original* string, so
  # +text.byteslice(m[:start], m[:length]) == m[:value]+.
  #
  # @param text [String] input string.
  # @param only [Symbol, String, Array, nil] same semantics as {redact}.
  # @param except [Symbol, String, Array, nil] same semantics as {redact}.
  # @return [Hash{Symbol => Object}] +{ redacted: String, matches:
  #   Array<Hash> }+. Each match hash has +:tag+ (Symbol), +:name+ (String),
  #   +:value+ (String), +:start+ (Integer byte offset), +:length+ (Integer).
  # @raise [UnknownTagError] if any Symbol in +only:+/+except:+ is not in {TAGS}.
  # @raise [UnknownPatternError] if any String in +only:+/+except:+ is not in {pattern_names}.
  #
  # @example
  #   DataRedactor.scan("user@example.com")
  #   # => { redacted: "[REDACTED]",
  #   #      matches: [{tag: :contact, name: "email",
  #   #                 value: "user@example.com", start: 0, length: 16}] }
  def scan(text, only: nil, except: nil)
    enable_bits = build_enable_bits(only, except)
    result = _scan(text, enable_bits)
    # Normalise: convert tag string from C (uppercase) back to the Symbol used in TAGS
    result[:matches].each { |m| m[:tag] = m[:tag].to_s.downcase.to_sym }
    result
  end

  # Register a custom redaction pattern.
  #
  # Patterns must be valid POSIX ERE. Ruby-only syntax (+\d+, +\s+, +\w+,
  # +\b+, lookaround, non-greedy quantifiers, named groups) is rejected
  # at registration time, never at redaction time.
  #
  # If a pattern with the same +name+ is already registered, it is replaced
  # (the old compiled +regex_t+ is freed).
  #
  # @param name [String] unique identifier for this pattern. Used by {remove_pattern}.
  # @param regex [String, Regexp] POSIX ERE source. A Regexp is accepted
  #   for convenience but only its +.source+ is used; flags are ignored.
  # @param tag [Symbol] one of {TAGS} keys. Defaults to +:custom+.
  # @param boundary [Boolean] when true, the pattern is wrapped with
  #   +(^|[^0-9A-Za-z])(...)([^0-9A-Za-z]|$)+ so it only matches when not
  #   embedded in a longer alphanumeric token. Incompatible with patterns
  #   that contain capture groups.
  # @return [Boolean] +true+ on success.
  # @raise [ArgumentError] if +name+ is not a non-empty String, or +regex+
  #   is neither a String nor a Regexp.
  # @raise [InvalidPatternError] if the pattern uses Ruby-only syntax,
  #   contains capture groups while +boundary: true+, or fails +regcomp+.
  # @raise [UnknownTagError] if +tag+ is not in {TAGS}.
  #
  # @example
  #   DataRedactor.add_pattern(name: "employee_id", regex: "EMP-[0-9]{6}")
  #   DataRedactor.add_pattern(name: "internal_key",
  #                            regex: /INT-[A-Z]{3}/,
  #                            tag: :credentials,
  #                            boundary: true)
  def add_pattern(name:, regex:, tag: :custom, boundary: false)
    raise ArgumentError, "name must be a non-empty String" \
      unless name.is_a?(String) && !name.empty?

    source = case regex
             when String then regex
             when Regexp then regex.source
             else raise ArgumentError, "regex must be a String or Regexp, got #{regex.class}"
             end

    if source =~ RUBY_ONLY_SYNTAX_RE
      raise InvalidPatternError,
        "pattern #{name.inspect} uses Ruby-only syntax (#{$&.inspect}); " \
        "use POSIX ERE — no \\d, \\s, \\w, \\b, lookaround, non-greedy, or named groups"
    end

    if boundary && source =~ CAPTURE_GROUP_RE
      raise InvalidPatternError,
        "pattern #{name.inspect} has capture groups and cannot use boundary: true"
    end

    tag_bit = TAGS[tag] or raise UnknownTagError,
      "unknown tag #{tag.inspect}; valid tags: #{TAGS.keys.inspect}"

    _add_pattern(name, source, tag_bit, boundary ? 1 : 0)
  end

  # Remove a previously registered custom pattern.
  #
  # @param name [String, Symbol] the +name+ used in {add_pattern}.
  # @return [Boolean] +true+ if a pattern was removed, +false+ if no
  #   pattern with that name was registered.
  def remove_pattern(name)
    _remove_pattern(name.to_s)
  end

  # List every currently registered custom pattern.
  #
  # @return [Array<Hash{Symbol => Object}>] one hash per pattern with keys
  #   +:name+ (String), +:source+ (String — the POSIX ERE source),
  #   +:tag+ (Symbol), +:boundary+ (Boolean).
  def custom_patterns
    _custom_patterns.map do |h|
      { name: h[:name], source: h[:source], tag: TAGS.key(h[:tag_bit]) || :custom,
        boundary: h[:boundary] }
    end
  end

  # Remove every registered custom pattern.
  #
  # Mostly useful in test suites that need a clean slate between examples.
  #
  # @return [nil]
  def clear_custom_patterns!
    _clear_custom_patterns
  end

  # @api private
  # Split a mixed Symbol/String filter list into +(tag_bitmask, name_set)+.
  #
  # @param entries [nil, Symbol, String, Array]
  # @return [Array(Integer, Set<String>)] tag bits OR-ed together; set of
  #   pattern-name Strings.
  # @raise [UnknownTagError] for unknown Symbols.
  # @raise [UnknownPatternError] for unknown Strings.
  def split_filter(entries)
    bits = 0
    names = Set.new
    return [bits, names] if entries.nil?
    Array(entries).each do |e|
      case e
      when Symbol
        bit = TAGS[e] or raise UnknownTagError,
          "unknown tag #{e.inspect}; valid tags: #{TAGS.keys.inspect}"
        bits |= bit
      when String
        unless pattern_names.include?(e)
          raise UnknownPatternError,
            "unknown pattern name #{e.inspect}; see DataRedactor.pattern_names"
        end
        names << e
      else
        raise ArgumentError,
          "only:/except: entries must be a Symbol (tag) or String (pattern name), got #{e.inspect}"
      end
    end
    [bits, names]
  end

  # @api private
  # Build the per-pattern enable bit-list passed to the C layer.
  #
  # The list has one Integer (0 or 1) per pattern in execution order:
  # built-ins first (NUM_PATTERNS entries), then currently registered custom
  # patterns in registration order. C iterates by index and skips zeros.
  #
  # Semantics of +only:+ / +except:+ — both accept a mix of Symbols (tags)
  # and Strings (pattern names):
  #   enabled(p) iff
  #     (only is nil OR p.tag ∈ only_tags OR p.name ∈ only_names)
  #     AND p.tag ∉ except_tags AND p.name ∉ except_names
  #
  # @return [Array<Integer>] same length as built-ins + customs.
  def build_enable_bits(only, except)
    only_bits,   only_names   = split_filter(only)
    except_bits, except_names = split_filter(except)
    only_present = !only.nil?

    bits = Array.new(BUILTIN_PATTERN_NAMES.length + _custom_patterns.length, 0)

    BUILTIN_PATTERN_NAMES.each_with_index do |name, i|
      tag_bit = BUILTIN_PATTERN_TAG_BITS[i]
      bits[i] = 1 if pattern_enabled?(name, tag_bit, only_present,
                                      only_bits, only_names,
                                      except_bits, except_names)
    end

    _custom_patterns.each_with_index do |h, i|
      bits[BUILTIN_PATTERN_NAMES.length + i] = 1 if pattern_enabled?(
        h[:name], h[:tag_bit], only_present,
        only_bits, only_names, except_bits, except_names)
    end

    bits
  end

  # @api private
  def pattern_enabled?(name, tag_bit, only_present, only_bits, only_names,
                       except_bits, except_names)
    return false if (tag_bit & except_bits) != 0
    return false if except_names.include?(name)
    return true  unless only_present
    return true  if (tag_bit & only_bits) != 0
    only_names.include?(name)
  end

  # @api private
  # Translate the user-facing +placeholder:+ value into the +(mode_int, str)+
  # pair the C layer expects.
  #
  # @param placeholder [String, :tagged, :hash]
  # @return [Array(Integer, String)]
  # @raise [ArgumentError] if +placeholder+ is none of the accepted values.
  def resolve_placeholder(placeholder)
    case placeholder
    when :tagged then [PH_MODE_TAGGED, ""]
    when :hash   then [PH_MODE_HASH,   ""]
    when String  then [PH_MODE_PLAIN,  placeholder]
    else
      raise ArgumentError,
        "placeholder must be a String, :tagged, or :hash — got #{placeholder.inspect}"
    end
  end
end
