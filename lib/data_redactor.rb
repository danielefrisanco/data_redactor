require_relative "data_redactor/version"
require_relative "data_redactor/data_redactor" # loads the compiled .so

module DataRedactor
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

  class UnknownTagError     < ArgumentError; end
  class InvalidPatternError < ArgumentError; end

  # Capture groups break boundary-wrapper group index assumptions ([1],[2],[3] shift).
  CAPTURE_GROUP_RE = /(?<!\\)\((?!\?:)/.freeze

  # Ruby regex syntax that has no POSIX ERE equivalent.
  RUBY_ONLY_SYNTAX_RE = /\\[dDwWsShHbB]|\(\?[<!=]|\(\?<[a-zA-Z]|\(\?[imx]|[*+?]\?/.freeze

  PLACEHOLDER_DEFAULT = "[REDACTED]"

  module_function

  def tags
    TAGS.keys
  end

  def redact(text, only: nil, except: nil, placeholder: PLACEHOLDER_DEFAULT)
    raise ArgumentError, "pass only: or except:, not both" if only && except

    mask =
      if only
        bits_for(only)
      elsif except
        TAG_ALL & ~bits_for(except)
      else
        TAG_ALL
      end

    ph_mode, ph_str = resolve_placeholder(placeholder)
    _redact(text, mask, ph_mode, ph_str)
  end

  # Add (or replace) a custom redaction pattern.
  #
  # name:     unique identifier string
  # regex:    String (POSIX ERE) or Regexp; Ruby-only syntax raises InvalidPatternError
  # tag:      one of the TAGS keys (default :custom), or any built-in tag
  # boundary: wrap with word-boundary guards; incompatible with capture groups
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

  def remove_pattern(name)
    _remove_pattern(name.to_s)
  end

  def custom_patterns
    _custom_patterns.map do |h|
      { name: h[:name], source: h[:source], tag: TAGS.key(h[:tag_bit]) || :custom,
        boundary: h[:boundary] }
    end
  end

  def clear_custom_patterns!
    _clear_custom_patterns
  end

  def bits_for(tag_list)
    Array(tag_list).inject(0) do |acc, tag|
      bit = TAGS[tag] or raise UnknownTagError,
        "unknown tag #{tag.inspect}; valid tags: #{TAGS.keys.inspect}"
      acc | bit
    end
  end

  # Returns [ph_mode_int, ph_str] for the C layer.
  #   placeholder: "***"      -> plain string
  #   placeholder: :tagged    -> "[REDACTED:TAGNAME]"
  #   placeholder: :hash      -> "[TAGNAME_xxxx]"
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
