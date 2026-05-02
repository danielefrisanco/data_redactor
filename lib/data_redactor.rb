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
    other:       TAG_OTHER
  }.freeze

  class UnknownTagError < ArgumentError; end

  module_function

  def tags
    TAGS.keys
  end

  def redact(text, only: nil, except: nil)
    if only && except
      raise ArgumentError, "pass only: or except:, not both"
    end

    mask =
      if only
        bits_for(only)
      elsif except
        TAG_ALL & ~bits_for(except)
      else
        TAG_ALL
      end

    _redact(text, mask)
  end

  def bits_for(tag_list)
    Array(tag_list).inject(0) do |acc, tag|
      bit = TAGS[tag] or raise UnknownTagError, "unknown tag #{tag.inspect}; valid tags: #{TAGS.keys.inspect}"
      acc | bit
    end
  end
end
