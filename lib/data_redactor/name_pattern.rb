# frozen_string_literal: true

module DataRedactor
  # Maps a base ASCII letter to the set of accented characters that should
  # also match it. Used to make generated name patterns diacritic-tolerant:
  # an input "Jose" still matches "José", and "Munoz" matches "Muñoz".
  #
  # @api private
  DIACRITIC_FOLD = {
    "a" => "àáâãäåāăą",
    "c" => "çćĉċč",
    "e" => "èéêëēĕėęě",
    "i" => "ìíîïĩīĭįı",
    "n" => "ñńņňŉ",
    "o" => "òóôõöøōŏő",
    "u" => "ùúûüũūŭůűų",
    "y" => "ýÿŷ",
    "s" => "śŝşš",
    "z" => "źżž",
    "g" => "ĝğġģ",
    "l" => "ĺļľŀł",
    "r" => "ŕŗř",
    "t" => "ţťŧ"
  }.freeze

  module_function

  # Build a POSIX ERE that matches a person's name across common written
  # variations, ready to hand to {add_pattern}.
  #
  # The returned pattern is **boundary-wrapped** — it embeds
  # +(^|[^A-Za-z])+ ... +([^A-Za-z]|$)+ so that +"Mario"+ matches as a whole
  # word but not inside +"Mariolino"+. Because the wrapper uses capture
  # groups, register the pattern with the default +boundary: false+ (do
  # **not** pass +boundary: true+ — that would double-wrap and reject the
  # groups).
  #
  # Variations covered:
  # - **Case** — every letter becomes a case-insensitive character class
  #   (+[Mm][Aa]...+), since POSIX ERE has no +/i+ flag.
  # - **Order** — +"First Last"+, +"Last First"+, +"Last, First"+,
  #   +"Last,First"+.
  # - **Initials** — +"M. Last"+, +"M Last"+, +"First R."+, +"First R"+,
  #   +"M.R."+, +"M R"+, +"MR"+.
  # - **Diacritics** — an ASCII letter with a {DIACRITIC_FOLD} entry also
  #   matches its accented forms (+"Jose"+ matches +"José"+). An accented
  #   input letter also matches its bare ASCII form.
  # - **Separators** — spaces and hyphens are interchangeable between and
  #   within name parts. A hyphenated part like +"Anne-Marie"+ also matches
  #   +"Anne Marie"+, +"AnneMarie"+, and each half on its own (+"Anne"+,
  #   +"Marie"+). Multi-word parts like +"Van der Berg"+ tolerate any
  #   space/hyphen separator between words.
  #
  # @param first [String] the given name. May contain hyphens or spaces.
  # @param last [String] the family name. May contain hyphens or spaces.
  # @param middle [String, nil] optional middle name. When given, the pattern
  #   matches **both** the no-middle forms and the with-middle forms.
  # @return [String] a POSIX ERE source string.
  # @raise [ArgumentError] if +first+ or +last+ is not a non-empty String,
  #   or +middle+ is given but is not a non-empty String.
  #
  # @example Register a name pattern
  #   DataRedactor.add_pattern(
  #     name:  "person_mario_rossi",
  #     regex: DataRedactor.name_pattern("Mario", "Rossi"),
  #     tag:   :contact
  #   )
  #
  # @example With a middle name
  #   DataRedactor.name_pattern("Mario", "Rossi", middle: "Luigi")
  def name_pattern(first, last, middle: nil)
    _validate_name_arg!(first, "first")
    _validate_name_arg!(last, "last")
    _validate_name_arg!(middle, "middle") unless middle.nil?

    first_tok  = _part_token(first)
    last_tok   = _part_token(last)
    middle_tok = middle && _part_token(middle)

    # Separator between name parts. Optional so initial-only forms collapse
    # ("MR", "M.R.") and so "First,Last" with no space still matches.
    sep = "[ ,-]*"

    bodies = []
    bodies << "#{first_tok}#{sep}#{last_tok}"            # First Last
    bodies << "#{last_tok}#{sep}#{first_tok}"            # Last First / Last, First

    if middle_tok
      bodies << "#{first_tok}#{sep}#{middle_tok}#{sep}#{last_tok}" # First Middle Last
      bodies << "#{last_tok}#{sep}#{first_tok}#{sep}#{middle_tok}" # Last First Middle
    end

    "(^|[^A-Za-z])(#{bodies.join('|')})([^A-Za-z]|$)"
  end

  # @api private
  # Build the alternation for one name part: the full case-insensitive name,
  # or its initial (with optional dot). Hyphenated/multi-word parts also
  # match each sub-word alone and tolerant separators between sub-words.
  #
  # @param part [String] a single name part, e.g. "Mario" or "Anne-Marie".
  # @return [String] a parenthesised POSIX ERE alternation.
  def _part_token(part)
    words = part.split(/[ -]+/).reject(&:empty?)

    word_alts = words.map { |w| _word_alternatives(w) }

    forms = []
    # whole part with tolerant separators between its words
    forms << word_alts.map { |alts| "(#{alts.join('|')})" }.join("[ -]?")
    # each word on its own (covers "Anne" / "Marie" from "Anne-Marie")
    if words.length > 1
      word_alts.each { |alts| forms << "(#{alts.join('|')})" }
    end

    "(#{forms.uniq.join('|')})"
  end

  # @api private
  # Alternatives for a single whitespace-free word: the full name (each
  # letter as a case-insensitive, diacritic-folded class) and its initial.
  #
  # @param word [String] a single word with no spaces or hyphens.
  # @return [Array<String>] alternation members for this word.
  def _word_alternatives(word)
    full    = word.chars.map { |ch| _letter_class(ch) }.join
    initial = "#{_letter_class(word[0])}\\.?"
    [full, initial]
  end

  # @api private
  # Build a POSIX bracket expression matching one letter case-insensitively
  # and, where applicable, its accented variants.
  #
  # @param char [String] a single character.
  # @return [String] a bracket expression, e.g. "[Mm]" or "[EeÈÉÊËèéêë]".
  def _letter_class(char)
    down = char.downcase
    up   = char.upcase
    members = [down]
    members << up unless up == down

    base = DIACRITIC_FOLD.key?(down) ? down : _ascii_base(down)
    if base && DIACRITIC_FOLD.key?(base)
      accented = DIACRITIC_FOLD[base]
      members << accented << accented.upcase
      members << base << base.upcase # accented input still matches bare ASCII
    end

    "[#{members.join}]"
  end

  # @api private
  # If +char+ is an accented letter, return the bare ASCII letter it folds
  # to; otherwise nil.
  #
  # @param char [String] a single lowercase character.
  # @return [String, nil]
  def _ascii_base(char)
    DIACRITIC_FOLD.each { |ascii, accents| return ascii if accents.include?(char) }
    nil
  end

  # @api private
  def _validate_name_arg!(value, label)
    return if value.is_a?(String) && !value.strip.empty?

    raise ArgumentError, "#{label} must be a non-empty String, got #{value.inspect}"
  end
end
