# frozen_string_literal: true

# Logger integration: scrub every log line before it is written. A drop-in
# Logger::Formatter — set it once and forget it.
#
#   ruby examples/logger.rb

require "logger"
require "data_redactor/integrations/logger"

logger = Logger.new($stdout)
logger.formatter = DataRedactor::Integrations::Logger.new

logger.info("Auth failed for user alice@example.com")
# => I, [...] -- : Auth failed for user [REDACTED]

logger.warn("Stripe charge with key AKIAIOSFODNN7EXAMPLE")
# => W, [...] -- : Stripe charge with key [REDACTED]

# Wrap an existing formatter (e.g. a JSON formatter) and restrict to tags.
# The inner formatter renders the line; we scrub the rendered result.
json_logger = Logger.new($stdout)
json_logger.formatter = DataRedactor::Integrations::Logger.new(
  inner: ->(sev, _time, _prog, msg) { %({"level":"#{sev}","msg":"#{msg}"}\n) },
  only:  [:credentials, :contact],
)
json_logger.error("login alice@example.com / AKIAIOSFODNN7EXAMPLE")
# => {"level":"ERROR","msg":"login [REDACTED] / [REDACTED]"}
