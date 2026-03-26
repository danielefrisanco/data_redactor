Gem::Specification.new do |spec|
  spec.name          = "data_redactor"
  spec.version       = "0.1.0"
  spec.authors       = ["Daniele Frisanco"]
  spec.email         = ["daniele.frisanco@gmail.com"]
  spec.summary       = "Redact PII and secrets from strings before sending to AI or external services"
  spec.description   = "A Ruby gem with a C extension for high-performance scanning and redaction of 79 sensitive patterns — API keys, tokens, credentials, IBANs, national IDs, emails, phone numbers, and PII from 15+ countries. Designed to sanitize text before sending to LLMs, logging systems, or any public/third-party API."
  spec.license       = "MIT"

  spec.files         = Dir["lib/**/*.rb", "ext/**/*.{c,h,rb}"]
  spec.extensions    = ["ext/data_redactor/extconf.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rspec", "~> 3.12"
end
