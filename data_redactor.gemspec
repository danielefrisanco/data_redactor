require_relative "lib/data_redactor/version"

Gem::Specification.new do |spec|
  spec.name          = "data_redactor"
  spec.version       = DataRedactor::VERSION
  spec.authors       = ["Daniele Frisanco"]
  spec.email         = ["daniele.frisanco@gmail.com"]
  spec.summary       = "Redact PII and secrets from strings before sending to AI or external services"
  spec.description   = "A Ruby gem with a C extension for high-performance scanning and redaction of sensitive data — API keys, tokens, credentials, IBANs, national IDs, emails, phone numbers, and PII from 15+ countries. Optional Logger formatter, Rails filter_parameters adapter, and Rack middleware. Designed to sanitize text before sending to LLMs, logging systems, or any public/third-party API."
  spec.license       = "MIT"
  spec.homepage      = "https://github.com/danielefrisanco/data_redactor"

  spec.required_ruby_version = ">= 2.7"

  spec.metadata = {
    "homepage_uri"      => spec.homepage,
    "source_code_uri"   => spec.homepage,
    "changelog_uri"     => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri"   => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir["lib/**/*.rb", "ext/**/*.{c,h,rb}"] +
               %w[LICENSE CHANGELOG.md README.md]
  spec.extensions    = ["ext/data_redactor/extconf.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rake-compiler-dock", "~> 1.5"
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "yard", "~> 0.9"
  spec.add_development_dependency "rack", ">= 2.0"
  spec.add_development_dependency "benchmark-ips", "~> 2.13"
  spec.add_development_dependency "benchmark-memory", "~> 0.2"
end
