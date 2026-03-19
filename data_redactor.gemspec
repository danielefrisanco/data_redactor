Gem::Specification.new do |spec|
  spec.name          = "data_redactor"
  spec.version       = "0.1.0"
  spec.authors       = ["Daniele Frisanco"]
  spec.email         = ["daniele.frisanco@gmail.com"]
  spec.summary       = "High-performance regex redaction using a C extension"
  spec.description   = "A Ruby gem with a C extension for scanning and redacting sensitive patterns (AWS keys, Italian fiscal codes, passport numbers, etc.)"
  spec.license       = "MIT"

  spec.files         = Dir["lib/**/*.rb", "ext/**/*.{c,h,rb}"]
  spec.extensions    = ["ext/data_redactor/extconf.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "rspec", "~> 3.12"
end
