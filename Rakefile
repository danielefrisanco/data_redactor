require "rake/extensiontask"
require "rspec/core/rake_task"

Rake::ExtensionTask.new("data_redactor") do |ext|
  ext.lib_dir = "lib/data_redactor"
end

RSpec::Core::RakeTask.new(:spec)

task default: [:compile, :spec]
