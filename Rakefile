require "bundler/gem_tasks"
require "rake/extensiontask"
require "rspec/core/rake_task"

GEMSPEC = Bundler.load_gemspec("data_redactor.gemspec")

CROSS_RUBY_VERSIONS  = %w[3.1 3.2 3.3 3.4].freeze
CROSS_PLATFORMS      = %w[
  x86_64-linux
  aarch64-linux
  x86_64-linux-musl
  aarch64-linux-musl
  x86_64-darwin
  arm64-darwin
].freeze

Rake::ExtensionTask.new("data_redactor", GEMSPEC) do |ext|
  ext.lib_dir         = "lib/data_redactor"
  ext.cross_compile   = true
  ext.cross_platform  = CROSS_PLATFORMS
  ext.cross_compiling do |spec|
    # Native gems ship the compiled .so files only — no C sources, no extconf.
    # Keeps platform gems small and prevents on-install recompilation.
    spec.files = spec.files.reject { |f| f.start_with?("ext/") }
    spec.extensions = []
    spec.dependencies.reject! { |d| d.name == "rake-compiler" }
  end
end

RSpec::Core::RakeTask.new(:spec)

task default: [:compile, :spec]

namespace :gem do
  desc "Build native gems for every supported platform via rake-compiler-dock (requires Docker)"
  task :all do
    require "rake_compiler_dock"
    CROSS_PLATFORMS.each do |platform|
      RakeCompilerDock.sh(
        "bundle install --jobs $(nproc) && " \
        "bundle exec rake native:data_redactor:#{platform} gem " \
        "RUBY_CC_VERSION=#{CROSS_RUBY_VERSIONS.join(':')}",
        platform: platform,
      )
    end
  end
end
