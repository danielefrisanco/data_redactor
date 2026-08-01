source "https://rubygems.org"
gemspec

# railties is only needed to test the Railtie, so it lives here rather than in
# the gemspec (the gem itself has no Rails dependency at all). CI pins a version
# per matrix entry via RAILS_VERSION to prove the Railtie works across the Rails
# versions the gem supports — `Rails.logger` is a plain Logger on 7.0 and an
# ActiveSupport::BroadcastLogger on 7.1+, which the Railtie handles differently.
#
# Grouped so the cross-compile container can exclude it with
# `BUNDLE_WITHOUT=rails`: that job only builds the C extension, but railties
# pulls in actionpack -> nokogiri, whose supported Ruby range excludes the Ruby
# that ships in the rake-compiler-dock image. Not an optional group — the specs
# need Rails by default everywhere else.
group :rails do
  gem "railties", ENV["RAILS_VERSION"] ? "~> #{ENV['RAILS_VERSION']}.0" : ">= 6.0"
end
