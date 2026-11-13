source "https://rubygems.org"

# Specify your gem's dependencies in raiha.gemspec
gemspec

group :development do
  gem "steep"
  gem "rbs"
  gem "rake"
  gem "rubocop"
  gem "debug"
end

group :test do
  gem "minitest"
  gem "simplecov", require: false
  # A Fiber scheduler for the tests of the runtime of raiha, and
  # Rack::Lint for its Rack adapter, which itself does not depend on rack.
  gem "async"
  gem "rack"
  # A TLS 1.3 in Ruby, for the interop test against it.
  gem "tttls1.3"
end

# Peer implementation for the quic gem interop test. It builds ngtcp2 +
# picotls native extensions at install time, so it is kept out of the default
# bundle. Enable with: bundle install --with interop
group :interop, optional: true do
  gem "quic", github: "unasuke/quic-ruby"
end
