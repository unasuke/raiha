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
end

# Peer implementation for the quic gem interop test. It builds LibreSSL +
# ngtcp2 native extensions at install time, so it is kept out of the default
# bundle. Enable with: bundle install --with interop
group :interop, optional: true do
  gem "quic", github: "unasuke/quic-ruby"
end
