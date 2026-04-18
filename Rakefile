require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.description = "Run all tests"
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

namespace :test do
  # Tests that spawn an external-language implementation (Python aioquic,
  # Go quic-go, Rust quiche, or the openssl/picotls CLI). CI runs each
  # of these in its own job with the corresponding toolchain installed.
  INTEROP_TEST_FILES = %w[
    test/raiha/quic_aioquic_interop_test.rb
    test/raiha/quic_quicgo_interop_test.rb
    test/raiha/quic_quiche_interop_test.rb
    test/raiha/http3/quiche_interop_test.rb
    test/raiha/http3/quiche_server_interop_test.rb
    test/raiha/tls/openssl_integration_test.rb
    test/raiha/tls/picotls_integration_test.rb
  ].freeze

  Rake::TestTask.new(:unit) do |t|
    t.description = "Run unit/self-contained tests (excludes cross-language interop)"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/**/*_test.rb"].exclude(*INTEROP_TEST_FILES)
  end

  Rake::TestTask.new(:quic) do |t|
    t.description = "Run QUIC tests"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/raiha/quic/**/*_test.rb"]
  end

  Rake::TestTask.new(:tls) do |t|
    t.description = "Run TLS tests"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/raiha/tls/**/*_test.rb"]
  end
end

task :default => :test
