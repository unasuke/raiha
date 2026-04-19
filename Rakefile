require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.description = "Run all tests"
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

namespace :test do
  Rake::TestTask.new(:unit) do |t|
    t.description = "Run unit/self-contained tests (excludes cross-language interop)"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/**/*_test.rb"].exclude("test/interop/**/*_test.rb")
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

  Rake::TestTask.new(:interop) do |t|
    t.description = "Run all cross-language interop tests"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/interop/**/*_test.rb"]
  end

  namespace :interop do
    {
      aioquic: "test/interop/quic/aioquic_test.rb",
      quicgo: "test/interop/quic/quicgo_test.rb",
      quiche: "test/interop/quic/quiche_test.rb",
      quiche_http3_client: "test/interop/http3/quiche_client_test.rb",
      quiche_http3_server: "test/interop/http3/quiche_server_test.rb",
      openssl: "test/interop/tls/openssl_test.rb",
      picotls: "test/interop/tls/picotls_test.rb"
    }.each do |name, file|
      Rake::TestTask.new(name) do |t|
        t.description = "Run #{name} interop tests"
        t.libs << "test"
        t.libs << "lib"
        t.test_files = [file]
      end
    end
  end
end

task :default => :test
