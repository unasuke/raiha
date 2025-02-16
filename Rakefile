require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.description = "Run all tests"
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

namespace :test do
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
