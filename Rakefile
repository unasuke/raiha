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
    INTEROP_SPEC = {
      aioquic: { file: "test/interop/quic/aioquic_test.rb", build: :aioquic },
      quicgo: { file: "test/interop/quic/quicgo_test.rb", build: :quicgo },
      quiche: { file: "test/interop/quic/quiche_test.rb", build: :quiche },
      quiche_http3_client: { file: "test/interop/http3/quiche_client_test.rb", build: :quiche },
      quiche_http3_server: { file: "test/interop/http3/quiche_server_test.rb", build: :quiche },
      openssl: { file: "test/interop/tls/openssl_test.rb", build: :openssl },
      picotls: { file: "test/interop/tls/picotls_test.rb", build: :picotls }
    }.freeze

    INTEROP_SPEC.each do |name, spec|
      Rake::TestTask.new(name) do |t|
        t.description = "Run #{name} interop tests (auto-builds the peer implementation)"
        t.libs << "test"
        t.libs << "lib"
        t.test_files = [spec[:file]]
      end
      task name => "interop:build:#{spec[:build]}"
    end
  end
end

namespace :interop do
  namespace :build do
    desc "Build quic-go interop client/server binaries"
    task :quicgo do
      Dir.chdir("test/support/quicgo") do
        sh "go build -o client_bin client.go"
        sh "go build -o server_bin server.go"
      end
    end

    desc "Clone and build cloudflare/quiche into tmp/quiche"
    task :quiche do
      unless Dir.exist?("tmp/quiche")
        mkdir_p "tmp"
        sh "git clone --depth 1 https://github.com/cloudflare/quiche.git tmp/quiche"
      end
      sh "cargo build --release --manifest-path tmp/quiche/Cargo.toml --package quiche_apps"
    end

    desc "Clone and build h2o/picotls into tmp/picotls"
    task :picotls do
      unless Dir.exist?("tmp/picotls")
        mkdir_p "tmp"
        sh "git clone --depth 1 --recurse-submodules https://github.com/h2o/picotls.git tmp/picotls"
      end
      sh "cmake -S tmp/picotls -B tmp/picotls"
      sh "make -C tmp/picotls cli"
    end

    desc "Verify uv is available (aioquic is resolved on-demand at test time)"
    task :aioquic do
      sh "uv --version"
    end

    desc "Verify system openssl is available"
    task :openssl do
      sh "openssl version"
    end
  end

  desc "Build every interop peer implementation"
  task build: %w[build:aioquic build:quicgo build:quiche build:openssl build:picotls]
end

task :default => :test
