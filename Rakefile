require "bundler/gem_tasks"
require "digest"
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

  Rake::TestTask.new(:next) do |t|
    t.description = "Run tests for the next release of raiha (lib/raiha)"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/raiha/**/*_test.rb"]
  end

  Rake::TestTask.new(:interop) do |t|
    t.description = "Run all cross-language interop tests"
    t.libs << "test"
    t.libs << "lib"
    t.test_files = FileList["test/interop/**/*_test.rb"]
  end
end

namespace :test do
  namespace :next do
    namespace :interop do
      NEXT_INTEROP_SPEC = {
        openssl: { file: "test/interop/tls/openssl_test.rb", build: :openssl },
        picotls: { file: "test/interop/tls/picotls_test.rb", build: :picotls },
        quicgo: { file: "test/interop/quic/quicgo_test.rb", build: :quicgo },
        aioquic: { file: "test/interop/quic/aioquic_test.rb", build: :aioquic },
        quic_gem: { file: "test/interop/quic/quic_gem_test.rb", build: :quic_gem },
        h3i: { file: "test/interop/http3/h3i_test.rb", build: :h3i },
        quiche_http3_client: { file: "test/interop/http3/quiche_client_test.rb", build: :quiche },
        quiche_http3_server: { file: "test/interop/http3/quiche_server_test.rb", build: :quiche },
        h3spec: { file: "test/interop/http3/h3spec_test.rb", build: :h3spec },
        # A gem in the bundle: nothing to build.
        tttls13: { file: "test/interop/tls/tttls13_test.rb", build: nil }
      }.freeze

      NEXT_INTEROP_SPEC.each do |name, spec|
        Rake::TestTask.new(name) do |t|
          t.description = "Run #{name} interop tests of the next release of raiha (auto-builds the peer implementation)"
          t.libs << "test"
          t.libs << "lib"
          t.test_files = [spec[:file]]
        end
        task name => "interop:build:#{spec[:build]}" if spec[:build]
      end
    end

    Rake::TestTask.new(:qifs) do |t|
      t.description = "Run QPACK of the next release of raiha against the qifs corpus (fetches it into tmp/qifs)"
      t.libs << "test"
      t.libs << "lib"
      t.test_files = FileList["test/interop/http3/qifs*_test.rb"]
    end
    task qifs: "interop:build:qifs"
  end
end

namespace :interop do
  namespace :build do
    desc "Build quic-go interop client/server binaries"
    task :quicgo do
      Dir.chdir("test/support/quicgo") do
        sh "go build -o client_bin client.go"
        sh "go build -o server_bin server.go"
        sh "go build -o resume_client_bin resume_client.go"
        sh "go build -o resume_server_bin resume_server.go"
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

    desc "Build the h3i conformance test harness (uses the tmp/quiche clone)"
    task h3i: :quiche do
      sh({ "CARGO_TARGET_DIR" => File.expand_path("tmp/h3i_harness") },
         "cargo", "build", "--release",
         "--manifest-path", "test/support/h3i_harness/Cargo.toml")
    end

    desc "Clone and build h2o/picotls into tmp/picotls"
    task :picotls do
      # CI restores tmp/picotls/cli alone from its cache, with no sources
      # beside it to build from.
      next if File.executable?("tmp/picotls/cli")

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

    # The latest commit of qpackers/qifs, from 2021.
    QIFS_COMMIT = "da52cd936b3e34dac7ac12aa8066fc57676af106"

    desc "Fetch the qifs corpus (qpackers/qifs) at a fixed commit into tmp/qifs"
    task :qifs do
      unless Dir.exist?("tmp/qifs/.git")
        mkdir_p "tmp/qifs"
        sh "git -C tmp/qifs init -q"
        sh "git -C tmp/qifs remote add origin https://github.com/qpackers/qifs.git"
      end
      unless `git -C tmp/qifs rev-parse HEAD 2>/dev/null`.strip == QIFS_COMMIT
        sh "git -C tmp/qifs fetch -q --depth 1 origin #{QIFS_COMMIT}"
        sh "git -C tmp/qifs checkout -q FETCH_HEAD"
      end
    end

    H3SPEC_VERSION = "v0.1.14"
    # The binary of each platform the release has, and its SHA-256.
    H3SPEC_BINARIES = {
      "x86_64-linux" => ["h3spec-linux-x86_64", "7f2e3232715a3f6ff5212d408b2a3e74d6aa3ca06f96efca9a4e5dc55f3c6860"],
      "arm64-darwin" => ["h3spec-mac-arm64", "1d76372c74b5fbc28256229e01135f7c878045b8b0a1dc578eaa866e10df140a"]
    }.freeze

    desc "Fetch h3spec (kazu-yamamoto/h3spec) of a fixed release into tmp/h3spec"
    task :h3spec do
      platform = "#{Gem::Platform.local.cpu}-#{Gem::Platform.local.os}"
      asset, sha256 = H3SPEC_BINARIES.fetch(platform) { raise "h3spec #{H3SPEC_VERSION} has no binary for #{platform}" }
      binary = "tmp/h3spec/h3spec"
      next if File.exist?(binary) && Digest::SHA256.file(binary).hexdigest == sha256
      mkdir_p "tmp/h3spec"
      sh "curl", "-fsSL", "-o", binary, "https://github.com/kazu-yamamoto/h3spec/releases/download/#{H3SPEC_VERSION}/#{asset}"
      raise "#{binary} is not the h3spec #{H3SPEC_VERSION} expected" unless Digest::SHA256.file(binary).hexdigest == sha256
      chmod 0o755, binary
    end

    desc "Install the quic gem (github: unasuke/quic-ruby) into the interop bundle group"
    task :quic_gem do
      # Outside the environment of `bundle exec`, whose bundler/setup would
      # load the group the commands are to install, and fail on it.
      Bundler.with_original_env do
        sh "bundle config set --local with interop"
        sh "bundle install"
      end
      ENV["BUNDLE_WITH"] = "interop" # also inherited by the Rake::TestTask ruby subprocess
    end
  end

  desc "Build every interop peer implementation"
  task build: %w[build:aioquic build:quicgo build:quiche build:h3i build:openssl build:picotls build:quic_gem]
end

task :default => :test
