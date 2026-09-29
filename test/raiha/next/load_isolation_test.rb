require "raiha/next/test_helper"
require "open3"
require "rbconfig"

# Requires each entry point alone in a fresh process and checks that the
# layers it must not refer to, and the old implementation, stay undefined.
# This stands in for "a gem cannot load what it does not depend on" from when
# the layers were planned as separate gems.
#
# A fully qualified reference such as `Raiha::Next::QUIC` written inside the
# TLS layer is not caught here unless the file is also required; that is left
# to review.
class RaihaNextLoadIsolationTest < Minitest::Test
  LIB = File.expand_path("../../../lib", __dir__)

  LAYERS = %i[TLS QUIC HTTP3 Runtime].freeze

  # Entry point => the layers it must leave undefined.
  FORBIDDEN_LAYERS = {
    "raiha/next/tls" => %i[QUIC HTTP3 Runtime],
    "raiha/next/quic" => %i[HTTP3 Runtime],
    "raiha/next/http3" => %i[TLS QUIC Runtime],
    "raiha/next/runtime" => %i[],
    "raiha/next" => %i[]
  }.freeze

  # `Raiha::VERSION` is the only old constant the next release may refer to,
  # since the version number outlives the replacement of the old
  # implementation.
  ALLOWED_UNDER_RAIHA = %i[Next VERSION].freeze

  FORBIDDEN_LAYERS.each do |entry, forbidden|
    define_method(:"test_require_#{entry.tr("/", "_")}_in_isolation") do
      raiha_constants, defined_layers = require_in_fresh_process(entry)

      assert_empty defined_layers & forbidden,
        "require #{entry.inspect} must not define Raiha::Next::{#{forbidden.join(",")}}"
      assert_empty raiha_constants - ALLOWED_UNDER_RAIHA,
        "require #{entry.inspect} must not load the old implementation"
    end
  end

  private def require_in_fresh_process(entry)
    script = <<~RUBY
      require #{entry.dump}
      puts Raiha.constants(false).sort.join(" ")
      puts #{LAYERS.inspect}.select { |name| Raiha::Next.const_defined?(name, false) }.join(" ")
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-I", LIB, "-e", script)
    assert status.success?, "require #{entry.inspect} failed:\n#{stderr}"

    raiha_line, layers_line = stdout.lines
    [raiha_line.split.map(&:to_sym), layers_line.split.map(&:to_sym)]
  end
end
