require "test_helper"
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
  LIB = File.expand_path("../../lib", __dir__)

  LAYERS = %i[TLS QUIC HTTP3 Runtime].freeze

  # Entry point => the layers it must leave undefined.
  FORBIDDEN_LAYERS = {
    "raiha/tls" => %i[QUIC HTTP3 Runtime],
    "raiha/tls/test" => %i[QUIC HTTP3 Runtime],
    "raiha/quic" => %i[HTTP3 Runtime],
    "raiha/quic/test" => %i[HTTP3 Runtime],
    "raiha/http3" => %i[TLS QUIC Runtime],
    "raiha/http3/qpack" => %i[TLS QUIC Runtime],
    "raiha/http3_binding" => %i[Runtime],
    "raiha/runtime" => %i[],
    "raiha/runtime/rack" => %i[],
    "raiha" => %i[]
  }.freeze

  # Entry point => constants of its own layer it must leave undefined. QPACK
  # is checked alone against a decoder's corpus, before any frame of HTTP/3
  # is written, so it must not need them.
  FORBIDDEN_CONSTANTS = {
    "raiha/http3/qpack" => %w[Raiha::Next::HTTP3::Frame],
    # The Rack adapter is for Rack, and loads no rack gem.
    "raiha/runtime/rack" => %w[::Rack]
  }.freeze

  # `Raiha::VERSION` is the only old constant the next release may refer to,
  # since the version number outlives the replacement of the old
  # implementation.
  ALLOWED_UNDER_RAIHA = %i[Next VERSION].freeze

  FORBIDDEN_LAYERS.each do |entry, forbidden|
    define_method(:"test_require_#{entry.tr("/", "_")}_in_isolation") do
      constants = FORBIDDEN_CONSTANTS.fetch(entry, [])
      raiha_constants, defined_layers, defined_constants = require_in_fresh_process(entry, constants)

      assert_empty defined_layers & forbidden,
        "require #{entry.inspect} must not define Raiha::Next::{#{forbidden.join(",")}}"
      assert_empty defined_constants,
        "require #{entry.inspect} must not define #{constants.join(", ")}"
      assert_empty raiha_constants - ALLOWED_UNDER_RAIHA,
        "require #{entry.inspect} must not load the old implementation"
    end
  end

  private def require_in_fresh_process(entry, constants)
    script = <<~RUBY
      require #{entry.dump}
      puts Raiha.constants(false).sort.join(" ")
      puts #{LAYERS.inspect}.select { |name| Raiha::Next.const_defined?(name, false) }.join(" ")
      puts #{constants.inspect}.select { |name| Object.const_get(name) rescue false }.join(" ")
    RUBY
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-I", LIB, "-e", script)
    assert status.success?, "require #{entry.inspect} failed:\n#{stderr}"

    raiha_line, layers_line, constants_line = stdout.lines
    [raiha_line.split.map(&:to_sym), layers_line.split.map(&:to_sym), constants_line.split]
  end
end
