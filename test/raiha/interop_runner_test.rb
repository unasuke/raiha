require "test_helper"

$LOAD_PATH.unshift File.expand_path("../../interop/lib", __dir__)
require "raiha_interop/runner"

# Sanity-checks for the entry point that quic-interop-runner invokes.
# End-to-end interop validation is exercised separately via Docker;
# these tests only cover the dispatch logic so changes to the runner
# scaffolding do not break the contract with run_endpoint.sh.
class RaihaInteropRunnerTest < Minitest::Test
  def test_unsupported_testcase_returns_127
    out = StringIO.new
    err = StringIO.new
    status = RaihaInterop::Runner.run(
      env: { "ROLE" => "client", "TESTCASE_CLIENT" => "doesnotexist" },
      stdout: out,
      stderr: err
    )

    assert_equal 127, status
    assert_match(/unsupported testcase/, err.string)
  end

  def test_unknown_role_returns_2
    err = StringIO.new
    status = RaihaInterop::Runner.run(
      env: { "ROLE" => "weird", "TESTCASE_CLIENT" => "handshake" },
      stdout: StringIO.new,
      stderr: err
    )

    assert_equal 2, status
    assert_match(/unknown ROLE/, err.string)
  end

  def test_supported_testcase_list_includes_handshake
    assert RaihaInterop::Testcases.supported?("handshake")
  end

  def test_supported_testcases_extend_to_http3_and_retry
    %w[transfer http3 versionnegotiation retry].each do |name|
      assert RaihaInterop::Testcases.supported?(name), "expected #{name} to be supported"
    end
  end

  def test_retry_requires_retry_flag
    assert RaihaInterop::Testcases.requires_retry?("retry")
    refute RaihaInterop::Testcases.requires_retry?("handshake")
  end

  def test_http3_testcases_request_h3_alpn
    assert RaihaInterop::Testcases.requires_http3?("http3")
    assert RaihaInterop::Testcases.requires_http3?("transfer")
    refute RaihaInterop::Testcases.requires_http3?("handshake")
  end
end
