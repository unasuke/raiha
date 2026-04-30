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
end
