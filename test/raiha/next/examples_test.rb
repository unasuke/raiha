require "raiha/next/test_helper"
require "open3"
require "rbconfig"

# Each example under examples/next runs in a process of its own and puts
# out what the "Expected output:" of its header comment says. The UDP
# handshake runs a client and a server over real sockets on the loopback
# interface, and so does the loopback of the runtime, under the scheduler
# of async.
class RaihaNextExamplesTest < Minitest::Test
  ROOT = File.expand_path("../../..", __dir__)
  TIMEOUT = 30

  # The lines under "Expected output:" in the header comment of `path`.
  def expected_output(path)
    header = File.readlines(path).take_while { _1.start_with?("#") }
    lines = header.drop_while { !_1.include?("Expected output:") }.drop(1)
    lines.take_while { _1.start_with?("#   ") }.map { _1.delete_prefix("#   ") }.join
  end

  # What `path` puts out, and its status; the process is killed after
  # TIMEOUT seconds.
  def run_example(path)
    Open3.popen2e(RbConfig.ruby, "-I#{File.join(ROOT, "lib")}", path, chdir: ROOT) do |stdin, output, wait|
      stdin.close
      reader = Thread.new { output.read }
      unless wait.join(TIMEOUT)
        Process.kill(:KILL, wait.pid)
        flunk "#{path} did not end in #{TIMEOUT} seconds:\n#{reader.value}"
      end
      [reader.value, wait.value]
    end
  end

  def test_udp_handshake
    path = File.join(ROOT, "examples/next/udp_handshake.rb")
    output, status = run_example(path)
    assert status.success?, output
    assert_equal expected_output(path), output
  end

  def test_high_level_loopback
    path = File.join(ROOT, "examples/next/high_level_loopback.rb")
    output, status = run_example(path)
    assert status.success?, output
    assert_equal expected_output(path), output
  end
end
