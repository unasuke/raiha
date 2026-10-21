require "raiha/next/test_helper"
require "raiha/next/support/quic_udp"
require "fileutils"

# The next release of raiha over UDP against aioquic, both ways: a client
# against aioquic's server with a certificate of the test CA, a server
# against aioquic's client, which closes once its handshake is done unless
# it has data to send. Both scripts print HANDSHAKE_COMPLETE then. The
# server answers the stream the client opens with "ECHO:" and what came on
# it, and aioquic's client prints what came back as STREAM_DATA. uv
# fetches aioquic when it first runs.
class NextQUICAioquicInteropTest < Minitest::Test
  include NextQUICUDP

  SERVER = File.expand_path("../../../support/aioquic_server.py", __dir__)
  CLIENT = File.expand_path("../../../support/aioquic_client.py", __dir__)
  PYTHON = %w[uv run --with aioquic python3].freeze
  ALPN = ["hq-interop"].freeze
  PAYLOAD = Random.new(1).bytes(20_000)

  def setup
    skip "uv not found" unless system("uv", "--version", out: File::NULL, err: File::NULL)
    @dir = Dir.mktmpdir("next-interop-aioquic-", TMP)
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_client_against_aioquic_server
    port = free_port
    chain, key = certificate_files(@dir)
    peer(*PYTHON, SERVER, "--certfile", chain, "--keyfile", key, "--port", port.to_s, "--alpn", ALPN.first) do |output|
      assert wait_for(output, "READY"), output
      client(port, alpn: ALPN) do |socket, connection|
        done = drive(socket, connection) { (connection.handshake_confirmed? && output.include?("HANDSHAKE_COMPLETE")) || connection.closed? }
        assert done, output
        assert connection.handshake_confirmed?, "#{connection.close_reason.inspect}\n#{output}"
      end
    end
  end

  def test_server_against_aioquic_client
    server(alpn: ALPN) do |socket, server|
      peer(*PYTHON, CLIENT, "--port", socket.addr[1].to_s, "--alpn", ALPN.first) do |output|
        done = drive(socket, server, seconds: 60) { server.connections.any?(&:handshake_complete?) && output.include?("HANDSHAKE_COMPLETE") }
        assert done, output
      end
    end
  end

  def test_echo_from_aioquic_server
    port = free_port
    chain, key = certificate_files(@dir)
    peer(*PYTHON, SERVER, "--certfile", chain, "--keyfile", key, "--port", port.to_s, "--alpn", ALPN.first) do |output|
      assert wait_for(output, "READY"), output
      client(port, alpn: ALPN) do |socket, connection|
        echo = EchoClient.new(connection, PAYLOAD)
        assert drive(socket, connection) { echo.step }, output
        assert_equal "ECHO:".b + PAYLOAD, echo.received, "#{connection.close_reason.inspect}\n#{output}"
      end
    end
  end

  def test_echo_to_aioquic_client
    server(alpn: ALPN) do |socket, server|
      echo = EchoServer.new(server)
      peer(*PYTHON, CLIENT, "--port", socket.addr[1].to_s, "--alpn", ALPN.first, "--data", PAYLOAD.unpack1("H*")) do |output|
        done = drive(socket, server, seconds: 60) do
          echo.step
          output.include?("STREAM_DATA:")
        end
        assert done, output
        assert_includes output, "STREAM_DATA:#{("ECHO:".b + PAYLOAD).unpack1("H*")}\n"
      end
    end
  end
end
