require "raiha/next/test_helper"
require "raiha/next/support/quic_udp"
require "fileutils"

# The handshake of the next release of raiha over UDP against quic-go,
# both ways: a client against quic-go's server with a certificate of the
# test CA, a server against quic-go's client. Both programs print
# HANDSHAKE_COMPLETE when their handshake is done; what each goes on to do
# with a stream is not waited for.
class NextQUICQuicgoInteropTest < Minitest::Test
  include NextQUICUDP

  SERVER = File.expand_path("../../../support/quicgo/server_bin", __dir__)
  CLIENT = File.expand_path("../../../support/quicgo/client_bin", __dir__)
  ALPN = ["quic-echo"].freeze

  def setup
    skip "quic-go server not found" unless File.executable?(SERVER)
    skip "quic-go client not found" unless File.executable?(CLIENT)
    @dir = Dir.mktmpdir("next-interop-quicgo-", TMP)
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def test_client_against_quicgo_server
    port = free_port
    peer(SERVER, port.to_s, *certificate_files(@dir)) do |output|
      assert wait_for(output, "READY"), output
      client(port, alpn: ALPN) do |socket, connection|
        done = drive(socket, connection) { (connection.handshake_confirmed? && output.include?("HANDSHAKE_COMPLETE")) || connection.closed? }
        assert done, output
        assert connection.handshake_confirmed?, "#{connection.close_reason.inspect}\n#{output}"
      end
    end
  end

  def test_server_against_quicgo_client
    server(alpn: ALPN) do |socket, server|
      peer(CLIENT, "127.0.0.1:#{socket.addr[1]}", "00") do |output|
        done = drive(socket, server) { server.connections.any?(&:handshake_complete?) && output.include?("HANDSHAKE_COMPLETE") }
        assert done, output
      end
    end
  end
end
