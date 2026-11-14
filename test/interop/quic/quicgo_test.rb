require "test_helper"
require "support/quic_udp"
require "fileutils"

# raiha over UDP against quic-go, both ways: a client
# against quic-go's server with a certificate of the test CA, a server
# against quic-go's client. Both programs print HANDSHAKE_COMPLETE when
# their handshake is done; the echo of a stream goes on from there. The
# server answers the stream the client opens with "ECHO:" and what came on
# it, and quic-go's client prints what came back as STREAM_DATA. For
# resumption, quic-go's programs connect or take connections twice and
# print, for each, whether it resumed and 0-RTT was taken.
class QUICQuicgoInteropTest < Minitest::Test
  include QUICUDP

  SERVER = File.expand_path("../../support/quicgo/server_bin", __dir__)
  CLIENT = File.expand_path("../../support/quicgo/client_bin", __dir__)
  RESUME_SERVER = File.expand_path("../../support/quicgo/resume_server_bin", __dir__)
  RESUME_CLIENT = File.expand_path("../../support/quicgo/resume_client_bin", __dir__)
  ALPN = ["quic-echo"].freeze
  PAYLOAD = Random.new(1).bytes(20_000)

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

  def test_echo_from_quicgo_server
    port = free_port
    peer(SERVER, port.to_s, *certificate_files(@dir)) do |output|
      assert wait_for(output, "READY"), output
      client(port, alpn: ALPN) do |socket, connection|
        echo = EchoClient.new(connection, PAYLOAD)
        assert drive(socket, connection) { echo.step }, output
        assert_equal "ECHO:".b + PAYLOAD, echo.received, "#{connection.close_reason.inspect}\n#{output}"
      end
    end
  end

  def test_echo_to_quicgo_client
    server(alpn: ALPN) do |socket, server|
      echo = EchoServer.new(server)
      peer(CLIENT, "127.0.0.1:#{socket.addr[1]}", PAYLOAD.unpack1("H*")) do |output|
        done = drive(socket, server) do
          echo.step
          output.include?("STREAM_DATA:")
        end
        assert done, output
        assert_includes output, "STREAM_DATA:#{("ECHO:".b + PAYLOAD).unpack1("H*")}\n"
      end
    end
  end

  # A ticket of quic-go's server resumes, and the echo goes in 0-RTT, which
  # the server takes.
  def test_resumption_and_0rtt_against_quicgo_server
    skip "quic-go resumption server not found" unless File.executable?(RESUME_SERVER)
    port = free_port
    peer(RESUME_SERVER, port.to_s, *certificate_files(@dir)) do |output|
      assert wait_for(output, "READY"), output
      ticket = client(port, alpn: ALPN) do |socket, connection|
        echo = EchoClient.new(connection, PAYLOAD)
        assert drive(socket, connection) { echo.step && echo.tickets.any? }, output
        echo.tickets.last
      end
      client(port, alpn: ALPN, session: ticket, early_data: true) do |socket, connection|
        assert_equal :pending, connection.zero_rtt_state
        echo = EchoClient.new(connection, PAYLOAD, early: true)
        assert drive(socket, connection) { echo.step && echo.handshake }, output
        assert_equal ["ECHO:".b + PAYLOAD, true, :accepted], [echo.received, echo.handshake.resumed, connection.zero_rtt_state],
          "#{connection.close_reason.inspect}\n#{output}"
      end
      assert wait_for(output, "CONNECTION resumed=true early=true", seconds: 5), output
    end
  end

  # quic-go's client resumes a ticket of ours, and its 0-RTT is taken; its
  # second Initial carries the NEW_TOKEN token of the first connection,
  # which validates its address.
  def test_resumption_and_0rtt_to_quicgo_client
    skip "quic-go resumption client not found" unless File.executable?(RESUME_CLIENT)
    server(alpn: ALPN, resumption: true) do |socket, server|
      validated = []
      server.define_singleton_method(:dispatch) do |route, now|
        validated << route.address_validated if route.is_a?(QUIC::Route::Incoming)
        super(route, now)
      end
      echo = EchoServer.new(server)
      peer(RESUME_CLIENT, "127.0.0.1:#{socket.addr[1]}", PAYLOAD.unpack1("H*")) do |output|
        done = drive(socket, server, seconds: 20) do
          echo.step
          output.scan("CONNECTION ").size == 2
        end
        assert done, output
        connections = output.lines.grep(/\ACONNECTION /)
        assert_equal ["resumed=false early=false", "resumed=true early=true"], connections.map { _1[/resumed=\S+ early=\S+/] }, output
        assert(connections.all? { _1.include?("data=#{("ECHO:".b + PAYLOAD).unpack1("H*")}") }, output)
        assert_equal [false, true], validated
      end
    end
  end
end
