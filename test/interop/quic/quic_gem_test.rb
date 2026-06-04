require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "tempfile"
require "securerandom"

# Interop tests between the quic gem (github: unasuke/quic-ruby, a thin ngtcp2
# + LibreSSL binding) acting as the client and raiha acting as the server. The
# quic gem ships a client only, so this is the sole possible direction.
#
# The quic gem owns its own blocking I/O loop (Client#bind(sock).run,
# Stream#read), so it is driven in a subprocess (test/support/quic_gem_echo_client.rb)
# over loopback UDP while raiha is pumped in this process, mirroring the
# aioquic / quiche interop tests.
class RaihaQuicGemInteropTest < Minitest::Test
  include TestCertificate

  QUIC_GEM_ECHO_CLIENT = File.expand_path("../../support/quic_gem_echo_client.rb", __dir__)
  ALPN = "raiha-interop"

  def setup
    require "quic"
  rescue LoadError
    skip "quic gem not installed (run: bundle install --with interop)"
  end

  def test_quic_gem_client_handshake_to_raiha_server
    port = find_available_udp_port

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", port)

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config,
      alpn_protocols: [ALPN]
    )

    client_rd, client_wr = IO.pipe
    client_pid = Process.spawn(
      "bundle", "exec", "ruby", QUIC_GEM_ECHO_CLIENT,
      "--host", "127.0.0.1",
      "--port", port.to_s,
      "--alpn", ALPN,
      out: client_wr, err: client_wr
    )
    client_wr.close

    Timeout.timeout(10) do
      until server_connection.handshake_complete?
        readable = IO.select([server_socket], nil, nil, 0.5)
        next unless readable

        data, addr = server_socket.recvfrom_nonblock(65535)
        server_connection.handle_packet(data)

        server_connection.get_packets_to_send.each { |pkt| server_socket.send(pkt, 0, addr[3], addr[1]) }
      end
    end

    Process.wait(client_pid)
    assert_equal 0, $?.exitstatus, "quic gem client should exit cleanly"
    client_output = client_rd.read
    assert_includes client_output, "HANDSHAKE_COMPLETE"
    assert server_connection.handshake_complete?, "raiha server should complete the handshake"
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
    server_socket&.close
  end

  def test_quic_gem_client_stream_echo_to_raiha_server
    # The raiha server side of this round trip is correct: it receives the
    # client's stream data and replies with STREAM(id=0, off=0, fin) carrying
    # "ECHO:"+payload, which an aioquic client receives intact. The quic gem
    # (unasuke/quic-ruby) client, however, does not yet surface server->client
    # stream data through Stream#read -- it ACKs raiha's 1-RTT echo packet but
    # never reports EOF, and the same Stream#read hangs even against an aioquic
    # echo server. Re-enable this test once quic-ruby implements reading
    # peer-sent stream data on a client-initiated bidi stream.
    skip "quic gem (quic-ruby) client cannot yet read server-initiated stream data (verified against aioquic too)"

    port = find_available_udp_port

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", port)

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config,
      alpn_protocols: [ALPN]
    )

    payload = SecureRandom.random_bytes(64)

    client_rd, client_wr = IO.pipe
    client_pid = Process.spawn(
      "bundle", "exec", "ruby", QUIC_GEM_ECHO_CLIENT,
      "--host", "127.0.0.1",
      "--port", port.to_s,
      "--alpn", ALPN,
      "--data", payload.unpack1("H*"),
      out: client_wr, err: client_wr
    )
    client_wr.close

    Timeout.timeout(10) do
      client_addr = nil

      until server_connection.handshake_complete?
        readable = IO.select([server_socket], nil, nil, 0.5)
        next unless readable

        data, addr = server_socket.recvfrom_nonblock(65535)
        client_addr = addr
        server_connection.handle_packet(data)

        server_connection.get_packets_to_send.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }
      end

      # Receive the stream data the quic gem client opened on stream 0.
      5.times do
        readable = IO.select([server_socket], nil, nil, 1.0)
        next unless readable

        data, addr = server_socket.recvfrom_nonblock(65535)
        client_addr = addr
        server_connection.handle_packet(data)

        server_connection.get_packets_to_send.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }

        stream = server_connection.streams.get_stream(0)
        break if stream&.data_available?
      end

      stream = server_connection.streams.get_stream(0)
      refute_nil stream, "Server should have received stream 0"
      assert stream.data_available?, "Stream should have data"
      received = stream.read
      assert_equal payload, received, "raiha should receive the exact bytes the quic gem client sent"

      # Echo back on the same client-initiated bidi stream and FIN it.
      server_connection.send_stream_data(0, "ECHO:".b + received, fin: true)
      server_connection.get_packets_to_send.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }
    end

    Process.wait(client_pid)
    assert_equal 0, $?.exitstatus, "quic gem client should exit cleanly after the echo round trip"
    client_output = client_rd.read
    assert_includes client_output, "HANDSHAKE_COMPLETE"
    assert_includes client_output, "ECHO_OK"
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
    server_socket&.close
  end

  private def find_available_udp_port
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    socket.close
    port
  end
end
