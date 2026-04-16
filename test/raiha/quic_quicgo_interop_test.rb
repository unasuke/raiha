require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "securerandom"

class RaihaQuicQuicgoInteropTest < Minitest::Test
  include TestCertificate

  QUICGO_SERVER = File.expand_path("../support/quicgo/server_bin", __dir__)
  QUICGO_CLIENT = File.expand_path("../support/quicgo/client_bin", __dir__)

  def setup
    skip "quic-go server not found" unless File.executable?(QUICGO_SERVER)
    skip "quic-go client not found" unless File.executable?(QUICGO_CLIENT)
  end

  def test_raiha_client_handshake_and_stream_with_quicgo_server
    port = find_available_udp_port

    server_rd, server_wr = IO.pipe
    server_pid = Process.spawn(
      QUICGO_SERVER, port.to_s,
      out: server_wr, err: server_wr
    )
    server_wr.close

    wait_for_ready(server_rd)

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", 0)

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      alpn_protocols: ["quic-echo"]
    )

    Timeout.timeout(30) do
      client_connection.start_handshake

      until client_connection.handshake_complete?
        send_packets(client_connection, client_socket, "127.0.0.1", port)
        receive_packets(client_socket, client_connection)
        # Send any pending ACKs/Finished immediately after receiving
        send_packets(client_connection, client_socket, "127.0.0.1", port)
      end

      assert client_connection.handshake_complete?, "Handshake with quic-go should complete"

      # Send stream data along with any pending frames (e.g., client Finished)
      payload = SecureRandom.random_bytes(64)
      client_connection.send_stream_data(0, payload, fin: true)
      send_packets(client_connection, client_socket, "127.0.0.1", port)

      # Receive echo response (quic-go may send HANDSHAKE_DONE and keepalive before stream data)
      receive_until_stream_data(client_socket, client_connection, "127.0.0.1", port, stream_id: 0)

      stream = client_connection.streams.get_stream(0)
      refute_nil stream, "Client should have received response on stream 0"
      assert stream.data_available?, "Stream should have data"
      received = stream.read
      assert_equal "ECHO:".b + payload, received, "Should receive echoed data"
    end
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    client_socket&.close
  end

  def test_quicgo_client_handshake_with_raiha_server
    port = find_available_udp_port

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", port)

    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      tls_config: create_server_config,
      alpn_protocols: ["quic-echo"]
    )

    payload = SecureRandom.random_bytes(64)

    client_rd, client_wr = IO.pipe
    client_pid = Process.spawn(
      QUICGO_CLIENT,
      "127.0.0.1:#{port}",
      payload.unpack1("H*"),
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

        packets = server_connection.get_packets_to_send
        packets.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }
      end

      assert server_connection.handshake_complete?, "Handshake with quic-go client should complete"
    end
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

  private def wait_for_ready(io, timeout: 10)
    deadline = Time.now + timeout
    loop do
      raise "quic-go server did not become ready" if Time.now > deadline

      readable = IO.select([io], nil, nil, 0.5)
      next unless readable

      line = io.gets
      return if line&.include?("READY")
    end
  end

  private def send_packets(connection, socket, host, port)
    packets = connection.get_packets_to_send
    packets.each { |packet| socket.send(packet, 0, host, port) }
  end

  private def receive_packets(socket, connection, timeout: 0.5)
    loop do
      readable = IO.select([socket], nil, nil, timeout)
      break unless readable

      data, = socket.recvfrom_nonblock(65535)
      connection.handle_packet(data)
      # Break if handshake just completed so we can respond quickly
      break if connection.handshake_complete?
    rescue IO::WaitReadable
      break
    end
  end

  # Receive packets and send ACKs back until the specified stream has data or max iterations
  private def receive_until_stream_data(socket, connection, host, port, stream_id:, max_iterations: 40, timeout: 0.5)
    max_iterations.times do
      readable = IO.select([socket], nil, nil, timeout)
      unless readable
        send_packets(connection, socket, host, port)
        next
      end

      data, = socket.recvfrom_nonblock(65535)
      connection.handle_packet(data)
      send_packets(connection, socket, host, port)

      stream = connection.streams.get_stream(stream_id)
      return if stream&.data_available?
    rescue IO::WaitReadable
      next
    end
  end
end
