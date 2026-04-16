require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"

class RaihaQuicQuicgoInteropTest < Minitest::Test
  include TestCertificate

  QUICGO_SERVER = File.expand_path("../support/quicgo/server_bin", __dir__)
  QUICGO_CLIENT = File.expand_path("../support/quicgo/client_bin", __dir__)

  def setup
    skip "quic-go server not found" unless File.executable?(QUICGO_SERVER)
    skip "quic-go client not found" unless File.executable?(QUICGO_CLIENT)
  end

  def test_raiha_client_to_quicgo_server
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

    Timeout.timeout(10) do
      client_connection.start_handshake

      until client_connection.handshake_complete?
        send_packets(client_connection, client_socket, "127.0.0.1", port)
        receive_packets(client_socket, client_connection)
      end

      assert client_connection.handshake_complete?, "Handshake with quic-go should complete"
    end
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    client_socket&.close
  end

  def test_quicgo_client_to_raiha_server
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
    rescue IO::WaitReadable
      break
    end
  end
end
