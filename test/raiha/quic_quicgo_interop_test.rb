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

  def test_raiha_client_handshake_with_quicgo_server
    with_quicgo_server do |port, client_socket|
      client_connection = build_raiha_client

      Timeout.timeout(15) do
        complete_handshake_as_client(client_connection, client_socket, port)
        assert client_connection.handshake_complete?, "Handshake with quic-go should complete"
      end
    end
  end

  def test_raiha_client_stream_exchange_with_quicgo_server
    with_quicgo_server do |port, client_socket|
      client_connection = build_raiha_client

      Timeout.timeout(30) do
        complete_handshake_as_client(client_connection, client_socket, port)

        payload = SecureRandom.random_bytes(64)
        client_connection.send_stream_data(0, payload, fin: true)
        send_packets(client_connection, client_socket, "127.0.0.1", port)

        receive_until_stream_data(client_socket, client_connection, "127.0.0.1", port, stream_id: 0)

        stream = client_connection.streams.get_stream(0)
        refute_nil stream, "Client should have received response on stream 0"
        assert stream.data_available?, "Stream should have data"
        assert_equal "ECHO:".b + payload, stream.read, "Should receive echoed data"
      end
    end
  end

  def test_quicgo_client_handshake_with_raiha_server
    server_socket, server_connection = build_raiha_server
    port = server_socket.addr[1]

    payload = SecureRandom.random_bytes(16)
    client_pid, client_rd = spawn_quicgo_client(port, payload)

    Timeout.timeout(15) do
      complete_handshake_as_server(server_connection, server_socket)
      assert server_connection.handshake_complete?, "Handshake with quic-go client should complete"
    end
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
    server_socket&.close
  end

  def test_quicgo_client_stream_exchange_with_raiha_server
    server_socket, server_connection = build_raiha_server
    port = server_socket.addr[1]

    payload = SecureRandom.random_bytes(64)
    client_pid, client_rd = spawn_quicgo_client(port, payload)

    Timeout.timeout(30) do
      client_addr = complete_handshake_as_server(server_connection, server_socket)

      received = receive_stream_data_as_server(server_connection, server_socket, stream_id: 0)
      assert_equal payload, received, "Server should receive exact data from quic-go client"

      # Echo back
      server_connection.send_stream_data(0, "ECHO:".b + received, fin: true)
      send_to(server_socket, server_connection.get_packets_to_send, client_addr)

      # Keep connection alive so quic-go client can receive the echo
      drive_server_until_client_exits(server_socket, server_connection, client_pid, client_addr)
    end

    client_output = client_rd.read rescue ""
    assert_includes client_output, "STREAM_DATA:#{("ECHO:".b + payload).unpack1("H*")}",
                    "quic-go client should have received echoed data"
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
    server_socket&.close
  end

  private def with_quicgo_server
    port = find_available_udp_port
    server_rd, server_wr = IO.pipe
    server_pid = Process.spawn(QUICGO_SERVER, port.to_s, out: server_wr, err: server_wr)
    server_wr.close
    wait_for_ready(server_rd)

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", 0)
    yield port, client_socket
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    client_socket&.close
  end

  private def build_raiha_client
    Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      alpn_protocols: ["quic-echo"]
    )
  end

  private def build_raiha_server
    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", 0)
    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      tls_config: create_server_config,
      alpn_protocols: ["quic-echo"]
    )
    [server_socket, server_connection]
  end

  private def spawn_quicgo_client(port, payload)
    client_rd, client_wr = IO.pipe
    client_pid = Process.spawn(
      QUICGO_CLIENT, "127.0.0.1:#{port}", payload.unpack1("H*"),
      out: client_wr, err: client_wr
    )
    client_wr.close
    [client_pid, client_rd]
  end

  private def complete_handshake_as_client(connection, socket, port)
    connection.start_handshake
    until connection.handshake_complete?
      send_packets(connection, socket, "127.0.0.1", port)
      receive_packets(socket, connection)
      send_packets(connection, socket, "127.0.0.1", port)
    end
  end

  private def complete_handshake_as_server(connection, socket)
    client_addr = nil
    until connection.handshake_complete?
      readable = IO.select([socket], nil, nil, 0.5)
      next unless readable

      data, addr = socket.recvfrom_nonblock(65535)
      client_addr = addr
      connection.handle_packet(data)
      send_to(socket, connection.get_packets_to_send, client_addr)
    end
    client_addr
  end

  private def receive_stream_data_as_server(connection, socket, stream_id:, max_iterations: 40)
    max_iterations.times do
      readable = IO.select([socket], nil, nil, 0.5)
      next unless readable

      data, addr = socket.recvfrom_nonblock(65535)
      connection.handle_packet(data)
      send_to(socket, connection.get_packets_to_send, addr)

      stream = connection.streams.get_stream(stream_id)
      return stream.read if stream&.data_available?
    end
    nil
  end

  private def drive_server_until_client_exits(socket, connection, client_pid, client_addr, max_iterations: 40)
    max_iterations.times do
      # Check if client has exited
      exited = Process.wait(client_pid, Process::WNOHANG) rescue nil
      return if exited

      readable = IO.select([socket], nil, nil, 0.3)
      if readable
        data, addr = socket.recvfrom_nonblock(65535) rescue next
        connection.handle_packet(data)
        send_to(socket, connection.get_packets_to_send, addr)
      else
        send_to(socket, connection.get_packets_to_send, client_addr)
      end
    end
  end

  private def send_to(socket, packets, addr)
    packets.each { |pkt| socket.send(pkt, 0, addr[3], addr[1]) }
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
