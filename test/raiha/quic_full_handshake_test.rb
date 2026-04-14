require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"

class RaihaQuicFullHandshakeTest < Minitest::Test
  include TestCertificate

  def test_full_handshake_via_crypto_setup
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    src_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: src_connection_id,
      dest_connection_id: dest_connection_id
    )

    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    # 1. Client starts handshake
    client_connection.start_handshake
    client_initial_packets = client_connection.get_packets_to_send
    refute_empty client_initial_packets, "Client should produce Initial packets"

    # 2. Server receives Initial packet
    client_initial_packets.each { |packet| server_connection.handle_packet(packet) }

    server_crypto = server_connection.instance_variable_get(:@crypto_setup)
    assert server_crypto.available?(:handshake), "Server should have handshake keys"

    # 3. Server sends response (Initial + Handshake packets)
    server_packets = server_connection.get_packets_to_send
    refute_empty server_packets, "Server should produce response packets"

    # 4. Client receives server packets
    server_packets.each { |packet| client_connection.handle_packet(packet) }

    client_crypto = client_connection.instance_variable_get(:@crypto_setup)
    assert client_crypto.available?(:one_rtt), "Client should have application keys"

    # 5. Client sends Finished (Handshake packet)
    client_handshake_packets = client_connection.get_packets_to_send
    refute_empty client_handshake_packets, "Client should produce Finished packet"

    # 6. Server receives Finished
    client_handshake_packets.each { |packet| server_connection.handle_packet(packet) }

    assert server_connection.handshake_complete?, "Server handshake should be complete"
    assert client_connection.handshake_complete?, "Client handshake should be complete"
  end

  def test_full_handshake_over_udp
    client_port = find_available_udp_port
    server_port = find_available_udp_port

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", client_port)

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", server_port)

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )

    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    Timeout.timeout(5) do
      # 1. Client → Server: Initial (ClientHello)
      client_connection.start_handshake
      send_packets(client_connection, client_socket, "127.0.0.1", server_port)

      # 2. Server receives and processes
      receive_packets(server_socket, server_connection)

      # 3. Server → Client: Initial (ServerHello) + Handshake (EE+Cert+CV+Fin)
      send_packets(server_connection, server_socket, "127.0.0.1", client_port)

      # 4. Client receives and processes
      receive_packets(client_socket, client_connection)

      # 5. Client → Server: Handshake (Finished)
      send_packets(client_connection, client_socket, "127.0.0.1", server_port)

      # 6. Server receives Finished
      receive_packets(server_socket, server_connection)

      assert client_connection.handshake_complete?, "Client should complete handshake over UDP"
      assert server_connection.handshake_complete?, "Server should complete handshake over UDP"
    end
  ensure
    client_socket&.close
    server_socket&.close
  end

  def test_stream_data_exchange_after_handshake
    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    client_connection, server_connection = complete_handshake(dest_connection_id)

    # Generate random data to exchange
    client_payload = SecureRandom.random_bytes(256)
    server_payload = SecureRandom.random_bytes(256)

    # Client sends stream data to server
    client_connection.send_stream_data(0, client_payload, fin: true)
    client_data_packets = client_connection.get_packets_to_send
    refute_empty client_data_packets, "Client should produce 1-RTT stream data packet"

    client_data_packets.each { |packet| server_connection.handle_packet(packet) }

    # Verify server received the data
    server_stream = server_connection.streams.get_stream(0)
    refute_nil server_stream, "Server should have stream 0"
    assert server_stream.data_available?
    received_from_client = server_stream.read
    assert_equal client_payload, received_from_client, "Server should receive exact data from client"

    # Server sends stream data back to client
    server_connection.send_stream_data(1, server_payload, fin: true)
    server_data_packets = server_connection.get_packets_to_send
    refute_empty server_data_packets, "Server should produce 1-RTT stream data packet"

    server_data_packets.each { |packet| client_connection.handle_packet(packet) }

    # Verify client received the data
    client_stream = client_connection.streams.get_stream(1)
    refute_nil client_stream, "Client should have stream 1"
    assert client_stream.data_available?
    received_from_server = client_stream.read
    assert_equal server_payload, received_from_server, "Client should receive exact data from server"
  end

  def test_stream_data_exchange_over_udp
    client_port = find_available_udp_port
    server_port = find_available_udp_port

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", client_port)

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", server_port)

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )

    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    random_message = SecureRandom.random_bytes(128)

    Timeout.timeout(5) do
      # Complete handshake
      client_connection.start_handshake
      send_packets(client_connection, client_socket, "127.0.0.1", server_port)
      receive_packets(server_socket, server_connection)

      send_packets(server_connection, server_socket, "127.0.0.1", client_port)
      receive_packets(client_socket, client_connection)

      send_packets(client_connection, client_socket, "127.0.0.1", server_port)
      receive_packets(server_socket, server_connection)

      assert client_connection.handshake_complete?
      assert server_connection.handshake_complete?

      # Client sends random data over stream
      client_connection.send_stream_data(0, random_message, fin: true)
      send_packets(client_connection, client_socket, "127.0.0.1", server_port)
      receive_packets(server_socket, server_connection)

      # Verify server received exact bytes
      server_stream = server_connection.streams.get_stream(0)
      refute_nil server_stream
      received = server_stream.read
      assert_equal random_message, received,
        "Data should survive encryption, UDP transport, and decryption unchanged"
    end
  ensure
    client_socket&.close
    server_socket&.close
  end

  private def complete_handshake(dest_connection_id)
    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )
    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    client_connection.start_handshake
    client_connection.get_packets_to_send.each { |p| server_connection.handle_packet(p) }
    server_connection.get_packets_to_send.each { |p| client_connection.handle_packet(p) }
    client_connection.get_packets_to_send.each { |p| server_connection.handle_packet(p) }

    [client_connection, server_connection]
  end

  private def send_packets(connection, socket, host, port)
    packets = connection.get_packets_to_send
    packets.each { |packet| socket.send(packet, 0, host, port) }
  end

  private def receive_packets(socket, connection)
    loop do
      readable = IO.select([socket], nil, nil, 0.1)
      break unless readable

      data, = socket.recvfrom_nonblock(65535)
      connection.handle_packet(data)
    rescue IO::WaitReadable
      break
    end
  end

  private def find_available_udp_port
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    socket.close
    port
  end
end
