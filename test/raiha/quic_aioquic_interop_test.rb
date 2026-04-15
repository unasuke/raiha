require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "tempfile"
require "securerandom"

class RaihaQuicAioquicInteropTest < Minitest::Test
  include TestCertificate

  AIOQUIC_SERVER_SCRIPT = File.expand_path("../support/aioquic_server.py", __dir__)
  AIOQUIC_CLIENT_SCRIPT = File.expand_path("../support/aioquic_client.py", __dir__)

  def test_raiha_client_to_aioquic_server
    cert_file, key_file = write_cert_files
    port = find_available_udp_port

    server_rd, server_wr = IO.pipe
    server_pid = Process.spawn(
      "uv", "run", "--with", "aioquic", "python3", AIOQUIC_SERVER_SCRIPT,
      "--certfile", cert_file.path,
      "--keyfile", key_file.path,
      "--port", port.to_s,
      out: server_wr, err: server_wr
    )
    server_wr.close

    wait_for_ready(server_rd)

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", 0)

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_connection_id
    )

    Timeout.timeout(10) do
      client_connection.start_handshake

      # Handshake loop
      until client_connection.handshake_complete?
        send_packets(client_connection, client_socket, "127.0.0.1", port)
        receive_packets(client_socket, client_connection)
      end

      # Send stream data
      payload = SecureRandom.random_bytes(64)
      client_connection.send_stream_data(0, payload, fin: true)
      send_packets(client_connection, client_socket, "127.0.0.1", port)

      # Receive echo response
      receive_packets(client_socket, client_connection, timeout: 2.0)

      stream = client_connection.streams.get_stream(0)
      refute_nil stream, "Client should have received response on stream 0"
      assert stream.data_available?, "Stream should have data"
      received = stream.read
      assert_equal "ECHO:".b + payload, received, "Should receive echoed data"
    end

    server_output = server_rd.read_nonblock(4096) rescue ""
    assert_includes server_output, "HANDSHAKE_COMPLETE"
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    client_socket&.close
    cert_file&.close!
    key_file&.close!
  end

  def test_aioquic_client_to_raiha_server
    cert_file, key_file = write_cert_files
    port = find_available_udp_port

    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", port)

    dest_connection_id = Raiha::Quic::Protocol::ConnectionID.generate
    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_connection_id,
      dest_connection_id: dest_connection_id,
      tls_config: create_server_config
    )

    payload = SecureRandom.random_bytes(64)

    client_rd, client_wr = IO.pipe
    client_pid = Process.spawn(
      "uv", "run", "--with", "aioquic", "python3", AIOQUIC_CLIENT_SCRIPT,
      "--host", "127.0.0.1",
      "--port", port.to_s,
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

        packets = server_connection.get_packets_to_send
        packets.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }
      end

      # Receive stream data from aioquic client
      5.times do
        readable = IO.select([server_socket], nil, nil, 1.0)
        next unless readable

        data, addr = server_socket.recvfrom_nonblock(65535)
        client_addr = addr
        server_connection.handle_packet(data)

        packets = server_connection.get_packets_to_send
        packets.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }

        stream = server_connection.streams.get_stream(0)
        break if stream&.data_available?
      end

      stream = server_connection.streams.get_stream(0)
      refute_nil stream, "Server should have received stream 0"
      assert stream.data_available?, "Stream should have data"
      received = stream.read
      assert_equal payload, received, "Server should receive exact data from aioquic client"

      # Echo back
      server_connection.send_stream_data(0, "ECHO:".b + received, fin: true)
      packets = server_connection.get_packets_to_send
      packets.each { |pkt| server_socket.send(pkt, 0, client_addr[3], client_addr[1]) }
    end

    Process.wait(client_pid)
    client_output = client_rd.read
    assert_includes client_output, "HANDSHAKE_COMPLETE"
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
    server_socket&.close
    cert_file&.close!
    key_file&.close!
  end

  private def write_cert_files
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new([["CN", "localhost"]])
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400
    cert.sign(key, "SHA256")

    cert_file = Tempfile.new(["quic_cert", ".pem"])
    key_file = Tempfile.new(["quic_key", ".pem"])
    cert_file.write(cert.to_pem)
    cert_file.flush
    key_file.write(key.to_pem)
    key_file.flush

    [cert_file, key_file]
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
      raise "aioquic server did not become ready" if Time.now > deadline

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
