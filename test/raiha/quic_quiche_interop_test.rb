require "test_helper"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "tempfile"

class RaihaQuicQuicheInteropTest < Minitest::Test
  include TestCertificate

  QUICHE_SERVER = File.expand_path("../../tmp/quiche/target/release/quiche-server", __dir__)

  def setup
    skip "quiche-server not found" unless File.executable?(QUICHE_SERVER)
  end

  def test_raiha_client_handshake_with_quiche_server
    cert_file, key_file = write_cert_files
    port = find_available_udp_port

    _server_rd, server_wr = IO.pipe
    _server_err_rd, server_err_wr = IO.pipe
    server_pid = Process.spawn(
      QUICHE_SERVER,
      "--listen", "127.0.0.1:#{port}",
      "--cert", cert_file.path,
      "--key", key_file.path,
      "--no-retry",
      out: server_wr, err: server_err_wr
    )
    server_wr.close
    server_err_wr.close
    sleep 0.5

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", 0)

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      alpn_protocols: ["h3"]
    )

    Timeout.timeout(10) do
      client_connection.start_handshake

      until client_connection.handshake_complete?
        send_packets(client_connection, client_socket, "127.0.0.1", port)
        receive_packets(client_socket, client_connection)
      end
    end

    assert client_connection.handshake_complete?, "Handshake with quiche-server should complete"
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    client_socket&.close
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

    cert_file = Tempfile.new(["quiche_cert", ".pem"])
    key_file = Tempfile.new(["quiche_key", ".pem"])
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
