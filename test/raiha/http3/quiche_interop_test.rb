require "test_helper"
require "raiha/http3"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "tempfile"

class RaihaHTTP3QuicheInteropTest < Minitest::Test
  include TestCertificate

  QUICHE_SERVER = File.expand_path("../../../tmp/quiche/target/release/quiche-server", __dir__)
  QUICHE_WWW = File.expand_path("../../../tmp/quiche-www", __dir__)

  def setup
    skip "quiche-server not found" unless File.executable?(QUICHE_SERVER)
    skip "quiche-www/index.html not found" unless File.exist?(File.join(QUICHE_WWW, "index.html"))
  end

  def test_raiha_http3_client_get_request_to_quiche_server
    cert_file, key_file = write_cert_files
    port = find_available_udp_port

    _server_rd, server_wr = IO.pipe
    server_pid = Process.spawn(
      QUICHE_SERVER,
      "--listen", "127.0.0.1:#{port}",
      "--cert", cert_file.path,
      "--key", key_file.path,
      "--root", QUICHE_WWW,
      "--no-retry",
      out: server_wr, err: server_wr
    )
    server_wr.close
    sleep 0.5

    client_socket = UDPSocket.new
    client_socket.bind("127.0.0.1", 0)

    client_connection = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      alpn_protocols: ["h3"]
    )

    http3_client = Raiha::HTTP3::Client.new(connection: client_connection)

    Timeout.timeout(20) do
      # 1. QUIC handshake
      client_connection.start_handshake
      until client_connection.handshake_complete?
        flush(client_connection, client_socket, port)
        drain(client_socket, client_connection)
      end
      assert client_connection.handshake_complete?

      # 2. HTTP/3 control streams + request
      http3_client.setup_control_stream

      request_stream = http3_client.send_request(
        method: "GET", scheme: "https", authority: "example.com", path: "/index.html"
      )

      expected_body = File.read(File.join(QUICHE_WWW, "index.html"))

      # 3. Drive I/O until response stream has data with FIN
      20.times do
        flush(client_connection, client_socket, port)
        drain(client_socket, client_connection, timeout: 0.5)

        client_side_request_stream = client_connection.streams.get_stream(request_stream.stream_id.value)
        next unless client_side_request_stream&.data_available?

        response = http3_client.receive_response(client_side_request_stream)
        assert_equal 200, response.status
        assert_equal expected_body, response.body
        return
      end

      flunk "Did not receive response from quiche-server in time"
    end
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    client_socket&.close
    cert_file&.close!
    key_file&.close!
  end

  private def flush(connection, socket, port)
    connection.get_packets_to_send.each { |pkt| socket.send(pkt, 0, "127.0.0.1", port) }
  end

  private def drain(socket, connection, timeout: 0.3)
    loop do
      readable = IO.select([socket], nil, nil, timeout)
      break unless readable

      data, = socket.recvfrom_nonblock(65535)
      connection.handle_packet(data)
    rescue IO::WaitReadable
      break
    end
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

    cert_file = Tempfile.new(["h3_cert", ".pem"])
    key_file = Tempfile.new(["h3_key", ".pem"])
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
end
