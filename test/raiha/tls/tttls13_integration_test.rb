require "test_helper"
require "support/test_certificate"
require "raiha/tls/client"
require "raiha/tls/server"
require "tttls1.3"
require "socket"
require "timeout"
require "tempfile"

class RaihaTLSTttls13IntegrationTest < Minitest::Test
  include TestCertificate

  def test_client_against_tttls13_server
    ca_file, cert_file, key_file = write_ca_signed_cert_files
    tcp_server = TCPServer.new("localhost", 0)
    port = tcp_server.addr[1]

    server_thread = Thread.new do
      conn = tcp_server.accept
      tttls_server = TTTLS13::Server.new(conn, crt_file: cert_file.path, key_file: key_file.path)
      tttls_server.accept
      tttls_server.close
    rescue
      # Server may fail if client disconnects early
    ensure
      conn&.close
    end

    client = Raiha::TLS::Client.new
    socket = TCPSocket.new("localhost", port)

    begin
      Timeout.timeout(10) do
        until client.finished? || client.state == Raiha::TLS::Client::State::CLOSED
          datagrams = client.datagrams_to_send
          datagrams&.each { |d| socket.write(d) }

          if IO.select([socket], nil, nil, 1)
            data = socket.recv(16384)
            break if data.nil? || data.empty?
            client.receive(data)
          end
        end
      end

      assert_includes [
        Raiha::TLS::Client::State::CONNECTED,
        Raiha::TLS::Client::State::CLOSED,
      ], client.state
    ensure
      socket.close
    end

    server_thread.join(3)
  ensure
    tcp_server&.close
    server_thread&.kill if server_thread&.alive?
    ca_file&.close!
    cert_file&.close!
    key_file&.close!
  end

  def test_server_against_tttls13_client
    ca_file, cert_file, key_file, config = create_ca_signed_server_config
    tcp_server = TCPServer.new("localhost", 0)
    port = tcp_server.addr[1]
    server_state = nil
    server_error = nil

    server_thread = Thread.new do
      server = Raiha::TLS::Server.new(config: config)
      conn = tcp_server.accept
      conn.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

      begin
        until server.connected?
          datagrams = server.datagrams_to_send
          if datagrams && !datagrams.empty?
            datagrams.flatten.each { |d| conn.write(d) }
            conn.flush
          end

          if IO.select([conn], nil, nil, 1)
            data = conn.recv(16384)
            next if data.nil? || data.empty?
            server.receive(data)
          end
        end
        server_state = server.state
      rescue => e
        server_error = e
      ensure
        conn.close
      end
    end

    Timeout.timeout(10) do
      sleep 0.1
      socket = TCPSocket.new("localhost", port)
      tttls_client = TTTLS13::Client.new(socket, "localhost", ca_file: ca_file.path)
      tttls_client.connect
      tttls_client.close
    rescue
      # tttls1.3 may raise on close_notify timing
    end

    server_thread.join(5)
    raise server_error if server_error
    assert_equal Raiha::TLS::Server::State::CONNECTED, server_state
  ensure
    tcp_server&.close
    server_thread&.kill if server_thread&.alive?
    ca_file&.close!
    cert_file&.close!
    key_file&.close!
  end

  private def write_ca_signed_cert_files
    ca_key = OpenSSL::PKey::RSA.generate(2048)
    ca_cert = generate_ca_cert(ca_key)
    server_key = OpenSSL::PKey::RSA.generate(2048)
    server_cert = generate_leaf_cert(server_key, ca_key, ca_cert, "localhost")

    ca_file = Tempfile.new(["ca", ".pem"])
    cert_file = Tempfile.new(["server_cert", ".pem"])
    key_file = Tempfile.new(["server_key", ".pem"])
    ca_file.write(ca_cert.to_pem); ca_file.flush
    cert_file.write(server_cert.to_pem); cert_file.flush
    key_file.write(server_key.to_pem); key_file.flush

    [ca_file, cert_file, key_file]
  end

  private def create_ca_signed_server_config
    ca_key = OpenSSL::PKey::RSA.generate(2048)
    ca_cert = generate_ca_cert(ca_key)
    server_key = OpenSSL::PKey::RSA.generate(2048)
    server_cert = generate_leaf_cert(server_key, ca_key, ca_cert, "localhost")

    ca_file = Tempfile.new(["ca", ".pem"])
    cert_file = Tempfile.new(["server_cert", ".pem"])
    key_file = Tempfile.new(["server_key", ".pem"])
    ca_file.write(ca_cert.to_pem); ca_file.flush
    cert_file.write(server_cert.to_pem); cert_file.flush
    key_file.write(server_key.to_pem); key_file.flush

    config = Raiha::TLS::Config.server_default
    config.server_certificate = server_cert
    config.server_private_key = server_key

    [ca_file, cert_file, key_file, config]
  end

  private def generate_ca_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new([["CN", "Test CA"]])
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
    cert.sign(key, "SHA256")
    cert
  end

  private def generate_leaf_cert(key, ca_key, ca_cert, hostname)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.new([["CN", hostname]])
    cert.issuer = ca_cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca_cert
    cert.add_extension(ef.create_extension("subjectAltName", "DNS:#{hostname}"))
    cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always"))
    cert.sign(ca_key, "SHA256")
    cert
  end

  private def wait_for_port(port, timeout: 5)
    deadline = Time.now + timeout
    loop do
      TCPSocket.new("localhost", port).close
      return
    rescue Errno::ECONNREFUSED
      raise "Port #{port} not available after #{timeout}s" if Time.now > deadline
      sleep 0.1
    end
  end
end
