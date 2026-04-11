require "test_helper"
require "support/test_certificate"
require "raiha/tls/client"
require "raiha/tls/server"
require "socket"
require "timeout"
require "tempfile"

class RaihaTLSOpenSSLIntegrationTest < Minitest::Test
  include TestCertificate

  def test_client_against_openssl_s_server
    cert_file, key_file = write_cert_files
    port = find_available_port

    server_pid = Process.spawn(
      "openssl", "s_server",
      "-accept", port.to_s,
      "-cert", cert_file.path,
      "-key", key_file.path,
      "-tls1_3",
      "-www",
      out: File::NULL, err: File::NULL
    )

    Timeout.timeout(10) do
      wait_for_port(port)

      client = Raiha::TLS::Client.new
      socket = TCPSocket.new("localhost", port)

      begin
        loop do
          break if client.finished?

          datagrams = client.datagrams_to_send
          datagrams&.each { |d| socket.write(d) }

          if IO.select([socket], nil, nil, 1)
            data = socket.recv(16384)
            break if data.nil? || data.empty?
            client.receive(data)
          end
        end

        assert_equal Raiha::TLS::Client::State::CONNECTED, client.state
      ensure
        socket.close
      end
    end
  ensure
    Process.kill("TERM", server_pid) if server_pid rescue nil
    Process.wait(server_pid) if server_pid rescue nil
    cert_file&.close!
    key_file&.close!
  end

  def test_server_against_openssl_s_client
    config = create_server_config_for_openssl
    tcp_server = TCPServer.new("localhost", 0)
    port = tcp_server.addr[1]
    server_state = nil
    server_error = nil
    client_pid = nil

    Timeout.timeout(10) do
      # Launch openssl s_client in background
      client_pid = Process.spawn(
        "openssl", "s_client",
        "-connect", "localhost:#{port}",
        "-tls1_3",
        "-no_ticket",
        "-groups", "prime256v1",
        in: File::NULL, out: File::NULL, err: File::NULL
      )

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
      ensure
        conn.close
      end
    end

    assert_equal Raiha::TLS::Server::State::CONNECTED, server_state
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
    tcp_server&.close
  end

  private def create_server_config_for_openssl
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = generate_server_cert(key, "localhost")

    config = Raiha::TLS::Config.server_default
    config.server_certificate = cert
    config.server_private_key = key
    config
  end

  private def write_cert_files
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = generate_server_cert(key, "localhost")

    cert_file = Tempfile.new(["server_cert", ".pem"])
    key_file = Tempfile.new(["server_key", ".pem"])
    cert_file.write(cert.to_pem)
    cert_file.flush
    key_file.write(key.to_pem)
    key_file.flush

    [cert_file, key_file]
  end

  private def generate_server_cert(key, hostname)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new([["CN", hostname]])
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("subjectAltName", "DNS:#{hostname}"))
    cert.sign(key, "SHA256")
    cert
  end

  private def find_available_port
    server = TCPServer.new("localhost", 0)
    port = server.addr[1]
    server.close
    port
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
