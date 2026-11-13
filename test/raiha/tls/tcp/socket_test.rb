require "test_helper"
require "support/tcp_pair"
require "socket"
require "timeout"

class RaihaTLSTCPSocketTest < Minitest::Test
  TLS = Raiha::TLS

  # Runs `serve` with the socket a server thread accepts, yields the port
  # to the client, and returns what `serve` returned or raised.
  def with_server(serve, config: TLSPair.server_config(alpn: ["echo"]))
    listener = TCPServer.new("localhost", 0)
    keyring = TLSPair.server_keyring(config:)
    result = Thread::Queue.new
    thread = Thread.new do
      result << TLS::TCP::Socket.accept(listener, config:, keyring:) { |sock| serve.call(sock) }
    rescue StandardError => e
      result << e
    end
    Timeout.timeout(10) { yield listener.addr[1] }
    thread.join(10)
    result.pop(timeout: 0)
  ensure
    listener&.close
    thread&.kill
  end

  def connect(port, config: TLSPair.client_config(alpn: ["echo"]), &)
    TLS::TCP::Socket.connect("localhost", port, config:, keyring: TLS::Keyring.client(config:), &)
  end

  def test_echo
    serve = ->(sock) { [sock.read(100).tap { |data| sock.write(data.upcase) }, sock.read(100)] }
    served = with_server(serve) do |port|
      connect(port) do |sock|
        assert_equal "echo", sock.alpn
        refute_empty sock.peer_certificates
        assert_equal 4, sock.write("ping")
        assert_equal "PING", sock.read(100)
      end
    end
    # The server read nil once the client's close_notify came.
    assert_equal ["ping", nil], served
  end

  # A client that trusts another CA: CertificateError here, and the alert
  # it sends is the server's AlertError.
  def test_certificate_error
    other = TestPKI.ca(name: "Other CA", key: TestPKI.key(:other_ca))
    config = TLS::Config.client(trust_anchors: [other.der], alpn: ["echo"])
    served = with_server(->(sock) { sock.read(1) }) do |port|
      error = assert_raises(TLS::CertificateError) { connect(port, config:) }
      assert_equal :unknown_ca, error.alert
    end
    assert_instance_of TLS::AlertError, served
    assert_equal 48, served.description
  end

  # TCP closed without close_notify may have cut the data short.
  def test_eof_without_close_notify
    serve = lambda do |sock|
      sock.write("partial")
      sock.instance_variable_get(:@io).close
      :closed
    end
    served = with_server(serve) do |port|
      sock = connect(port)
      assert_equal "partial", sock.read(100)
      assert_raises(EOFError) { sock.read(100) }
      sock.close
    end
    assert_equal :closed, served
  end
end
