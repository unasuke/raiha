require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"
require "raiha/next/tls"
require "socket"
require "timeout"
require "tmpdir"
require "tttls1.3"

# The next release of raiha over TCP against tttls1.3, a TLS 1.3 in Ruby,
# both ways, in one process.
class NextTLSTttls13InteropTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTLSPair
  PKI = NextTestPKI
  TMP = File.expand_path("../../../../tmp", __dir__)

  def setup
    @dir = Dir.mktmpdir("next-interop-tttls13-", TMP)
    leaf = PKI.leaf(Pair.ca)
    @ca_file = write("ca.pem", Pair.ca.certificate.to_pem)
    @cert_file = write("cert.pem", leaf.certificate.to_pem)
    @key_file = write("key.pem", leaf.key.private_to_pem)
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def write(name, contents) = File.join(@dir, name).tap { |path| File.write(path, contents) }

  # Runs `serve` in a thread with the next connection on a listener, yields
  # its port, and returns what `serve` returned or raised.
  def with_listener(serve)
    listener = TCPServer.new("127.0.0.1", 0)
    result = Thread::Queue.new
    thread = Thread.new do
      result << serve.call(listener)
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

  def test_client_against_tttls13_server
    serve = lambda do |listener|
      socket = listener.accept
      server = TTTLS13::Server.new(socket, crt_file: @cert_file, key_file: @key_file)
      server.accept
      data = server.read
      server.write(data.upcase)
      server.close
      data
    ensure
      socket&.close
    end
    served = with_listener(serve) do |port|
      config = Pair.client_config
      TLS::TCP::Socket.connect("127.0.0.1", port, server_name: "localhost", config:, keyring: TLS::Keyring.client(config:)) do |sock|
        sock.write("hello tttls1.3")
        assert_equal "HELLO TTTLS1.3", sock.read(100)
      end
    end
    assert_equal "hello tttls1.3", served
  end

  # tttls1.3's client asks for records of 1,000 bytes at most (RFC 8449),
  # and gets them.
  def test_server_against_tttls13_client
    config = Pair.server_config
    keyring = Pair.server_keyring(config:)
    serve = lambda do |listener|
      TLS::TCP::Socket.accept(listener, config:, keyring:) do |sock|
        data = sock.read(100)
        sock.write(data * 300)
        data
      end
    end
    served = with_listener(serve) do |port|
      socket = TCPSocket.new("127.0.0.1", port)
      client = TTTLS13::Client.new(socket, "localhost", ca_file: @ca_file, record_size_limit: 1000)
      client.connect
      client.write("0123456789")
      received = +""
      received << client.read until received.bytesize >= 3000 || client.eof?
      assert_equal "0123456789" * 300, received
      client.close
    ensure
      socket&.close
    end
    assert_equal "0123456789", served
  end
end
