require "test_helper"
require "fileutils"
require "support/tls_pair"
require "raiha/tls"
require "open3"
require "socket"
require "timeout"
require "tmpdir"

# The next release of raiha over TCP against the openssl command, both
# ways: a client against `openssl s_server`, a server against
# `openssl s_client`. OpenSSL is a RFC 8446 implementation, so these also
# check that what RFC 8446 allowed and RFC 9846 does not is taken.
class TLSOpenSSLInteropTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = TLSPair
  PKI = TestPKI
  # tmp/ is not in git, so a fresh checkout has none.
  TMP = File.expand_path("../../../tmp", __dir__).tap { |dir| FileUtils.mkdir_p(dir) }

  def setup
    skip "openssl command not found" unless system("openssl", "version", out: File::NULL, err: File::NULL)
    @dir = Dir.mktmpdir("next-interop-openssl-", TMP)
    leaf = PKI.leaf(Pair.ca)
    @ca_file = write("ca.pem", Pair.ca.certificate.to_pem)
    @cert_file = write("cert.pem", leaf.certificate.to_pem)
    @key_file = write("key.pem", leaf.key.private_to_pem)
    client = PKI.leaf(Pair.ca, names: [], common_name: "client", key: PKI.key(:client), purpose: "clientAuth", serial: 3)
    @client_cert_file = write("client_cert.pem", client.certificate.to_pem)
    @client_key_file = write("client_key.pem", client.key.private_to_pem)
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def write(name, contents) = File.join(@dir, name).tap { |path| File.write(path, contents) }

  def free_port = TCPServer.open("localhost", 0) { |server| server.addr[1] }

  # openssl s_server on a free port for the block.
  def s_server(*options)
    port = free_port
    pid = Process.spawn("openssl", "s_server", "-accept", port.to_s, "-cert", @cert_file, "-key", @key_file, "-tls1_3", *options,
      in: File::NULL, out: File::NULL, err: File::NULL)
    wait_for(port)
    Timeout.timeout(10) { yield port }
  ensure
    if pid
      Process.kill("TERM", pid) rescue nil # rubocop:disable Style/RescueModifier
      Process.wait(pid)
    end
  end

  def wait_for(port)
    Timeout.timeout(5) do
      TCPSocket.new("localhost", port).close
    rescue Errno::ECONNREFUSED
      sleep 0.05
      retry
    end
  end

  def connect(port, config: Pair.client_config, **keyring_options, &)
    TLS::TCP::Socket.connect("localhost", port, config:, keyring: TLS::Keyring.client(config:, **keyring_options), &)
  end

  # Reads until `count` bytes have come, or the peer closes.
  def read_bytes(sock, count)
    data = +""
    while data.bytesize < count && (chunk = sock.read(count - data.bytesize))
      data << chunk
    end
    data
  end

  def test_client_against_s_server
    s_server("-www") do |port|
      connect(port) do |sock|
        sock.write("GET / HTTP/1.0\r\n\r\n")
        assert_match(%r{\AHTTP/1.0 200 ok}, read_bytes(sock, 16))
      end
    end
  end

  # s_server prefers no group of ours with a key share: a
  # HelloRetryRequest for P-256.
  def test_client_after_a_hello_retry_request
    s_server("-www", "-groups", "P-256") do |port|
      connect(port) do |sock|
        sock.write("GET / HTTP/1.0\r\n\r\n")
        assert_match(%r{\AHTTP/1.0 200 ok}, read_bytes(sock, 16))
      end
    end
  end

  def test_client_certificate
    s_server("-www", "-Verify", "1", "-verifyCAfile", @ca_file, "-verify_return_error") do |port|
      connect(port, identities: [Pair.client_identity]) do |sock|
        sock.write("GET / HTTP/1.0\r\n\r\n")
        assert_match(%r{\AHTTP/1.0 200 ok}, read_bytes(sock, 16))
      end
    end
  end

  # Our KeyUpdate asks for s_server's; its answer comes before its data,
  # and both sides go on with the next keys.
  def test_client_key_update
    s_server("-rev") do |port|
      connect(port) do |sock|
        sock.write("abc\n")
        assert_equal "cba\n", read_bytes(sock, 4)
        sock.request_key_update(request_peer_update: true)
        sock.write("defg\n")
        assert_equal "gfed\n", read_bytes(sock, 5)
      end
    end
  end

  # s_client against our echo server, with a KeyUpdate that asks for ours
  # in between ("K" on its own line, a command only without -ign_eof, so
  # stdin stays open until the echo is back).
  def test_server_against_s_client
    config = Pair.server_config
    keyring = Pair.server_keyring(config:)
    listener = TCPServer.new("localhost", 0)
    port = listener.addr[1]
    received = Thread::Queue.new
    echoed = Thread::Queue.new
    server = Thread.new do
      TLS::TCP::Socket.accept(listener, config:, keyring:) do |sock|
        data = +""
        while (chunk = sock.read(100))
          data << chunk
          sock.write(chunk)
          echoed << chunk
        end
        received << data
      end
    rescue StandardError => e
      received << e
    end
    Open3.popen2e("openssl", "s_client", "-connect", "localhost:#{port}", "-tls1_3", "-CAfile", @ca_file,
      "-verify_return_error", "-servername", "localhost") do |stdin, out, wait|
      stdin.sync = true
      Timeout.timeout(10) do
        stdin.write("hello\n")
        assert_equal "hello\n", echoed.pop
        # s_client takes a command from one read of stdin as a whole, so
        # the line after it has to come in a read of its own.
        stdin.write("K\n")
        sleep 0.5
        stdin.write("after\n")
        assert_equal "after\n", echoed.pop
        stdin.close
        output = out.read
        assert wait.value.success?, output
        assert_includes output, "Verify return code: 0 (ok)"
        assert_includes output, "KEYUPDATE"
      end
    end
    server.join(5)
    assert_equal "hello\nafter\n", received.pop(timeout: 0)
  ensure
    listener&.close
    server&.kill
  end

  # s_client offering a share for P-256 only, to a server that takes
  # X25519 only: our HelloRetryRequest.
  def test_server_hello_retry_request
    config = Pair.server_config(groups: [:x25519])
    keyring = Pair.server_keyring(config:)
    listener = TCPServer.new("localhost", 0)
    port = listener.addr[1]
    received = Thread::Queue.new
    server = Thread.new do
      TLS::TCP::Socket.accept(listener, config:, keyring:) { |sock| received << sock.read(100) }
    rescue StandardError => e
      received << e
    end
    out, status = Timeout.timeout(10) do
      Open3.capture2e("openssl", "s_client", "-connect", "localhost:#{port}", "-tls1_3", "-CAfile", @ca_file,
        "-verify_return_error", "-servername", "localhost", "-groups", "P-256:X25519", stdin_data: "hi\n")
    end
    server.join(5)
    assert_equal "hi\n", received.pop(timeout: 0)
    assert status.success?, out
  ensure
    listener&.close
    server&.kill
  end
end
