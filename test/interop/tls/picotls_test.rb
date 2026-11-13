require "test_helper"
require "fileutils"
require "support/tls_pair"
require "raiha/tls"
require "open3"
require "socket"
require "timeout"
require "tmpdir"

# The next release of raiha over TCP against picotls's cli (built into
# tmp/picotls by `rake interop:build:picotls`), both ways. picotls's `-u`
# asks for a KeyUpdate as soon as the handshake completes, and sends it with
# its first data.
class TLSPicotlsInteropTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = TLSPair
  PKI = TestPKI
  # tmp/ is not in git, so a fresh checkout has none.
  TMP = File.expand_path("../../../tmp", __dir__).tap { |dir| FileUtils.mkdir_p(dir) }
  PICOTLS = File.join(TMP, "picotls", "cli")

  def setup
    skip "picotls cli not found at #{PICOTLS}" unless File.executable?(PICOTLS)
    @dir = Dir.mktmpdir("next-interop-picotls-", TMP)
    leaf = PKI.leaf(Pair.ca)
    @ca_file = write("ca.pem", Pair.ca.certificate.to_pem)
    @cert_file = write("cert.pem", leaf.certificate.to_pem)
    @key_file = write("key.pem", leaf.key.private_to_pem)
    @out_file = File.join(@dir, "out")
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def write(name, contents) = File.join(@dir, name).tap { |path| File.write(path, contents) }

  def free_port = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }

  # picotls's server on a free port for the block, sending `input` to the
  # client and printing what it receives to @out_file.
  def picotls_server(*options, input:)
    port = free_port
    input_file = write("input", input)
    pid = Process.spawn(PICOTLS, "-c", @cert_file, "-k", @key_file, "-i", input_file, *options, "127.0.0.1", port.to_s,
      in: File::NULL, out: @out_file, err: File::NULL)
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
      TCPSocket.new("127.0.0.1", port).close
    rescue Errno::ECONNREFUSED
      sleep 0.05
      retry
    end
  end

  # Waits until picotls has printed `expected`.
  def printed(expected)
    Timeout.timeout(5) do
      sleep 0.05 until File.exist?(@out_file) && File.read(@out_file).include?(expected)
    end
    File.read(@out_file)
  end

  def connect(port, config: Pair.client_config, **keyring_options, &)
    TLS::TCP::Socket.connect("127.0.0.1", port, server_name: "localhost", config:,
      keyring: TLS::Keyring.client(config:, **keyring_options), &)
  end

  def read_bytes(sock, count)
    data = +""
    while data.bytesize < count && (chunk = sock.read(count - data.bytesize))
      data << chunk
    end
    data
  end

  def test_client_against_picotls_server
    picotls_server(input: "from picotls\n") do |port|
      connect(port) do |sock|
        assert_equal "from picotls\n", read_bytes(sock, 13)
        sock.write("from raiha\n")
        printed("from raiha\n")
      end
    end
  end

  # The server's KeyUpdate asks for ours, which goes before our data.
  def test_client_with_a_key_update_from_the_server
    picotls_server("-u", input: "updated\n") do |port|
      connect(port) do |sock|
        assert_equal "updated\n", read_bytes(sock, 8)
        sock.write("after the update\n")
        printed("after the update\n")
      end
    end
  end

  def test_client_certificate
    picotls_server("-a", "-V", @ca_file, input: "authenticated\n") do |port|
      connect(port, identities: [Pair.client_identity]) do |sock|
        assert_equal "authenticated\n", read_bytes(sock, 14)
      end
    end
  end

  # picotls's client against our echo server, with `options` added.
  def against_picotls_client(*options, config: Pair.server_config)
    keyring = Pair.server_keyring(config:)
    listener = TCPServer.new("127.0.0.1", 0)
    received = Thread::Queue.new
    server = Thread.new do
      TLS::TCP::Socket.accept(listener, config:, keyring:) do |sock|
        data = +""
        while (chunk = sock.read(100))
          data << chunk
          sock.write(chunk)
        end
        received << data
      end
    rescue StandardError => e
      received << e
    end
    input_file = write("input", "hello picotls\n")
    out, status = Timeout.timeout(10) do
      Open3.capture2e(PICOTLS, "-4", "-V", @ca_file, "-i", input_file, *options, "localhost", listener.addr[1].to_s)
    end
    server.join(5)
    assert_equal "hello picotls\n", received.pop(timeout: 0)
    assert_includes out, "hello picotls"
    # The cli ends on any error from ptls_receive, our close_notify (peer
    # alert 0, 0x100 + 0) included, and exits with 1 then.
    assert_includes out, "ptls_receive:256"
    assert_equal 1, status.exitstatus, out
  ensure
    listener&.close
    server&.kill
  end

  def test_server_against_picotls_client = against_picotls_client

  # picotls asks for our KeyUpdate; ours goes before the echo.
  def test_server_with_a_key_update_from_the_client = against_picotls_client("-u")

  # No key share from picotls (-n): our HelloRetryRequest.
  def test_server_hello_retry_request = against_picotls_client("-n")
end
