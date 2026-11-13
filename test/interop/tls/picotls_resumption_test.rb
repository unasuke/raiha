require "test_helper"
require "fileutils"
require "support/tls_pair"
require "support/tcp_drive"
require "raiha/tls"
require "open3"
require "socket"
require "timeout"
require "tmpdir"

# Resumption and 0-RTT of the next release of raiha over TCP against
# picotls's cli (built into tmp/picotls by `rake interop:build:picotls`),
# both ways. The cli keeps a session in the file given by `-s`, and with
# `-e` sends what it is given as 0-RTT when it resumes one.
#
# Both sides use X25519 (`-N x25519`): a picotls server that sends a
# HelloRetryRequest selects no PSK in the second ClientHello. The cli
# client connects to an IP address, with no SNI: with one it greases ECH,
# and then its outer ClientHello carries a random PSK identity, which no
# server without ECH can resume. `-S` has it offer psk_dhe_ke, the only
# mode we take.
class TLSPicotlsResumptionInteropTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = TLSPair
  PKI = TestPKI
  # tmp/ is not in git, so a fresh checkout has none.
  TMP = File.expand_path("../../../tmp", __dir__).tap { |dir| FileUtils.mkdir_p(dir) }
  PICOTLS = File.join(TMP, "picotls", "cli")
  SEED = "\x18".b * 32

  def setup
    skip "picotls cli not found at #{PICOTLS}" unless File.executable?(PICOTLS)
    @dir = Dir.mktmpdir("next-interop-picotls-resumption-", TMP)
    leaf = PKI.leaf(Pair.ca, names: ["DNS:localhost", "IP:127.0.0.1"])
    @identity = TLS::Keyring::Identity.new(cert_der: [leaf.der, Pair.ca.der], key_der: leaf.key_der)
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

  def picotls_server(*options, input:)
    port = free_port
    input_file = write("input", input)
    pid = Process.spawn(PICOTLS, "-c", @cert_file, "-k", @key_file, "-i", input_file, *options, "127.0.0.1", port.to_s,
      in: File::NULL, out: @out_file, err: File::NULL)
    Timeout.timeout(5) do
      TCPSocket.new("127.0.0.1", port).close
    rescue Errno::ECONNREFUSED
      sleep 0.05
      retry
    end
    Timeout.timeout(15) { yield port }
  ensure
    if pid
      Process.kill("TERM", pid) rescue nil # rubocop:disable Style/RescueModifier
      Process.wait(pid)
    end
  end

  def printed(expected)
    Timeout.timeout(5) { sleep 0.05 until File.exist?(@out_file) && File.read(@out_file).include?(expected) }
  end

  def client(port, **options)
    config = Pair.client_config
    connection = TLS::TCP::Connection.client(config:, keyring: TLS::Keyring.client(config:), server_name: "localhost", now: Time.now,
      **options)
    TCPDrive.new(TCPSocket.new("127.0.0.1", port), connection)
  end

  def test_client_resumes_with_0rtt
    picotls_server("-N", "x25519", input: "from picotls\n") do |port|
      first = client(port)
      received = +""
      first.until { (received << first.connection.read(100).to_s).include?("from picotls\n") && !first.sessions.empty? }
      session = first.sessions.last or flunk "no ticket from picotls"
      first.close
      second = client(port, session:, early_data: true)
      assert_equal 6, second.connection.write_early_data("early\n")
      second.until { second.connection.handshake_complete? }
      assert second.completion.resumed
      assert second.completion.early_data_accepted
      printed("early\n")
      second.close
    end
  end

  # Our server for `count` connections of picotls's client: what each sent
  # as 0-RTT and as 1-RTT, and whether it resumed and took 0-RTT.
  def server(count)
    config = Pair.server_config(ticket_key: SEED, max_early_data_size: 16_384)
    keyring = Pair.server_keyring(config:, identities: [@identity])
    anti_replay = TLS::AntiReplay::Memory.new(now: Time.now, warmup: false)
    listener = TCPServer.new("127.0.0.1", 0)
    results = Thread::Queue.new
    thread = Thread.new do
      count.times do
        drive = TCPDrive.new(listener.accept, TLS::TCP::Connection.server(config:, keyring:, now: Time.now, anti_replay:))
        drive.until { drive.connection.handshake_complete? }
        early = drive.connection.read_early_data(65_536)
        data = drive.read_all(timeout: 10)
        results << [early, data, drive.completion&.resumed, drive.completion&.early_data_accepted]
        drive.close
      end
    rescue StandardError => e
      results << e
    end
    yield listener.addr[1], results
  ensure
    listener&.close
    thread&.kill
  end

  def picotls_client(port, *options, input:)
    input_file = write("client-input", input)
    out, = Timeout.timeout(10) do
      Open3.capture2e(PICOTLS, "-4", "-V", @ca_file, "-N", "x25519", "-S", "-i", input_file, *options, "127.0.0.1", port.to_s)
    end
    out
  end

  def test_server_resumes_and_takes_0rtt
    session_file = File.join(@dir, "client-session")
    server(2) do |port, results|
      Timeout.timeout(25) do
        picotls_client(port, "-s", session_file, input: "first\n")
        first = results.pop
        raise first if first.is_a?(Exception)
        assert_equal [nil, "first\n", false, false], first
        picotls_client(port, "-s", session_file, "-e", input: "second\n")
        second = results.pop
        raise second if second.is_a?(Exception)
        assert_equal ["second\n", "", true, true], second
      end
    end
  end
end
