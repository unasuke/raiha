require "test_helper"
require "fileutils"
require "support/tls_pair"
require "support/tcp_drive"
require "raiha/tls"
require "open3"
require "socket"
require "timeout"
require "tmpdir"

# Resumption and 0-RTT of the next release of raiha over TCP against the
# openssl command, both ways: a client resuming a session of
# `openssl s_server` with 0-RTT, and a server resuming `openssl s_client`
# and taking its 0-RTT.
class TLSOpenSSLResumptionInteropTest < Minitest::Test
  TLS = Raiha::TLS
  Pair = TLSPair
  PKI = TestPKI
  # tmp/ is not in git, so a fresh checkout has none.
  TMP = File.expand_path("../../../tmp", __dir__).tap { |dir| FileUtils.mkdir_p(dir) }
  SEED = "\x17".b * 32
  REQUEST = "GET / HTTP/1.0\r\n\r\n"

  def setup
    skip "openssl command not found" unless system("openssl", "version", out: File::NULL, err: File::NULL)
    @dir = Dir.mktmpdir("next-interop-openssl-resumption-", TMP)
    leaf = PKI.leaf(Pair.ca)
    @ca_file = write("ca.pem", Pair.ca.certificate.to_pem)
    @cert_file = write("cert.pem", leaf.certificate.to_pem)
    @key_file = write("key.pem", leaf.key.private_to_pem)
  end

  def teardown
    FileUtils.rm_rf(@dir) if @dir
  end

  def write(name, contents) = File.join(@dir, name).tap { |path| File.write(path, contents) }

  def free_port = TCPServer.open("localhost", 0) { |server| server.addr[1] }

  def s_server(*options)
    port = free_port
    pid = Process.spawn("openssl", "s_server", "-accept", port.to_s, "-cert", @cert_file, "-key", @key_file, "-tls1_3", *options,
      in: File::NULL, out: File::NULL, err: File::NULL)
    Timeout.timeout(5) do
      TCPSocket.new("localhost", port).close
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

  def client(port, **options)
    config = Pair.client_config
    connection = TLS::TCP::Connection.client(config:, keyring: TLS::Keyring.client(config:), server_name: "localhost", now: Time.now,
      **options)
    TCPDrive.new(TCPSocket.new("localhost", port), connection)
  end

  # A page from s_server -www, and the sessions of the tickets it sent.
  def fetch(port, **options)
    drive = client(port, **options)
    yield drive if block_given?
    drive.until { drive.connection.handshake_complete? }
    drive.connection.write(REQUEST)
    [drive.read_all, drive]
  ensure
    drive&.close
  end

  def test_client_resumes_with_0rtt
    s_server("-www", "-early_data", "-max_early_data", "16384", "-num_tickets", "2") do |port|
      page, first = fetch(port)
      assert_match(%r{\AHTTP/1.0 200 ok}, page)
      session = first.sessions.last or flunk "no ticket from s_server"
      assert_equal 16_384, session.max_early_data_size
      page, second = fetch(port, session:, early_data: true) { |drive| assert_equal 3, drive.connection.write_early_data("hi\n") }
      assert_match(%r{\AHTTP/1.0 200 ok}, page)
      assert second.completion.resumed
      assert second.completion.early_data_accepted
    end
  end

  # s_server takes no 0-RTT without -early_data: the client's is skipped,
  # and the handshake resumes.
  def test_client_0rtt_rejected
    s_server("-www", "-max_early_data", "16384") do |port|
      _, first = fetch(port)
      session = first.sessions.last or flunk "no ticket from s_server"
      page, second = fetch(port, session:, early_data: true) { |drive| drive.connection.write_early_data("hi\n") }
      assert_match(%r{\AHTTP/1.0 200 ok}, page)
      assert second.completion.resumed
      refute second.completion.early_data_accepted
      assert_equal [:rejected_by_server], second.events.grep(TLS::Event::EarlyDataRejected).map(&:reason)
    end
  end

  # Our server for `count` connections of s_client: what each sent as
  # 0-RTT and as 1-RTT, and whether it resumed.
  def server(count)
    config = Pair.server_config(ticket_key: SEED, max_early_data_size: 16_384)
    keyring = Pair.server_keyring(config:)
    anti_replay = TLS::AntiReplay::Memory.new(now: Time.now, warmup: false)
    listener = TCPServer.new("localhost", 0)
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

  def s_client(port, *options, input:)
    Open3.popen2e("openssl", "s_client", "-connect", "localhost:#{port}", "-tls1_3", "-CAfile", @ca_file, "-verify_return_error",
      "-servername", "localhost", *options) do |stdin, out, wait|
      stdin.sync = true
      # Time for the tickets to come before the input closes s_client.
      sleep 0.5
      stdin.write(input)
      stdin.close
      output = out.read
      assert wait.value.success?, output
      output
    end
  end

  def test_server_resumes_and_takes_0rtt
    session_file = File.join(@dir, "session.pem")
    early_file = write("early.txt", "early data\n")
    server(2) do |port, results|
      Timeout.timeout(20) do
        s_client(port, "-sess_out", session_file, input: "first\n")
        first = results.pop
        raise first if first.is_a?(Exception)
        assert_equal [nil, "first\n", false], first.first(3)
        output = s_client(port, "-sess_in", session_file, "-early_data", early_file, input: "second\n")
        second = results.pop
        raise second if second.is_a?(Exception)
        assert_equal ["early data\n", "second\n", true, true], second
        assert_includes output, "Early data was accepted"
      end
    end
  end
end
