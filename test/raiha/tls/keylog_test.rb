require "test_helper"
require "raiha/tls/test"
require "support/tls_pair"
require "stringio"
require "tmpdir"

class RaihaNextTLSKeylogTest < Minitest::Test
  TLS = Raiha::Next::TLS
  RFC8448 = TLS::Test::RFC8448
  S = RFC8448::Simple1RTT
  Pair = NextTLSPair
  NOW = Time.utc(2018, 1, 1)

  def hex(bytes) = bytes.unpack1("H*")

  def line(label, secret) = "#{label} #{hex(S::CLIENT_HELLO_RANDOM)} #{hex(secret)}\n"

  # RFC 8448 section 3 in both roles: each traffic secret as it is derived,
  # and not the exporter secret.
  def test_rfc8448_lines
    handshake = [line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", S::CLIENT_HANDSHAKE_TRAFFIC_SECRET),
      line("SERVER_HANDSHAKE_TRAFFIC_SECRET", S::SERVER_HANDSHAKE_TRAFFIC_SECRET)]
    application = [line("SERVER_TRAFFIC_SECRET_0", S::SERVER_APPLICATION_TRAFFIC_SECRET_0),
      line("CLIENT_TRAFFIC_SECRET_0", S::CLIENT_APPLICATION_TRAFFIC_SECRET_0)]

    keylog = StringIO.new
    client = RFC8448.machine(:simple_1rtt, :client, now: NOW, keylog:)
    client.receive(S::SERVER_HELLO, epoch: :initial, now: NOW)
    assert_equal handshake.join, keylog.string
    client.receive(S::ENCRYPTED_EXTENSIONS + S::CERTIFICATE + S::CERTIFICATE_VERIFY + S::SERVER_FINISHED, epoch: :handshake, now: NOW)
    assert client.complete?
    assert_equal (handshake + application).join, keylog.string
    refute_includes keylog.string, hex(S::EXPORTER_SECRET)

    keylog = StringIO.new
    server = RFC8448.machine(:simple_1rtt, :server, now: NOW, keylog:)
    server.receive(S::CLIENT_HELLO, epoch: :initial, now: NOW)
    assert_equal (handshake + application).join, keylog.string
  end

  # The 0-RTT key goes to the client's keylog, and to the server's only
  # when it takes 0-RTT.
  def test_the_early_traffic_secret
    seed = "\x16".b * 32
    config = Pair.server_config(ticket_key: seed, max_early_data_size: 1024)
    pair = Pair.run(Pair.client, { config: })
    Pair.deliver(pair.server_outputs.select { |o| o.is_a?(TLS::Output::Message) && o.epoch == :application }, pair.client)
    session = pair.client.each_event.grep(TLS::Event::NewSessionTicket).first.session
    labels = lambda do |server_config|
      client_log, server_log = StringIO.new, StringIO.new
      Pair.run(Pair.client(session:, early_data: true, keylog: client_log), { config: server_config, keylog: server_log })
      [client_log, server_log].map { |log| log.string.lines.map { |l| l.split.first } }
    end
    client, server = labels.(config)
    assert_includes client, "CLIENT_EARLY_TRAFFIC_SECRET"
    assert_includes server, "CLIENT_EARLY_TRAFFIC_SECRET"
    client, server = labels.(Pair.server_config(ticket_key: seed))
    assert_includes client, "CLIENT_EARLY_TRAFFIC_SECRET"
    refute_includes server, "CLIENT_EARLY_TRAFFIC_SECRET"
  end

  # A KeyUpdate's next generation is not written.
  def test_nothing_after_the_handshake
    keylog = StringIO.new
    pair = Pair.run(Pair.client(keylog:))
    lines = keylog.string.lines
    assert_equal %w[CLIENT_HANDSHAKE_TRAFFIC_SECRET SERVER_HANDSHAKE_TRAFFIC_SECRET SERVER_TRAFFIC_SECRET_0 CLIENT_TRAFFIC_SECRET_0],
      lines.map { |l| l.split.first }
    pair.client.request_key_update(request_peer_update: true)
    assert_equal lines, keylog.string.lines
  end

  # The keylog's exception goes through, with the secrets forgotten first.
  def test_an_exception_from_the_keylog
    broken = Object.new
    def broken.write(_line) = raise(IOError, "disk full")
    client = Pair.client(keylog: broken)
    server = Pair.server(client.outputs.first.bytes)
    assert_raises(IOError) { Pair.deliver(server.outputs, client) }
    assert client.failed?
    assert_empty client.outputs
    assert_empty client.each_event.to_a
  end

  def test_file_is_owner_only_and_appended
    Dir.mktmpdir do |dir|
      path = File.join(dir, "keylog.txt")
      File.write(path, "existing\n")
      File.chmod(0o644, path)
      file = TLS::Keylog::File.new(path)
      file.write("a\n")
      file.close
      assert_equal "existing\na\n", File.read(path)
      assert_equal 0o600, File.stat(path).mode & 0o777
    end
  end
end
