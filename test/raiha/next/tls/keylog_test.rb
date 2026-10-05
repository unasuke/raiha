require "raiha/next/test_helper"
require "raiha/next/tls/test"
require "raiha/next/support/tls_pair"
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
