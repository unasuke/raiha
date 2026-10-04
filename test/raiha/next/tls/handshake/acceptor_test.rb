require "raiha/next/test_helper"
require "raiha/next/support/tls_pair"

class RaihaNextTLSAcceptorTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Acceptor = TLS::Handshake::Acceptor
  Extension = TLS::Extension
  RFC8448 = begin
    require "raiha/next/tls/test"
    TLS::Test::RFC8448
  end
  NOW = NextTLSPair::NOW

  def client_hello(**options) = NextTLSPair.client(config: NextTLSPair.client_config(**options)).outputs.first.bytes

  def outputs(acceptor) = [].tap { |list| acceptor.each_output { |output| list << output } }

  def test_accepts_a_client_hello
    bytes = client_hello(alpn: %w[h3 h2])
    acceptor = Acceptor.new
    acceptor.receive(bytes, epoch: :initial, now: NOW)
    accepted = acceptor.accepted
    assert_equal bytes, accepted.bytes
    assert accepted.bytes.frozen?
    info = accepted.info
    assert_equal ["localhost", %w[h3 h2], false, false, false],
      [info.server_name, info.alpn_protocols, info.psk_offered, info.early_data_offered, info.after_hello_retry_request]
    assert_includes info.cipher_suites, 0x1301
    assert_includes info.supported_groups, 0x001d
    assert_includes info.extension_types, 51
    assert_empty outputs(acceptor)
  end

  def test_a_client_hello_split_anywhere
    bytes = client_hello
    acceptor = Acceptor.new
    bytes.each_char { |byte| acceptor.receive(byte, epoch: :initial, now: NOW) }
    assert_equal bytes, acceptor.accepted.bytes
  end

  def test_info_from_rfc8448
    acceptor = Acceptor.new
    acceptor.receive(RFC8448::HelloRetryRequest::CLIENT_HELLO_2, epoch: :initial, now: NOW)
    info = acceptor.accepted.info
    assert_equal ["server", true], [info.server_name, info.after_hello_retry_request]
    acceptor = Acceptor.new
    acceptor.receive(RFC8448::Resumed0RTT::CLIENT_HELLO, epoch: :initial, now: NOW)
    assert_equal [true, true], [acceptor.accepted.info.psk_offered, acceptor.accepted.info.early_data_offered]
  end

  # A ClientHello that fails its own checks never reaches the application.
  def test_invalid_client_hello_is_not_accepted
    hello = TLS::Handshake.parse(client_hello, registry: Extension::Registry::BUILTIN)
    without_versions = hello.with(extensions: hello.extensions.reject { |ext| ext.extension_type == 43 })
    acceptor = Acceptor.new
    acceptor.receive(without_versions.encode, epoch: :initial, now: NOW)
    assert_nil acceptor.accepted
    assert_equal [:protocol_version, :supported_versions], [acceptor.alert, acceptor.reason]
    assert_equal [[:alert, :initial, :protocol_version]], NextTLSPair.shape(outputs(acceptor))
  end

  def test_errors
    {
      "\x01\x00\x00\x02\x03\x03".b => :decode_error,
      "\x02\x00\x00\x00".b => :unexpected_message,
      "\x01\x00\x40\x01".b => :decode_error
    }.each do |bytes, alert|
      acceptor = Acceptor.new
      acceptor.receive(bytes, epoch: :initial, now: NOW)
      acceptor.receive("\x00".b * 4, epoch: :initial, now: NOW) unless acceptor.failed?
      assert_equal alert, acceptor.alert, bytes.unpack1("H*")
    end
  end

  def test_bytes_after_the_client_hello
    acceptor = Acceptor.new
    acceptor.receive(client_hello + "\x16".b, epoch: :initial, now: NOW)
    assert_equal :unexpected_message, acceptor.alert
    assert_nil acceptor.accepted
    acceptor = Acceptor.new
    acceptor.receive(client_hello, epoch: :initial, now: NOW)
    acceptor.receive("\x01".b, epoch: :initial, now: NOW)
    assert_equal [:unexpected_message, :data_after_client_hello], [acceptor.alert, acceptor.reason]
  end

  # A server has no keys yet, so other epochs are the caller's mistake.
  def test_only_initial_bytes
    assert_raises(TLS::UsageError) { Acceptor.new.receive(client_hello, epoch: :handshake, now: NOW) }
  end

  def test_reject
    Acceptor::REJECT_ALERTS.each do |alert|
      acceptor = Acceptor.new
      acceptor.receive(client_hello, epoch: :initial, now: NOW)
      acceptor.reject(alert)
      assert_equal [[:alert, :initial, alert]], NextTLSPair.shape(outputs(acceptor))
    end
    %i[access_denied decode_error illegal_parameter close_notify].each do |alert|
      assert_raises(ArgumentError) { Acceptor.new.reject(alert) }
    end
  end

  def test_sni_that_is_not_a_host_name_is_absent
    acceptor = Acceptor.new
    acceptor.receive(client_hello_with_sni("192.0.2.1"), epoch: :initial, now: NOW)
    assert_nil acceptor.accepted.info.server_name
  end

  # A server Machine without a ClientHello uses an Acceptor of its own, and
  # reports its failure as its own.
  def test_machine_with_its_own_acceptor
    config = NextTLSPair.server_config
    server = TLS::Handshake::Machine.server(config:, keyring: NextTLSPair.server_keyring(config:), now: NOW)
    server.receive("\x02\x00\x00\x00".b, epoch: :initial, now: NOW)
    assert server.failed?
    assert_equal [[:alert, :initial, :unexpected_message]], NextTLSPair.shape(server.outputs)
    assert_equal [TLS::Event::Failed.new(alert: :unexpected_message, reason: :unexpected_message)], server.each_event.to_a
    server.receive(client_hello, epoch: :initial, now: NOW)
    assert_empty server.outputs
  end

  def test_machine_takes_an_accepted
    acceptor = Acceptor.new
    acceptor.receive(client_hello, epoch: :initial, now: NOW)
    config = NextTLSPair.server_config
    server = TLS::Handshake::Machine.server(config:, keyring: NextTLSPair.server_keyring(config:), client_hello: acceptor.accepted, now: NOW)
    assert_equal [:message, :initial, 2], NextTLSPair.shape(server.outputs).fetch(3)
  end

  def client_hello_with_sni(name)
    hello = TLS::Handshake.parse(client_hello, registry: Extension::Registry::BUILTIN)
    extensions = hello.extensions.map { |ext| ext.extension_type == 0 ? Extension::ServerName::CH.new(host_name: name) : ext }
    hello.with(extensions:).encode
  end
end
