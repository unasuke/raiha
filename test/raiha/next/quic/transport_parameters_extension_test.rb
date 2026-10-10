require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/tls/test"

# quic_transport_parameters registered in the TLS layer's Extension::Registry
# as QUIC's TransportParameters::Extension.
class RaihaNextQUICTransportParametersExtensionTest < Minitest::Test
  TLS = Raiha::Next::TLS
  QUIC = Raiha::Next::QUIC
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = TLS::Extension::Registry::BUILTIN.with(QUIC::TransportParameters::Extension)

  def parameters = QUIC::TransportParameters.new(initial_max_data: 1 << 20, initial_source_connection_id: "c".b * 8)

  def extension = TLS::Extension::Opaque.new(type: 0x39, data: parameters.encode)

  def client_hello
    ch = TLS::Handshake.parse(RFC8448::CLIENT_HELLO, registry: TLS::Extension::Registry::BUILTIN)
    ch.with(extensions: ch.extensions + [extension])
  end

  # TLS keeps the bytes as they came, and QUIC decodes them.
  def test_client_hello_keeps_the_bytes
    parsed = TLS::Handshake.parse(client_hello.encode, registry: REGISTRY)
    assert_equal extension, parsed.extension(0x39)
    assert_equal parameters, QUIC::TransportParameters.decode(parsed.extension(0x39).data, sender: :client)
  end

  # Bytes that do not decode are QUIC's to refuse, not a TLS alert.
  def test_bytes_that_do_not_decode_pass_through_tls
    broken = TLS::Extension::Opaque.new(type: 0x39, data: "\x04\x05\x01".b)
    ch = client_hello.with(extensions: client_hello.extensions[0...-1] + [broken])
    parsed = TLS::Handshake.parse(ch.encode, registry: REGISTRY)
    assert_equal broken, parsed.extension(0x39)
    error = assert_raises(QUIC::Wire::Malformed) { QUIC::TransportParameters.decode(broken.data, sender: :client) }
    assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, error.code
  end

  def test_encrypted_extensions_carries_it
    ee = TLS::Handshake::EncryptedExtensions.new(extensions: [extension])
    assert_equal ee, TLS::Handshake.parse(ee.encode, registry: REGISTRY)
  end

  # RFC 9001 "QUIC Transport Parameters Extension": in no other message.
  def test_tls_refuses_it_elsewhere
    sh = TLS::Handshake.parse(RFC8448::SERVER_HELLO, registry: REGISTRY)
    with_parameters = sh.with(extensions: sh.extensions + [extension])
    assert_raises(TLS::Codec::IllegalPlacement) { TLS::Handshake.parse(with_parameters.encode, registry: REGISTRY) }
  end

  def test_the_registry_can_go_to_another_ractor
    assert Ractor.shareable?(REGISTRY)
  end
end
