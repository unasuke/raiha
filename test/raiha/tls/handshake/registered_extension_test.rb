require "test_helper"
require "raiha/tls/test"

# Appendix B 4: an extension registered from outside, shaped like QUIC's
# quic_transport_parameters, is parsed and encoded exactly like a built-in
# one, with no special case.
class RaihaNextTLSHandshakeRegisteredExtensionTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  RFC8448 = TLS::Test::RFC8448::Simple1RTT

  module TransportParameters
    TYPE = 57

    class Value < Data.define(:parameters)
      def self.parse(data) = new(parameters: data)

      def extension_type = TYPE

      def encode = parameters
    end

    CODECS = { client_hello: Value, encrypted_extensions: Value }.freeze
  end

  REGISTRY = Extension::Registry::BUILTIN.with(TransportParameters)
  PARAMETERS = TransportParameters::Value.new(parameters: "\x01\x02\x40\x64".b)

  def client_hello
    ch = TLS::Handshake.parse(RFC8448::CLIENT_HELLO, registry: Extension::Registry::BUILTIN)
    ch.with(extensions: ch.extensions + [PARAMETERS])
  end

  def test_client_hello_carries_it_like_a_builtin_extension
    ch = client_hello
    parsed = TLS::Handshake.parse(ch.encode, registry: REGISTRY)
    assert_equal ch, parsed
    assert_equal PARAMETERS, parsed.extension(57)
    assert_nil parsed.validate
  end

  def test_encrypted_extensions_carries_it_too
    ee = TLS::Handshake::EncryptedExtensions.new(extensions: [PARAMETERS])
    assert_equal ee, TLS::Handshake.parse(ee.encode, registry: REGISTRY)
  end

  def test_placement_applies_to_it
    sh = TLS::Handshake.parse(RFC8448::SERVER_HELLO, registry: REGISTRY)
    with_parameters = sh.with(extensions: sh.extensions + [PARAMETERS])
    assert_raises(TLS::Codec::IllegalPlacement) { TLS::Handshake.parse(with_parameters.encode, registry: REGISTRY) }
  end

  def test_without_registration_it_stays_opaque
    parsed = TLS::Handshake.parse(client_hello.encode, registry: Extension::Registry::BUILTIN)
    assert_equal Extension::Opaque.new(type: 57, data: PARAMETERS.parameters), parsed.extension(57)
  end
end
