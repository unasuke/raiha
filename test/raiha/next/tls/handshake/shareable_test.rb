require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSHandshakeShareableTest < Minitest::Test
  TLS = Raiha::Next::TLS
  RFC8448 = TLS::Test::RFC8448
  REGISTRY = TLS::Extension::Registry::BUILTIN

  MESSAGES = [
    RFC8448::Simple1RTT::CLIENT_HELLO,
    RFC8448::Simple1RTT::SERVER_HELLO,
    RFC8448::HelloRetryRequest::HELLO_RETRY_REQUEST,
    RFC8448::Simple1RTT::NEW_SESSION_TICKET,
    "\x05\x00\x00\x00".b,
    RFC8448::Simple1RTT::ENCRYPTED_EXTENSIONS,
    RFC8448::Simple1RTT::CERTIFICATE,
    TLS::Handshake::CertificateRequest.new(certificate_request_context: "".b,
      extensions: [TLS::Extension::SignatureAlgorithms.new(supported_signature_algorithms: [0x0804])]).encode,
    RFC8448::Simple1RTT::CERTIFICATE_VERIFY,
    RFC8448::Simple1RTT::SERVER_FINISHED,
    "\x18\x00\x00\x01\x00".b
  ].freeze

  def test_every_parsed_message_type_is_shareable
    parsed = MESSAGES.map { |bytes| TLS::Handshake.parse(bytes, registry: REGISTRY) }
    expected = TLS::Handshake::TYPES.values.grep(Class)
    assert_equal expected.sort_by(&:name), parsed.map(&:class).uniq.sort_by(&:name)
    parsed.each { |message| assert Ractor.shareable?(message), message.class.name }
  end
end
