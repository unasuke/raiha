require "raiha/next/test_helper"
require "raiha/next/tls/test"

class RaihaNextTLSHandshakeOtherMessagesValidateTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Extension = TLS::Extension
  Handshake = TLS::Handshake
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = Extension::Registry::BUILTIN

  def test_certificate_request_requires_signature_algorithms
    with = Handshake::CertificateRequest.new(certificate_request_context: "".b,
      extensions: [Extension::SignatureAlgorithms.new(supported_signature_algorithms: [0x0804])])
    assert_nil with.validate
    assert_equal Handshake::Violation.new(alert: :missing_extension, reason: :signature_algorithms),
      with.with(extensions: []).validate
  end

  def test_certificate_verify_rejects_pkcs1_and_sha1
    [0x0201, 0x0203, 0x0401, 0x0501, 0x0601].each do |algorithm|
      cv = Handshake::CertificateVerify.new(algorithm:, signature: "s".b)
      assert_equal Handshake::Violation.new(alert: :illegal_parameter, reason: :signature_algorithm), cv.validate, format("0x%04x", algorithm)
    end
    [0x0403, 0x0804, 0x0807].each do |algorithm|
      assert_nil Handshake::CertificateVerify.new(algorithm:, signature: "s".b).validate
    end
    assert_nil Handshake.parse(RFC8448::CERTIFICATE_VERIFY, registry: REGISTRY).validate
  end

  # Code points that are not schemes, reserved ones and GREASE included, are
  # left to the state machine, which rejects any scheme it did not offer.
  def test_certificate_verify_leaves_undefined_schemes_to_the_state_machine
    [0x0202, 0x0a0a, 0xfe00].each do |algorithm|
      assert_nil Handshake::CertificateVerify.new(algorithm:, signature: "s".b).validate
    end
  end

  def test_key_update_request_update
    assert_nil Handshake::KeyUpdate.new(request_update: 0).validate
    assert_nil Handshake::KeyUpdate.new(request_update: 1).validate
    [2, 255].each do |value|
      assert_equal Handshake::Violation.new(alert: :illegal_parameter, reason: :request_update),
        Handshake::KeyUpdate.new(request_update: value).validate
    end
  end

  def test_messages_without_context_free_checks
    [RFC8448::ENCRYPTED_EXTENSIONS, RFC8448::CERTIFICATE, RFC8448::SERVER_FINISHED, RFC8448::NEW_SESSION_TICKET,
      "\x05\x00\x00\x00".b].each do |bytes|
      assert_nil Handshake.parse(bytes, registry: REGISTRY).validate
    end
  end

  # A NewSessionTicket lifetime above 7 days is the sender's error to avoid,
  # not the receiver's to abort on.
  def test_new_session_ticket_lifetime_is_not_checked
    nst = Handshake.parse(RFC8448::NEW_SESSION_TICKET, registry: REGISTRY).with(ticket_lifetime: 604_801)
    assert_nil nst.validate
  end
end
