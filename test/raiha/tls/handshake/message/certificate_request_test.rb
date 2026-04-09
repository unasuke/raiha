require "test_helper"
require_relative "../../../../../lib/raiha/tls/handshake"

class RaihaTLSHandshakeCertificateRequestTest < Minitest::Test
  def test_serialize_empty_context
    req = Raiha::TLS::Handshake::CertificateRequest.new
    req.certificate_request_context = ""
    req.extensions = []

    serialized = req.serialize
    assert_equal "\x00\x00\x00".b, serialized
  end

  def test_roundtrip_via_handshake
    req = Raiha::TLS::Handshake::CertificateRequest.new
    req.certificate_request_context = "\x01\x02\x03".b
    req.extensions = []

    hs = Raiha::TLS::Handshake.new
    hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:certificate_request]
    hs.message = req

    serialized = hs.serialize
    deserialized = Raiha::TLS::Handshake.deserialize(serialized)

    assert_equal Raiha::TLS::Handshake::CertificateRequest, deserialized.message.class
    assert_equal "\x01\x02\x03".b, deserialized.message.certificate_request_context
    assert_equal [], deserialized.message.extensions
  end

  def test_deserialize
    # context_length(1) + context(0) + extensions_length(2) + no extensions
    data = "\x00\x00\x00".b
    req = Raiha::TLS::Handshake::CertificateRequest.deserialize(data)

    assert_equal "", req.certificate_request_context
    assert_equal [], req.extensions
  end
end
