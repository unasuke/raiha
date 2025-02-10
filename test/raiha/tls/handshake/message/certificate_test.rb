require "test_helper"
require "support/rfc8448_test_vector"
require "openssl"
require "raiha/tls/handshake"

class RaihaTLSHandshakeCertificateTest < Minitest::Test
  def test_deserialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE)
    assert_equal Raiha::TLS::Handshake::Certificate, handshake.message.class
    assert_equal "", handshake.message.certificate_request_context
    assert_equal 0, handshake.message.extensions.length
    assert_equal OpenSSL::X509::Certificate, OpenSSL::X509::Certificate.new(handshake.message.opaque_certificate_data).class
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE)
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE, handshake.serialize
  end
end
