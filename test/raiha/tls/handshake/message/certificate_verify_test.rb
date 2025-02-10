require "test_helper"
require "support/rfc8448_test_vector"
require "raiha/tls/handshake"

class RaihaTLSHandshakeCertificateVerifyTest < Minitest::Test
  def test_deserialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY)
    assert_equal Raiha::TLS::Handshake::CertificateVerify, handshake.message.class
    assert_equal "rsa_pss_rsae_sha256", handshake.message.algorithm
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY)
    serialized = handshake.serialize
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_CERTIFICATE_VERIFY, serialized
  end
end
