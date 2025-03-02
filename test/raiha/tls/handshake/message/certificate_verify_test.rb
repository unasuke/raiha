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

  def test_serialize_and_deserialize
    handshake = Raiha::TLS::Handshake.new.tap do |hs|
      hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:certificate_verify]
      hs.message = Raiha::TLS::Handshake::CertificateVerify.new.tap do |cv|
        cv.algorithm = "rsa_pss_rsae_sha256"
        cv.signature = "sample-signature"
      end
    end
    serialized = handshake.serialize
    deserialized = Raiha::TLS::Handshake.deserialize(serialized)
    assert_equal Raiha::TLS::Handshake::CertificateVerify, deserialized.message.class
    assert_equal "rsa_pss_rsae_sha256", deserialized.message.algorithm
    assert_equal "sample-signature", deserialized.message.signature
    assert_equal_bin deserialized.serialize, serialized
  end
end
