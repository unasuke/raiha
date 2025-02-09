require "test_helper"
require "raiha/tls/handshake"

class RaihaTLSHandshakeCertificateVerifyTest < Minitest::Test
  RFC8448_1RTT_SERVER_HANDSHAKE_CERTIFICATE_VERIFY = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    0f 00 00 84 08 04 00 80 5a 74 7c
    5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
    b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
    86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
    be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
    5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
    3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3
  HEX

  def test_deserialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_1RTT_SERVER_HANDSHAKE_CERTIFICATE_VERIFY)
    assert_equal Raiha::TLS::Handshake::CertificateVerify, handshake.message.class
    assert_equal "rsa_pss_rsae_sha256", handshake.message.algorithm
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_1RTT_SERVER_HANDSHAKE_CERTIFICATE_VERIFY)
    serialized = handshake.serialize
    assert_equal_bin RFC8448_1RTT_SERVER_HANDSHAKE_CERTIFICATE_VERIFY, serialized
  end
end
