require "test_helper"
require "openssl"
require "raiha/tls/handshake"

class RaihaTLSHandshakeFinishedTest < Minitest::Test
  RFC8448_1RTT_SERVER_HANDSHAKE_FINISHED = [<<~HEX.gsub(/[[:space:]]/, '')].pack("H*")
    14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
    dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07
    18
  HEX

  def test_deserialize_rfc8446
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_1RTT_SERVER_HANDSHAKE_FINISHED)
    assert_equal Raiha::TLS::Handshake::Finished, handshake.message.class
    assert_equal OpenSSL::Digest.new("sha256").digest_length, handshake.message.verify_data.bytesize
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_1RTT_SERVER_HANDSHAKE_FINISHED)
    serialized = handshake.serialize
    assert_equal_bin RFC8448_1RTT_SERVER_HANDSHAKE_FINISHED, serialized
  end
end
