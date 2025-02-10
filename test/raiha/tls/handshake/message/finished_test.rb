require "test_helper"
require "support/rfc8448_test_vector"
require "openssl"
require "raiha/tls/handshake"

class RaihaTLSHandshakeFinishedTest < Minitest::Test
  def test_deserialize_rfc8446
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED)
    assert_equal Raiha::TLS::Handshake::Finished, handshake.message.class
    assert_equal OpenSSL::Digest.new("sha256").digest_length, handshake.message.verify_data.bytesize
  end

  def test_serialize_rfc8448
    handshake = Raiha::TLS::Handshake.deserialize(RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED)
    serialized = handshake.serialize
    assert_equal_bin RFC8448_SIMPLE_1RTT_HANDSHAKE_SERVER_FINISHED, serialized
  end
end
