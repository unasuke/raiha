require "test_helper"
require "raiha/quic"

class RaihaNextQUICCryptoRandomTest < Minitest::Test
  Crypto = Raiha::Next::QUIC::Crypto

  def test_secure_random_by_default
    assert_same SecureRandom, Crypto::Random
    bytes = Crypto::Random.bytes(20)
    assert_equal 20, bytes.bytesize
    assert_equal Encoding::BINARY, bytes.encoding
  end

  # Each Ractor of a multi-worker server draws from it.
  def test_usable_from_a_ractor
    assert_equal 8, Ractor.new { Raiha::Next::QUIC::Crypto::Random.bytes(8).bytesize }.value
  end
end
