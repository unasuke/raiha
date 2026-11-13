require "test_helper"
require "raiha/quic"

class RaihaNextQUICCryptoMacTest < Minitest::Test
  Mac = Raiha::QUIC::Crypto::Mac

  # RFC 4231 test case 2.
  def test_hmac_sha256
    assert_equal ["5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"].pack("H*"),
      Mac.digest("Jefe".b, "what do ya want for nothing?".b)
  end

  def test_same
    assert Mac.same?("abc".b, "abc".b)
    refute Mac.same?("abc".b, "abd".b)
    refute Mac.same?("abc".b, "ab".b)
  end
end
