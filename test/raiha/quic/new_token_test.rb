require "test_helper"
require "raiha/quic"

# The token of a NEW_TOKEN frame: valid for the IP address and version it
# was made for until it expires, whatever the port, each one of its own,
# and nothing of the connection it came on in the clear.
class RaihaNextQUICNewTokenTest < Minitest::Test
  NewToken = Raiha::Next::QUIC::NewToken
  KEY = NewToken.key("\x01".b * 32)
  NOW = Time.at(1_800_000_000)
  ADDRESS = ["192.0.2.1", 50_000].freeze
  V1 = 0x00000001

  def mint(address: ADDRESS, version: V1, time: NOW) = NewToken.mint(key: KEY, address:, version:, time:, random: Random.new(1))

  def valid?(token, address: ADDRESS, version: V1, time: NOW, key: KEY) = NewToken.valid?(token, key:, address:, version:, time:)

  def test_a_token_for_its_address_and_version
    token = mint
    assert_equal NewToken::LENGTH, token.bytesize
    assert_equal NewToken::KIND, token.getbyte(0)
    assert valid?(token)
    assert valid?(token, address: ["192.0.2.1", 1234])
    assert valid?(token, time: NOW + NewToken::LIFETIME)
    refute valid?(token, time: NOW + NewToken::LIFETIME + 1)
    refute valid?(token, address: ["192.0.2.9", 50_000])
    refute valid?(token, version: 0x6b3343cf)
    refute valid?(token, key: NewToken.key("\x02".b * 32))
  end

  def test_tokens_that_are_not_ones
    token = mint
    forged = token.dup.tap { |t| t.setbyte(-1, t.getbyte(-1) ^ 1) }
    refute valid?(forged)
    refute valid?(token.byteslice(0, token.bytesize - 1))
    refute valid?("\x00".b + token.byteslice(1..))
    refute valid?(mint(address: ["2001:db8::1", 443]))
    assert valid?(mint(address: ["2001:db8::1", 443]), address: ["2001:db8::1", 8443])
  end

  # A token tells nothing of the connection it came on, and none is like
  # another.
  def test_each_token_is_its_own
    tokens = Array.new(3) { NewToken.mint(key: KEY, address: ADDRESS, version: V1, time: NOW, random: Random.new) }
    assert_equal 3, tokens.uniq.size
    tokens.each { |token| refute_includes token, IPAddr.new(ADDRESS.first).hton }
  end
end
