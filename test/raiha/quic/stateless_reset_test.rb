require "test_helper"
require "raiha/quic"

# RFC 9000 "Stateless Reset".
class RaihaQUICStatelessResetTest < Minitest::Test
  StatelessReset = Raiha::QUIC::StatelessReset

  KEY = ("r" * 32).b

  # The same connection ID gives the same token, another one another.
  def test_token
    token = StatelessReset.token(key: KEY, connection_id: "c".b * 8)
    assert_equal 16, token.bytesize
    assert_equal token, StatelessReset.token(key: KEY, connection_id: "c".b * 8)
    refute_equal token, StatelessReset.token(key: KEY, connection_id: "d".b * 8)
    refute_equal token, StatelessReset.token(key: ("s" * 32).b, connection_id: "c".b * 8)
  end

  # Looks like a short header packet and ends in the token.
  def test_packet
    token = "t".b * 16
    packet = StatelessReset.packet(token:, length: 40, random: Random.new(1))
    assert_equal 40, packet.bytesize
    assert_equal 0b01, packet.getbyte(0) >> 6
    assert packet.end_with?(token)
    assert_equal packet, StatelessReset.packet(token:, length: 40, random: Random.new(1))
    assert_equal 21, StatelessReset.packet(token:, length: 21, random: Random.new(1)).bytesize
    assert_raises(ArgumentError) { StatelessReset.packet(token:, length: 20, random: Random.new(1)) }
  end

  def test_match
    token = "t".b * 16
    packet = StatelessReset.packet(token:, length: 30, random: Random.new(1))
    assert StatelessReset.match?(packet, ["u".b * 16, token])
    refute StatelessReset.match?(packet, ["u".b * 16])
    refute StatelessReset.match?(packet, [])
    refute StatelessReset.match?(token.byteslice(0, 15) + "\x00".b * 5, [token])
  end
end
