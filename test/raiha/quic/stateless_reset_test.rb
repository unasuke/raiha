require "test_helper"
require "raiha/quic/stateless_reset"

class RaihaQuicStatelessResetTest < Minitest::Test
  def test_build_produces_at_least_min_packet_length
    token = "\x00".b * 16
    packet = Raiha::Quic::StatelessReset.build(token)

    assert_operator packet.bytesize, :>=, Raiha::Quic::StatelessReset::MIN_PACKET_LENGTH
    assert_equal token, packet.byteslice(-16, 16)
  end

  def test_build_honors_min_size_when_larger_than_minimum
    token = "\x00".b * 16
    packet = Raiha::Quic::StatelessReset.build(token, min_size: 200)

    assert_equal 200, packet.bytesize
    assert_equal token, packet.byteslice(-16, 16)
  end

  def test_build_sets_fixed_bit_and_clears_header_form_bit
    token = "\x00".b * 16
    packet = Raiha::Quic::StatelessReset.build(token)

    first = packet.getbyte(0)
    assert_equal 0, first & 0x80, "header form bit should be 0 (short header)"
    assert_equal 0x40, first & 0x40, "fixed bit should be 1"
  end

  def test_build_rejects_non_16_byte_tokens
    assert_raises(ArgumentError) { Raiha::Quic::StatelessReset.build("short".b) }
    assert_raises(ArgumentError) { Raiha::Quic::StatelessReset.build("\x00".b * 15) }
    assert_raises(ArgumentError) { Raiha::Quic::StatelessReset.build("\x00".b * 17) }
  end

  def test_match_token_detects_trailing_token
    token = "abcdefghijklmnop".b
    datagram = ("\x00".b * 20) + token

    assert Raiha::Quic::StatelessReset.match_token?(datagram, [token])
  end

  def test_match_token_returns_false_without_match
    token = "abcdefghijklmnop".b
    datagram = ("\x00".b * 20) + "different_token_".b

    refute Raiha::Quic::StatelessReset.match_token?(datagram, [token])
  end

  def test_match_token_returns_false_for_short_datagram
    token = "abcdefghijklmnop".b
    # 20 bytes is below the 21-byte minimum even though the trailing bytes match.
    datagram = "\x00".b * 4 + token

    refute Raiha::Quic::StatelessReset.match_token?(datagram, [token])
  end

  def test_match_token_returns_false_with_empty_token_set
    datagram = "\x00".b * 40
    refute Raiha::Quic::StatelessReset.match_token?(datagram, [])
  end

  def test_match_token_handles_multiple_candidate_tokens
    active = "ACTIVETOKEN_____".b[0, 16]
    other = "OTHERONE________".b[0, 16]
    datagram = ("\x00".b * 20) + active

    assert Raiha::Quic::StatelessReset.match_token?(datagram, [other, active])
  end
end
