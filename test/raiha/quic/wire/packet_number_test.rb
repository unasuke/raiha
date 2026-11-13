require "test_helper"
require "raiha/quic"

class RaihaNextQUICWirePacketNumberTest < Minitest::Test
  PacketNumber = Raiha::QUIC::Wire::PacketNumber

  # RFC 9000 appendix A.2.
  def test_rfc9000_encoding_examples
    assert_equal 2, PacketNumber.length(0xac5c02, largest_acked: 0xabe8b3)
    assert_equal 3, PacketNumber.length(0xace8fe, largest_acked: 0xabe8b3)
    assert_equal_bin "\x5c\x02".b, PacketNumber.encode(0xac5c02, 2)
    assert_equal_bin "\xac\xe8\xfe".b, PacketNumber.encode(0xace8fe, 3)
  end

  # RFC 9000 appendix A.3, and the short header packet of RFC 9001
  # appendix A.5, whose number 654360564 travels as 0xbff4.
  def test_rfc_decoding_examples
    assert_equal 0xa82f9b32, PacketNumber.decode(0x9b32, length: 2, largest: 0xa82f30ea)
    assert_equal_bin "\xbf\xf4".b, PacketNumber.encode(654_360_564, 2)
    assert_equal 654_360_564, PacketNumber.decode(0xbff4, length: 2, largest: 654_360_563)
  end

  def test_length_without_acknowledgments
    assert_equal 1, PacketNumber.length(0, largest_acked: nil)
    assert_equal 1, PacketNumber.length(127, largest_acked: nil)
    assert_equal 2, PacketNumber.length(128, largest_acked: nil)
    assert_equal 4, PacketNumber.length((1 << 31) - 1, largest_acked: nil)
    assert_raises(ArgumentError) { PacketNumber.length(1 << 31, largest_acked: nil) }
  end

  def test_length_misuse
    assert_raises(ArgumentError) { PacketNumber.length(5, largest_acked: 5) }
    assert_raises(ArgumentError) { PacketNumber.encode(1, 0) }
    assert_raises(ArgumentError) { PacketNumber.encode(1, 5) }
  end

  # A field longer than needed is allowed; RFC 9001 appendix A.2 sends
  # packet 2 in four bytes.
  def test_longer_field
    assert_equal_bin "\x00\x00\x00\x02".b, PacketNumber.encode(2, 4)
    assert_equal 2, PacketNumber.decode(2, length: 4, largest: nil)
  end

  def test_decoding_picks_the_nearest
    assert_equal 5, PacketNumber.decode(5, length: 1, largest: nil)
    # Past the window's edge upward, and a late packet from below it.
    assert_equal 0x102, PacketNumber.decode(0x02, length: 1, largest: 0xfe)
    assert_equal 0xff, PacketNumber.decode(0xff, length: 1, largest: 0x100)
    # Never past 2^62 - 1.
    assert_equal PacketNumber::MAX - 0xff, PacketNumber.decode(0x00, length: 1, largest: PacketNumber::MAX - 1)
  end

  # Whatever the receiver has processed between what was acknowledged and
  # the packet before this one, it decodes the number the sender meant.
  def test_round_trip
    [[nil, 0], [nil, 200], [0, 1], [0xabe8b3, 0xac5c02], [0xabe8b3, 0xace8fe], [1_000_000, 1_000_000 + 0x7fff_ffff]].each do |acked, number|
      length = PacketNumber.length(number, largest_acked: acked)
      truncated = PacketNumber.encode(number, length).unpack1("H*").to_i(16)
      [acked, number - 1].uniq.each do |largest|
        assert_equal number, PacketNumber.decode(truncated, length:, largest:), [acked, number, largest].inspect
      end
    end
  end
end
