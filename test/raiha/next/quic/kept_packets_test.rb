require "raiha/next/test_helper"
require "raiha/next/quic"
require "objspace"

# The packets a connection keeps until their keys come, and their bounds.
class RaihaNextQUICKeptPacketsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  FROM = ["192.0.2.1", 50_000].freeze

  def keep(kept, bytes, level: :handshake, received_at: 0.0)
    kept.keep(bytes, level:, from: FROM, to: nil, ecn: :not_ect, received_at:)
  end

  # No more than PACKETS packets are kept, nor BYTES in all.
  def test_the_bounds
    kept = QUIC::KeptPackets.new
    QUIC::KeptPackets::PACKETS.times { assert keep(kept, "x".b * 100) }
    refute keep(kept, "x".b)
    kept = QUIC::KeptPackets.new
    assert keep(kept, "x".b * (QUIC::KeptPackets::BYTES - 1))
    refute keep(kept, "x".b * 2)
    assert keep(kept, "x".b)
  end

  # What is taken leaves room, and comes in the order it came; the rest
  # stays.
  def test_take
    kept = QUIC::KeptPackets.new
    keep(kept, "a".b, level: :one_rtt)
    keep(kept, "b".b, level: :handshake)
    keep(kept, "c".b * QUIC::KeptPackets::BYTES.pred.pred, level: :one_rtt)
    taken = kept.take { _1 == :one_rtt }
    assert_equal ["a".b, "c".b * QUIC::KeptPackets::BYTES.pred.pred], taken.map(&:bytes)
    assert keep(kept, "d".b * 100)
    assert_equal ["b".b, "d".b * 100], kept.take { true }.map(&:bytes)
    assert kept.empty?
  end

  # A packet is kept in a String of its own, not as a part of the datagram
  # it came in.
  def test_a_packet_does_not_keep_its_datagram
    datagram = "\x01".b * 5000
    tail = datagram.byteslice(4000..)
    assert ObjectSpace.dump(tail).include?('"shared":true'), "a substring to the end is shared"
    kept = QUIC::KeptPackets.new
    keep(kept, tail)
    refute ObjectSpace.dump(kept.take { true }.first.bytes).include?('"shared":true')
  end
end
