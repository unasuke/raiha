require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICRecoveryDutyTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Duty = QUIC::Recovery::Duty

  # Loss recovery's design, the table of duties: one kind for each frame
  # sent again or acknowledged to some effect, and none for PING, PADDING,
  # CONNECTION_CLOSE, PATH_CHALLENGE, PATH_RESPONSE and DATAGRAM.
  def test_the_closed_set
    assert_equal %w[
      Stream Crypto Ack ResetStream StopSending MaxData MaxStreamData MaxStreams
      DataBlocked StreamDataBlocked StreamsBlocked NewConnectionID RetireConnectionID NewToken HandshakeDone
    ], Duty::ALL.map { |kind| kind.name.split("::").last }
    assert_equal Duty.constants.sort - [:ALL], Duty::ALL.map { |kind| kind.name.split("::").last.to_sym }.sort
  end

  def test_values
    assert_equal Duty::Stream.new(stream_id: 4, offset: 0, length: 100, fin: true), Duty::Stream.new(4, 0, 100, true)
    assert_equal Duty::HandshakeDone.new, Duty::HandshakeDone.new
    case Duty::MaxStreamData.new(stream_id: 4, maximum: 1000)
    in Duty::MaxStreamData(stream_id:, maximum:)
      assert_equal [4, 1000], [stream_id, maximum]
    end
  end

  def test_sent_packet
    path = QUIC::Path.new(config: QUIC::Config.new)
    duties = [Duty::Ack.new(largest: 3), Duty::Crypto.new(offset: 0, length: 100)].freeze
    packet = QUIC::Recovery::SentPacket.new(packet_number: 5, time_sent: 1.0, sent_bytes: 1200, ack_eliciting: true, in_flight: true,
      path:, duties:, pmtu_probe: false, ecn: :ect0)
    assert_same path, packet.path
    assert_equal [5, 1200, :ect0], [packet.packet_number, packet.sent_bytes, packet.ecn]
    case packet
    in { duties: [Duty::Ack(largest:), *] }
      assert_equal 3, largest
    end
  end
end
