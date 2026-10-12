require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# RFC 9000 "ECN Validation" and RFC 9002 "Congestion Control" with ECN, as
# loss recovery's design, "ECN validation and CE", applies them.
class RaihaNextQUICRecoveryEcnTest < Minitest::Test
  include NextQUICRecovery

  ECNCounts = QUIC::Wire::Frame::Ack::ECNCounts

  # NewReno that keeps the order of what it was told.
  class Spy < Raiha::Next::QUIC::Congestion::NewReno
    def calls = @calls ||= []

    def on_ecn_ce(**keywords)
      calls << [:on_ecn_ce, keywords]
      super
    end

    def on_loss(**keywords)
      calls << [:on_loss, keywords]
      super
    end
  end

  def spied(tracer: nil)
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(role: :server, config:, path: QUIC::Path.new(config:, tracer:), tracer:)
  end

  def counts(ect0, ce = 0, ect1 = 0) = ECNCounts.new(ect0:, ect1:, ce:)

  def acked_with(recovery, ranges, ecn, now:)
    recovery.on_ack_received(packet_type: :handshake, ack: QUIC::Wire::Frame::Ack.new(ranges:, delay: 0.0, ecn:), now:)
  end

  # Every packet is marked ECT(0) while the path is testing or capable.
  def test_marks_and_validation
    tracer = RecordingTracer.new
    recovery = spied(tracer:)
    path = recovery.path
    2.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_equal [:testing, :ect0], [path.ecn_state, path.ecn]
    acked_with(recovery, [0..1], counts(2), now: 0.1)
    assert_equal :capable, path.ecn_state
    assert_equal [{ old: :testing, new: :capable, now: 0.1 }], tracer.of(:ecn_state_updated)
    assert_equal :ect0, path.ecn
  end

  # Each rule of the counts fails the path for good.
  def test_counts_that_fail
    {
      "no counts" => [nil],
      "ECT(1)" => [counts(2, 0, 1)],
      "more ECT(0) than sent" => [counts(5)],
      "too few marks" => [counts(1)],
      "counts that go down" => [counts(2), counts(1, 1)]
    }.each do |name, sequence|
      recovery = spied
      path = recovery.path
      4.times { send_packet(recovery, :handshake, now: 0.0) }
      acked_with(recovery, [0..1], sequence.first, now: 0.1)
      acked_with(recovery, [2..3], sequence.last, now: 0.2) if sequence.size > 1
      assert_equal :failed, path.ecn_state, name
      assert_equal :not_ect, path.ecn, name
    end
  end

  # An ACK that does not raise the largest acknowledged is not validated:
  # it may well lack the counts.
  def test_only_an_ack_raising_the_largest_is_validated
    recovery = spied
    3.times { send_packet(recovery, :handshake, now: 0.0) }
    acked_with(recovery, [2..2], counts(1), now: 0.1)
    acked_with(recovery, [2..2, 0..0], nil, now: 0.2)
    assert_equal :capable, recovery.path.ecn_state
  end

  # A CE mark that grew tells the congestion controller once, with the time
  # the largest newly acknowledged packet was sent, before any loss.
  def test_ce
    recovery = spied
    send_packet(recovery, :handshake, now: 0.0)
    send_packet(recovery, :handshake, now: 0.5)
    3.times { send_packet(recovery, :handshake, now: 0.6) }
    acked_with(recovery, [4..4, 2..2], counts(1, 1), now: 0.7)
    calls = recovery.path.congestion.calls
    assert_equal [[:on_ecn_ce, { largest_acked_sent_at: 0.6, now: 0.7 }]], calls.select { _1.first == :on_ecn_ce }
    assert_equal %i[on_ecn_ce on_loss], calls.map(&:first)
    acked_with(recovery, [3..3], counts(2, 1), now: 0.8)
    assert_equal 1, calls.count { _1.first == :on_ecn_ce }
  end

  # A failed path heeds no counts, CE marks included.
  def test_a_failed_path_ignores_ce
    recovery = spied
    3.times { send_packet(recovery, :handshake, now: 0.0) }
    acked_with(recovery, [0..0], nil, now: 0.1)
    acked_with(recovery, [1..1], counts(0, 1), now: 0.2)
    assert_empty recovery.path.congestion.calls
  end

  # RFC 9000 "ECN Validation": every ECT(0) packet lost while testing.
  def test_all_marked_packets_lost
    recovery = spied
    2.times { send_packet(recovery, :handshake, now: 0.0) }
    assert_equal QUIC::Recovery::Probe.new(space: :handshake, packets: 2), recovery.on_timeout(now: 1.0).probe
    4.times { send_packet(recovery, :handshake, now: 1.0) }
    recovery.path.ecn_lost(6, now: 2.0)
    assert_equal :failed, recovery.path.ecn_state
    other = spied
    2.times { send_packet(other, :handshake, now: 0.0) }
    other.path.ecn_lost(1, now: 1.0)
    assert_equal :testing, other.path.ecn_state
  end
end
