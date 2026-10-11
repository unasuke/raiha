require "raiha/next/test_helper"
require "raiha/next/support/quic_recovery"

# RFC 9002 "Persistent Congestion", as loss recovery's design, "Persistent
# congestion", applies it.
class RaihaNextQUICRecoveryPersistentCongestionTest < Minitest::Test
  include NextQUICRecovery

  # NewReno that keeps whether each loss was persistent congestion.
  class Spy < Raiha::Next::QUIC::Congestion::NewReno
    def persistent = @persistent ||= []

    def on_loss(persistent:, **)
      self.persistent << persistent
      super
    end
  end

  def spied
    config = QUIC::Config.new(congestion_control: Spy)
    recovery(role: :server, config:, path: QUIC::Path.new(config:))
  end

  def persistent(recovery) = recovery.path.congestion.persistent

  # An RTT sample of 0.1 s at 1.0: the period is
  # (0.1 + 4 * 0.05 + 0.025) * 3 = 0.975 s.
  def sampled
    recovery = spied
    send_packet(recovery, :handshake, now: 0.9)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(0..0), now: 1.0)
    recovery
  end

  # Packets 1 to 16 sent every 0.1 s from 1.1, then 17 at 3.0, acknowledged
  # at `ack_at`; `acked` and `not_eliciting` change some on the way.
  def lose_a_run(recovery, ack_at: 3.1, acked: nil, not_eliciting: nil)
    (1..16).each { |number| send_packet(recovery, :handshake, now: 1.0 + number * 0.1, ack_eliciting: number != not_eliciting) }
    recovery.on_ack_received(packet_type: :handshake, ack: ack(acked..acked), now: 2.0) if acked
    send_packet(recovery, :handshake, now: 3.0)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(17..17), now: ack_at)
  end

  def test_a_long_run_of_losses
    recovery = sampled
    outcome = lose_a_run(recovery, ack_at: 3.3)
    assert_equal (1..16).to_a, outcome.lost.map(&:packet_number)
    assert_equal [true], persistent(recovery)
    # The minimum is taken again from the latest sample.
    assert_in_delta 0.3, recovery.path.rtt.min_rtt
  end

  def test_a_short_run_is_no_persistent_congestion
    recovery = sampled
    (1..5).each { |number| send_packet(recovery, :handshake, now: 1.0 + number * 0.1) }
    send_packet(recovery, :handshake, now: 1.6)
    send_packet(recovery, :handshake, now: 1.6)
    send_packet(recovery, :handshake, now: 1.6)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(8..8), now: 1.7)
    assert_equal [false], persistent(recovery)
  end

  # A packet acknowledged in between ends the run.
  def test_a_gap_ends_the_run
    recovery = sampled
    lose_a_run(recovery, acked: 8)
    assert_equal [false, false], persistent(recovery)
  end

  # A lost packet that elicits no ACK keeps the run going.
  def test_a_packet_eliciting_no_ack_keeps_the_run
    recovery = sampled
    lose_a_run(recovery, not_eliciting: 8)
    assert_equal [true], persistent(recovery)
  end

  # Only packets sent after the first RTT sample count.
  def test_before_the_first_sample
    recovery = spied
    (0..15).each { |number| send_packet(recovery, :handshake, now: 1.0 + number * 0.1) }
    send_packet(recovery, :handshake, now: 3.0)
    recovery.on_ack_received(packet_type: :handshake, ack: ack(16..16), now: 3.1)
    assert_equal [false], persistent(recovery)
  end
end
