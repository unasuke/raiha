require "test_helper"
require "raiha/quic/ack_handler"
require "raiha/quic/wire/frames/ack_frame"
require "raiha/quic/congestion/rtt_stats"

class RaihaQuicAckHandlerSentPacketHandlerTest < Minitest::Test
  def test_sent_packet_tracking
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    packet_number = handler.get_next_packet_number(:application_data)
    assert_equal 0, packet_number.value

    handler.sent_packet(
      packet_number: packet_number,
      frames: [],
      size: 1200,
      ack_eliciting: true,
      pn_space: :application_data
    )

    assert_equal 1200, handler.bytes_in_flight
  end

  def test_non_ack_eliciting_not_in_flight
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: false,
      pn_space: :application_data
    )

    assert_equal 0, handler.bytes_in_flight
  end

  def test_received_ack_removes_packets
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    3.times do |i|
      handler.sent_packet(
        packet_number: Raiha::Quic::Protocol::PacketNumber.new(i),
        frames: [],
        size: 100,
        ack_eliciting: true,
        pn_space: :application_data
      )
    end

    assert_equal 300, handler.bytes_in_flight

    ack_frame = Raiha::Quic::Wire::Frames::AckFrame.new
    ack_frame.largest_acknowledged = 2
    ack_frame.ack_delay = 0
    ack_frame.ack_ranges = [
      Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 2)
    ]

    handler.received_ack(ack_frame, pn_space: :application_data)
    assert_equal 0, handler.bytes_in_flight
  end

  def test_packet_number_spaces_are_independent
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    initial_pn = handler.get_next_packet_number(:initial)
    handshake_pn = handler.get_next_packet_number(:handshake)
    app_pn = handler.get_next_packet_number(:application_data)

    assert_equal 0, initial_pn.value
    assert_equal 0, handshake_pn.value
    assert_equal 0, app_pn.value
  end

  def test_sequential_packet_numbers
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new

    assert_equal 0, handler.get_next_packet_number(:application_data).value
    assert_equal 1, handler.get_next_packet_number(:application_data).value
    assert_equal 2, handler.get_next_packet_number(:application_data).value
  end

  def test_ack_with_new_ce_count_triggers_congestion_controller
    ce_notifications = 0
    controller = Object.new
    controller.define_singleton_method(:on_packet_sent) { |_| }
    controller.define_singleton_method(:on_packets_acked) { |_| }
    controller.define_singleton_method(:on_packet_lost) { |_| }
    controller.define_singleton_method(:on_ecn_ce) { ce_notifications += 1 }

    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(
      congestion_controller: controller,
      rtt_stats: Raiha::Quic::Congestion::RTTStats.new
    )

    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data
    )

    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = 0
    ack.ack_delay = 0
    ack.ack_ranges = [
      Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)
    ]
    ack.ecn_counts = { ect0: 0, ect1: 0, ecn_ce: 1 }

    handler.received_ack(ack, pn_space: :application_data)
    assert_equal 1, ce_notifications

    # Same ecn_ce on a follow-up ACK must not refire; only an increase does.
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(1),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data
    )
    follow_up = Raiha::Quic::Wire::Frames::AckFrame.new
    follow_up.largest_acknowledged = 1
    follow_up.ack_delay = 0
    follow_up.ack_ranges = [
      Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)
    ]
    follow_up.ecn_counts = { ect0: 0, ect1: 0, ecn_ce: 1 }
    handler.received_ack(follow_up, pn_space: :application_data)
    assert_equal 1, ce_notifications
  end

  def test_time_threshold_declares_old_packet_lost_on_ack
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    lost = [] #: Array[Raiha::Quic::AckHandler::SentPacketHandler::SentPacket]
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(
      rtt_stats: rtt_stats,
      on_packet_lost: ->(packet, _space) { lost << packet }
    )

    old = Time.now - 10.0  # older than any plausible loss_delay
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: old
    )
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(1),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data
    )

    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = 1
    ack.ack_delay = 0
    ack.ack_ranges = [
      Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)
    ]

    handler.received_ack(ack, pn_space: :application_data)

    assert_equal 1, lost.length
    assert_equal 0, lost.first.packet_number.value
  end

  def test_loss_detection_deadline_follows_oldest_in_flight
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(rtt_stats: rtt_stats)

    # No loss_time if nothing has been acked yet.
    assert_nil handler.loss_detection_deadline

    start = Time.now
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: start
    )
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(1),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: start
    )

    # ACK #1 but not #0; #0 is now in loss_time scope because it precedes
    # largest_acked and hasn't crossed loss_delay yet.
    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = 1
    ack.ack_delay = 0
    ack.ack_ranges = [Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)]
    handler.received_ack(ack, pn_space: :application_data, now: start)

    deadline = handler.loss_detection_deadline
    refute_nil deadline
    assert_operator deadline, :>, start
    assert_in_delta rtt_stats.loss_delay, deadline - start, 0.01
  end

  def test_pto_deadline_uses_last_ack_eliciting_sent_time_with_backoff
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(rtt_stats: rtt_stats)

    start = Time.now
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: start
    )

    base = rtt_stats.pto
    assert_in_delta start + base, handler.pto_deadline, 0.001

    # Simulate one prior PTO firing: deadline doubles (exponential backoff).
    handler.instance_variable_set(:@pto_count, 1)
    assert_in_delta start + base * 2, handler.pto_deadline, 0.001
  end

  def test_on_loss_detection_timeout_without_loss_time_fires_pto
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    pto_callbacks = 0
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(
      rtt_stats: rtt_stats,
      on_pto_fired: -> { pto_callbacks += 1 }
    )

    start = Time.now
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: start
    )

    # No ACK arrived, loss_time stays nil. Firing the timer past the PTO
    # deadline should bump pto_count and trigger the callback.
    handler.on_loss_detection_timeout(now: start + rtt_stats.pto + 0.01)
    assert_equal 1, handler.pto_count
    assert_equal 1, pto_callbacks

    # Firing again doubles the backoff and fires another probe.
    handler.on_loss_detection_timeout(now: start + rtt_stats.pto * 4)
    assert_equal 2, handler.pto_count
    assert_equal 2, pto_callbacks
  end

  def test_ack_resets_pto_count
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(
      rtt_stats: rtt_stats,
      on_pto_fired: ->() {}
    )

    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data
    )
    handler.instance_variable_set(:@pto_count, 3)

    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = 0
    ack.ack_delay = 0
    ack.ack_ranges = [Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)]
    handler.received_ack(ack, pn_space: :application_data)

    assert_equal 0, handler.pto_count
  end

  def test_on_loss_detection_timeout_declares_time_threshold_losses
    rtt_stats = Raiha::Quic::Congestion::RTTStats.new
    lost = [] #: Array[Raiha::Quic::AckHandler::SentPacketHandler::SentPacket]
    handler = Raiha::Quic::AckHandler::SentPacketHandler.new(
      rtt_stats: rtt_stats,
      on_packet_lost: ->(packet, _space) { lost << packet }
    )

    start = Time.now
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(0),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: start
    )
    handler.sent_packet(
      packet_number: Raiha::Quic::Protocol::PacketNumber.new(1),
      frames: [],
      size: 100,
      ack_eliciting: true,
      pn_space: :application_data,
      sent_time: start
    )
    ack = Raiha::Quic::Wire::Frames::AckFrame.new
    ack.largest_acknowledged = 1
    ack.ack_delay = 0
    ack.ack_ranges = [Raiha::Quic::Wire::Frames::AckFrame::AckRange.new(gap: 0, ack_range_length: 0)]
    handler.received_ack(ack, pn_space: :application_data, now: start)

    # Not yet past the deadline: no loss fires.
    handler.on_loss_detection_timeout(now: start)
    assert_empty lost

    # Fast-forward past loss_delay: now #0 is time-threshold lost.
    handler.on_loss_detection_timeout(now: start + rtt_stats.loss_delay + 0.01)
    assert_equal [0], lost.map { |p| p.packet_number.value }
  end
end
