require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICPathTest < Minitest::Test
  QUIC = Raiha::Next::QUIC

  def path(**config) = QUIC::Path.new(config: QUIC::Config.new(**config))

  def test_starts_from_the_config
    path = path(initial_max_datagram_size: 1350)
    assert_kind_of QUIC::Congestion::Cubic, path.congestion
    assert_equal [13_500, 1350, 10], [path.congestion.window, path.max_datagram_size, path.window_packets]
    assert_equal [0, 0, 0.333], [path.bytes_in_flight, path.ack_eliciting_in_flight, path.rtt.smoothed_rtt]
  end

  def test_in_flight
    path = path()
    path.add_in_flight(sent_bytes: 1200, ack_eliciting: true, now: 0.0)
    path.add_in_flight(sent_bytes: 50, ack_eliciting: false, now: 0.0)
    assert_equal [1250, 1, 2], [path.bytes_in_flight, path.ack_eliciting_in_flight, path.packets_in_flight]
    path.remove_in_flight(sent_bytes: 1200, ack_eliciting: true)
    assert_equal [50, 0, 1], [path.bytes_in_flight, path.ack_eliciting_in_flight, path.packets_in_flight]
  end

  # Loss recovery's design, "app_limited:": only a full window, or pacing
  # holding back what would fill it, leaves the window used. Pacing with
  # nothing waiting holds back nothing (RFC 9002 "Underutilizing the
  # Congestion Window").
  def test_application_limited
    path = path()
    refute path.app_limited?
    path.transmission_stopped(:drained, waiting: true, next_packet_number: 0)
    assert path.app_limited?
    path.transmission_stopped(:congestion, waiting: true, next_packet_number: 0)
    refute path.app_limited?
    path.transmission_stopped(:flow_control, waiting: true, next_packet_number: 0)
    assert path.app_limited?
    path.transmission_stopped(:pacing, waiting: true, next_packet_number: 0)
    refute path.app_limited?
    path.transmission_stopped(:pacing, waiting: false, next_packet_number: 0)
    assert path.app_limited?
    path.transmission_stopped(:amplification, waiting: true, next_packet_number: 0)
    assert path.app_limited?
    10.times { path.add_in_flight(sent_bytes: 1200, ack_eliciting: true, now: 0.0) }
    path.transmission_stopped(:drained, waiting: true, next_packet_number: 0)
    refute path.app_limited?
    assert_raises(ArgumentError) { path.transmission_stopped(:bored, waiting: false, next_packet_number: 0) }
  end

  # Held back by the window or pacing with data waiting, what is
  # acknowledged makes the delivery rate; with nothing waiting, or once no
  # longer held back, it does not.
  def test_delivery_rate
    path = path()
    path.transmission_stopped(:congestion, waiting: false, next_packet_number: 0)
    path.delivered(1200, largest: 0, now: 0.0)
    path.delivered(12_000, largest: 10, now: 0.0625)
    assert_nil path.delivery_rate
    path.transmission_stopped(:pacing, waiting: true, next_packet_number: 11)
    path.delivered(1200, largest: 11, now: 0.125)
    path.delivered(12_000, largest: 21, now: 0.1875)
    assert_in_delta 192_000.0, path.delivery_rate
    path.transmission_stopped(:drained, waiting: false, next_packet_number: 30)
    path.delivered(12_000, largest: 31, now: 0.25)
    path.delivered(12_000, largest: 41, now: 0.3125)
    assert_in_delta 192_000.0, path.delivery_rate
  end

  def test_max_datagram_size
    path = path()
    path.update_max_datagram_size(1500, now: 1.0)
    assert_equal [1500, 3000, 14_720], [path.max_datagram_size, path.congestion.minimum_window, path.congestion.window]
  end

  def test_abandon
    path = path()
    refute path.abandoned?
    path.abandon
    assert path.abandoned?
  end
end
