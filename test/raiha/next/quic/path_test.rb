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
  # holding back what would fill it, leaves the window used.
  def test_application_limited
    path = path()
    refute path.app_limited?
    path.transmission_stopped(:drained)
    assert path.app_limited?
    path.transmission_stopped(:congestion)
    refute path.app_limited?
    path.transmission_stopped(:flow_control)
    assert path.app_limited?
    path.transmission_stopped(:pacing)
    refute path.app_limited?
    path.transmission_stopped(:amplification)
    assert path.app_limited?
    10.times { path.add_in_flight(sent_bytes: 1200, ack_eliciting: true, now: 0.0) }
    path.transmission_stopped(:drained)
    refute path.app_limited?
    assert_raises(ArgumentError) { path.transmission_stopped(:bored) }
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
