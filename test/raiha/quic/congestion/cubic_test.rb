require "test_helper"
require "raiha/quic/congestion/cubic"

class RaihaQuicCongestionCubicTest < Minitest::Test
  def test_initial_window
    cubic = Raiha::Quic::Congestion::Cubic.new
    assert_equal 12000, cubic.congestion_window # 10 * 1200
  end

  def test_initial_slow_start
    cubic = Raiha::Quic::Congestion::Cubic.new
    assert cubic.in_slow_start?
    refute cubic.in_congestion_avoidance?
  end

  def test_slow_start_increase
    cubic = Raiha::Quic::Congestion::Cubic.new
    initial_congestion_window = cubic.congestion_window

    cubic.on_packet_sent(1200)
    packet = Data.define(:size).new(size: 1200)
    cubic.on_packets_acked([packet])

    assert cubic.congestion_window > initial_congestion_window
    assert cubic.in_slow_start?
  end

  def test_congestion_event_reduces_window
    cubic = Raiha::Quic::Congestion::Cubic.new
    cubic.on_packet_sent(1200)

    congestion_window_before = cubic.congestion_window
    packet = Data.define(:size).new(size: 1200)
    cubic.on_packet_lost(packet)

    assert cubic.congestion_window < congestion_window_before
    refute cubic.in_slow_start?
  end

  def test_minimum_congestion_window
    cubic = Raiha::Quic::Congestion::Cubic.new
    cubic.instance_variable_set(:@congestion_window, 100)
    cubic.on_packet_sent(100)

    packet = Data.define(:size).new(size: 100)
    cubic.on_packet_lost(packet)

    assert cubic.congestion_window >= 2400 # MIN_WINDOW_PACKETS * MAX_DATAGRAM_SIZE
  end

  def test_can_send
    cubic = Raiha::Quic::Congestion::Cubic.new
    assert cubic.can_send?

    cubic.on_packet_sent(12000)
    refute cubic.can_send?
  end

  def test_available_congestion_window
    cubic = Raiha::Quic::Congestion::Cubic.new
    assert_equal 12000, cubic.available_congestion_window

    cubic.on_packet_sent(5000)
    assert_equal 7000, cubic.available_congestion_window
  end

  def test_bytes_in_flight_tracking
    cubic = Raiha::Quic::Congestion::Cubic.new
    assert_equal 0, cubic.bytes_in_flight

    cubic.on_packet_sent(1200)
    assert_equal 1200, cubic.bytes_in_flight

    packet = Data.define(:size).new(size: 1200)
    cubic.on_packets_acked([packet])
    assert_equal 0, cubic.bytes_in_flight
  end

  def test_slow_start_threshold_set_on_loss
    cubic = Raiha::Quic::Congestion::Cubic.new
    assert_equal Float::INFINITY, cubic.slow_start_threshold

    cubic.on_packet_sent(1200)
    packet = Data.define(:size).new(size: 1200)
    cubic.on_packet_lost(packet)

    refute_equal Float::INFINITY, cubic.slow_start_threshold
    assert_equal cubic.congestion_window, cubic.slow_start_threshold
  end

  def test_on_ecn_ce_reduces_window_like_loss
    cubic = Raiha::Quic::Congestion::Cubic.new
    initial = cubic.congestion_window

    cubic.on_ecn_ce

    assert_operator cubic.congestion_window, :<, initial
    refute cubic.in_slow_start?
    assert_equal cubic.congestion_window, cubic.slow_start_threshold
  end
end
