require "raiha/next/test_helper"
require "raiha/next/quic"
require "raiha/next/support/quic_recovery"

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

  # The Config's startup wraps the controller until it is done, and the
  # path takes the controller back then.
  def test_startup
    path = path(startup: QUIC::Congestion::Startup::RapidStart)
    startup = path.congestion
    assert_kind_of QUIC::Congestion::Startup::RapidStart, startup
    startup.on_ack(acked_bytes: 12_000, largest_acked_sent_at: 0.5, latest_rtt: 0.05, smoothed_rtt: 0.05, min_rtt: 0.05, app_limited: false,
      now: 0.55)
    startup.on_loss(lost_bytes: 1200, largest_lost_sent_at: 0.5, persistent: false, now: 0.6)
    assert_same startup, path.congestion
    startup.on_ack(acked_bytes: 1200, largest_acked_sent_at: 0.7, latest_rtt: 0.05, smoothed_rtt: 0.05, min_rtt: 0.05, app_limited: false,
      now: 0.75)
    assert_kind_of QUIC::Congestion::Cubic, path.congestion
    assert_same path.congestion, path.congestion
  end

  # Before the path's first RTT sample, the window sending goes by is no
  # more than RFC 9002's initial window, however large the Config's; from
  # it, the controller's.
  # The window keeps to RFC 9002's initial window until an ACK tells the
  # congestion controller an RTT: a sample with no ACK, as a Retry's, does
  # not lift it.
  def test_window_before_an_rtt_sample
    path = path(initial_window: Ractor.shareable_lambda { |max_datagram_size| 20 * max_datagram_size })
    assert_equal [12_000, 24_000], [path.window, path.congestion.window]
    path.rtt.update(latest_rtt: 0.05, ack_delay: 0.0, max_ack_delay: 0.025, handshake_confirmed: false, now: 1.0)
    assert_equal 12_000, path.window
    path.add_in_flight(sent_bytes: 1200, ack_eliciting: true, now: 1.0)
    path.remove_in_flight(sent_bytes: 1200, ack_eliciting: true)
    path.acked(acked_bytes: 1200, largest_acked_sent_at: 1.0, sampled: false, now: 1.05)
    assert_equal [25_200, 25_200], [path.window, path.congestion.window]
  end

  def test_max_datagram_size
    path = path()
    path.update_max_datagram_size(1500, now: 1.0)
    assert_equal [1500, 3000, 14_720], [path.max_datagram_size, path.congestion.minimum_window, path.congestion.window]
  end

  # A path searches for its MTU from what it carries: a probe at a time,
  # and one through makes the path carry that much; asked again, the
  # search goes on as it is. With no search, there is no probe.
  def test_mtu_search
    path = path()
    assert_nil path.mtu_probe_size
    path.search_mtu(up_to: 1472)
    assert_equal 1472, path.mtu_probe_size
    path.mtu_probe_sent(1472)
    assert_nil path.mtu_probe_size
    path.mtu_probe_acked(1472, now: 1.0)
    assert_equal [1472, 2944], [path.max_datagram_size, path.congestion.minimum_window]
    path.search_mtu(up_to: 1500)
    assert_nil path.mtu_probe_size
  end

  # Two PTOs in a row with nothing of the path's acknowledged take a
  # larger path back to 1200 as persistent congestion does; one does not,
  # nor two with an ACK in between.
  def test_ptos_in_a_row
    path = path()
    path.update_max_datagram_size(1472, now: 1.0)
    path.probe_timed_out(now: 2.0)
    path.add_in_flight(sent_bytes: 1200, ack_eliciting: true, now: 2.0)
    path.remove_in_flight(sent_bytes: 1200, ack_eliciting: true)
    path.acked(acked_bytes: 1200, largest_acked_sent_at: 2.0, sampled: false, now: 2.5)
    path.probe_timed_out(now: 3.0)
    assert_equal 1472, path.max_datagram_size
    path.probe_timed_out(now: 4.0)
    assert_equal 1200, path.max_datagram_size
  end

  # Persistent congestion on a path that carries more than 1200 bytes
  # takes it back to 1200, and its search starts over; on one of 1200, it
  # changes nothing.
  def test_a_black_hole
    path = path()
    path.search_mtu(up_to: 1472)
    path.mtu_probe_sent(1472)
    path.mtu_probe_acked(1472, now: 1.0)
    path.persistent_congestion(now: 2.0)
    assert_equal [1200, nil], [path.max_datagram_size, path.mtu_probe_size]
    path.search_mtu(up_to: 1472)
    assert_equal 1472, path.mtu_probe_size
    path.persistent_congestion(now: 3.0)
    assert_equal [1200, 1472], [path.max_datagram_size, path.mtu_probe_size]
  end

  # The tracer hears each change of the path's datagrams, and the end of
  # its search: through at the largest, given up on halfway, or gone back
  # to 1200 on persistent congestion.
  def test_mtu_updates_traced
    tracer = NextQUICRecovery::RecordingTracer.new
    path = QUIC::Path.new(config: QUIC::Config.new, tracer:)
    path.search_mtu(up_to: 1472)
    path.mtu_probe_acked(1472, now: 1.0)
    path.persistent_congestion(now: 2.0)
    path.search_mtu(up_to: 1220)
    3.times { path.mtu_probe_lost(1220, now: 3.0) }
    assert_equal [[1200, 1472, true, 1.0], [1472, 1200, false, 2.0], [1200, 1200, true, 3.0]],
      tracer.of(:mtu_updated).map { _1.values_at(:old, :new, :done, :now) }
  end

  def test_abandon
    path = path()
    refute path.abandoned?
    path.abandon
    assert path.abandoned?
  end

  # A datagram on the path fills in the addresses the path does not know
  # yet, and leaves those it knows.
  def test_addresses
    path = QUIC::Path.new(config: QUIC::Config.new, remote: ["192.0.2.1", 443])
    assert_nil path.local
    path.learn(local: ["198.51.100.1", 50_000], remote: ["203.0.113.9", 443])
    assert_equal [["198.51.100.1", 50_000], ["192.0.2.1", 443]], [path.local, path.remote]
  end

  # RFC 9000 "Path Validation": a challenge is due at once, and again an
  # interval on, the interval doubled each time, until the deadline; the
  # answer to one in a datagram short of 1200 bytes validates the address
  # and makes the next due at once, in a full one, whose answer ends it.
  def test_validation
    path = QUIC::Path.new(config: QUIC::Config.new, destination_connection_id: "c".b * 8)
    path.start_validation(now: 1.0, interval: 0.5, deadline: 4.0)
    assert_equal [true, true, "c".b * 8, 1.0], [path.validating?, path.challenge_due?(1.0), path.destination_connection_id, path.validation_timeout]
    path.challenge_sent("a".b * 8, full_size: false, now: 1.0)
    path.challenge_sent("b".b * 8, full_size: false, now: 1.5)
    assert_equal [false, 2.5], [path.challenge_due?(2.4), path.validation_timeout]
    refute path.responded("x".b * 8, now: 2.0)
    assert path.responded("a".b * 8, now: 2.0)
    assert_equal [true, true, true, nil], [path.validated?, path.full_size_due?, path.challenge_due?(2.0), path.amplification_budget]
    path.challenge_sent("c".b * 8, full_size: true, now: 2.0)
    assert path.responded("c".b * 8, now: 2.1)
    assert_equal [false, false, nil], [path.validating?, path.full_size_due?, path.validation_timeout]
  end

  def test_validation_fails_at_the_deadline
    path = path()
    path.start_validation(now: 1.0, interval: 0.5, deadline: 4.0)
    refute path.validation_failed?(3.9)
    assert path.validation_failed?(4.0)
    assert_equal 4.0, path.validation_deadline
  end

  # A path the peer's port alone tells apart takes over what the other
  # learned, the search for its MTU too, which sends again the probe out
  # on the other, as what became of it goes there; the other starts
  # learning over and keeps what it has in flight.
  def test_take_over
    old = path(initial_max_datagram_size: 1350)
    old.add_in_flight(sent_bytes: 1350, ack_eliciting: true, now: 0.0)
    old.rtt.update(latest_rtt: 0.05, ack_delay: 0.0, max_ack_delay: 0.025, handshake_confirmed: true, now: 1.0)
    old.ecn_validated(now: 1.0)
    old.search_mtu(up_to: 1472)
    3.times { old.mtu_probe_lost(1472, now: 1.0) }
    old.mtu_probe_sent(1411)
    congestion = old.congestion
    new = path()
    new.take_over(old)
    assert_equal [0.05, 1350, :capable, 0], [new.rtt.smoothed_rtt, new.max_datagram_size, new.ecn_state, new.bytes_in_flight]
    assert_same congestion, new.congestion
    assert_equal [1411, nil], [new.mtu_probe_size, old.mtu_probe_size]
    assert_equal [0.333, :testing, 1350], [old.rtt.smoothed_rtt, old.ecn_state, old.bytes_in_flight]
    refute_same congestion, old.congestion
  end

  # Until the remote address is validated, three times what came on the
  # path may go on it (RFC 9000 "Address Validation"); once it is, there is
  # no limit.
  def test_amplification_budget
    path = path()
    refute path.validated?
    assert_equal 0, path.amplification_budget
    path.datagram_received(1200)
    path.datagram_sent(1000)
    assert_equal 2600, path.amplification_budget
    path.validate
    path.datagram_sent(5000)
    assert path.validated?
    assert_nil path.amplification_budget
  end
end
