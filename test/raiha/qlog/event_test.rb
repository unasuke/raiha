require "test_helper"
require "raiha/qlog"

class RaihaQlogEventTest < Minitest::Test
  def test_base_event_to_h
    event = Raiha::Qlog::Event.new(
      category: :transport,
      event_type: :test_event,
      data: { key: "value" }
    )

    h = event.to_h
    assert_equal "transport:test_event", h[:name]
    assert_equal({ key: "value" }, h[:data])
    assert_kind_of Integer, h[:time]
  end

  def test_base_event_to_json
    event = Raiha::Qlog::Event.new(category: :transport, event_type: :test)
    json = JSON.parse(event.to_json)
    assert_equal "transport:test", json["name"]
  end

  def test_connection_started
    event = Raiha::Qlog::ConnectionEvents::ConnectionStarted.new(
      src_cid: "abc123",
      dest_cid: "def456"
    )

    h = event.to_h
    assert_equal "connectivity:connection_started", h[:name]
    assert_equal "abc123", h[:data][:src_cid]
    assert_equal "def456", h[:data][:dst_cid]
  end

  def test_connection_state_updated
    event = Raiha::Qlog::ConnectionEvents::ConnectionStateUpdated.new(
      old_state: :handshaking,
      new_state: :connected
    )

    h = event.to_h
    assert_equal "connectivity:connection_state_updated", h[:name]
    assert_equal "handshaking", h[:data][:old]
    assert_equal "connected", h[:data][:new]
  end

  def test_connection_closed
    event = Raiha::Qlog::ConnectionEvents::ConnectionClosed.new(
      owner: :local,
      trigger: :idle_timeout
    )

    h = event.to_h
    assert_equal "connectivity:connection_closed", h[:name]
    assert_equal "local", h[:data][:owner]
    assert_equal "idle_timeout", h[:data][:trigger]
    refute h[:data].key?(:error_code)
  end

  def test_connection_closed_with_error
    event = Raiha::Qlog::ConnectionEvents::ConnectionClosed.new(
      owner: :remote,
      trigger: :error,
      error_code: 0x0a,
      reason: "flow control error"
    )

    h = event.to_h
    assert_equal 0x0a, h[:data][:error_code]
    assert_equal "flow control error", h[:data][:reason]
  end

  def test_connection_id_updated
    event = Raiha::Qlog::ConnectionEvents::ConnectionIdUpdated.new(
      owner: :local,
      old_id: "aabb",
      new_id: "ccdd"
    )

    h = event.to_h
    assert_equal "connectivity:connection_id_updated", h[:name]
    assert_equal "aabb", h[:data][:old]
    assert_equal "ccdd", h[:data][:new]
  end

  def test_packet_sent
    event = Raiha::Qlog::TransportEvents::PacketSent.new(
      packet_type: :initial,
      packet_number: 0,
      frames: []
    )

    h = event.to_h
    assert_equal "transport:packet_sent", h[:name]
    assert_equal "initial", h[:data][:header][:packet_type]
    assert_equal 0, h[:data][:header][:packet_number]
    assert_equal [], h[:data][:frames]
  end

  def test_packet_received
    event = Raiha::Qlog::TransportEvents::PacketReceived.new(
      packet_type: "1RTT",
      packet_number: 42,
      frames: []
    )

    h = event.to_h
    assert_equal "transport:packet_received", h[:name]
    assert_equal "1RTT", h[:data][:header][:packet_type]
    assert_equal 42, h[:data][:header][:packet_number]
  end

  def test_packet_dropped
    event = Raiha::Qlog::TransportEvents::PacketDropped.new(
      packet_type: :initial,
      trigger: :decryption_failure
    )

    h = event.to_h
    assert_equal "transport:packet_dropped", h[:name]
    assert_equal "initial", h[:data][:packet_type]
    assert_equal "decryption_failure", h[:data][:trigger]
  end

  def test_parameters_set
    event = Raiha::Qlog::TransportEvents::ParametersSet.new(
      owner: :local,
      parameters: { initial_max_data: 1_048_576, initial_max_streams_bidi: 100 }
    )

    h = event.to_h
    assert_equal "transport:parameters_set", h[:name]
    assert_equal "local", h[:data][:owner]
    assert_equal 1_048_576, h[:data][:initial_max_data]
  end

  def test_key_updated
    event = Raiha::Qlog::SecurityEvents::KeyUpdated.new(
      key_type: :handshake_1rtt,
      generation: 0,
      trigger: :tls
    )

    h = event.to_h
    assert_equal "security:key_updated", h[:name]
    assert_equal "handshake_1rtt", h[:data][:key_type]
    assert_equal 0, h[:data][:generation]
  end

  def test_key_discarded
    event = Raiha::Qlog::SecurityEvents::KeyDiscarded.new(
      key_type: :initial,
      trigger: :tls
    )

    h = event.to_h
    assert_equal "security:key_discarded", h[:name]
    assert_equal "initial", h[:data][:key_type]
  end

  def test_metrics_updated
    event = Raiha::Qlog::RecoveryEvents::MetricsUpdated.new(
      min_rtt: 10,
      smoothed_rtt: 15,
      latest_rtt: 12,
      rtt_variance: 3,
      congestion_window: 14720,
      bytes_in_flight: 1200
    )

    h = event.to_h
    assert_equal "recovery:metrics_updated", h[:name]
    assert_equal 10, h[:data][:min_rtt]
    assert_equal 15, h[:data][:smoothed_rtt]
    assert_equal 14720, h[:data][:congestion_window]
  end

  def test_metrics_updated_partial
    event = Raiha::Qlog::RecoveryEvents::MetricsUpdated.new(
      smoothed_rtt: 20
    )

    h = event.to_h
    assert_equal 20, h[:data][:smoothed_rtt]
    refute h[:data].key?(:min_rtt)
  end

  def test_congestion_state_updated
    event = Raiha::Qlog::RecoveryEvents::CongestionStateUpdated.new(
      old_state: :slow_start,
      new_state: :congestion_avoidance
    )

    h = event.to_h
    assert_equal "recovery:congestion_state_updated", h[:name]
    assert_equal "slow_start", h[:data][:old]
    assert_equal "congestion_avoidance", h[:data][:new]
  end

  def test_packet_lost
    event = Raiha::Qlog::RecoveryEvents::PacketLost.new(
      packet_type: :handshake,
      packet_number: 3,
      trigger: :timeout
    )

    h = event.to_h
    assert_equal "recovery:packet_lost", h[:name]
    assert_equal "handshake", h[:data][:header][:packet_type]
    assert_equal 3, h[:data][:header][:packet_number]
  end
end
