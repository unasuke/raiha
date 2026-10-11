require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICConfigTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  Config = QUIC::Config

  def test_defaults
    config = Config.new
    assert_equal [30.0, 65_527, 768 * 1024, 512 * 1024, 100, 3, 0.025, 3, 4, false, nil],
      config.to_h.values_at(:max_idle_timeout, :max_udp_payload_size, :initial_max_data, :initial_max_stream_data_uni,
        :initial_max_streams_bidi, :initial_max_streams_uni, :max_ack_delay, :ack_delay_exponent, :active_connection_id_limit,
        :disable_active_migration, :max_datagram_frame_size)
    assert_equal [[QUIC::Version::V1], 8, 1200, 6 * 1024 * 1024, 15 * 1024 * 1024, 15 * 1024 * 1024],
      config.to_h.values_at(:versions, :connection_id_length, :initial_max_datagram_size, :max_stream_receive_window,
        :max_receive_window, :max_send_buffer)
  end

  # Shareable between Ractors, without freezing what the caller passed.
  def test_shareable
    versions = [QUIC::Version::V1]
    config = Config.new(versions:)
    assert Ractor.shareable?(config)
    refute versions.frozen?
    assert Ractor.shareable?(config.with(versions: [QUIC::Version::V1]))
    assert_equal 30.0, Ractor.new(config) { |shared| shared.max_idle_timeout }.value
  end

  def test_with
    config = Config.new
    longer = config.with(max_idle_timeout: 60.0)
    assert_equal [30.0, 60.0], [config.max_idle_timeout, longer.max_idle_timeout]
    assert_raises(ArgumentError) { config.with(ack_delay_exponent: 21) }
  end

  # The rules of the transport parameters hold here too.
  def test_transport_parameter_rules
    [{ max_udp_payload_size: 1199 }, { ack_delay_exponent: 21 }, { max_ack_delay: 16.384 }, { active_connection_id_limit: 1 },
     { initial_max_streams_bidi: (1 << 60) + 1 }, { max_idle_timeout: -1.0 }, { max_datagram_frame_size: -1 }].each do |fields|
      assert_raises(ArgumentError, fields.inspect) { Config.new(**fields) }
    end
  end

  def test_implementation_settings
    [{ versions: [] }, { versions: [QUIC::Version::V1.with(number: 0x6b3343cf)] }, { connection_id_length: 21 },
     { connection_id_length: -1 }, { initial_max_datagram_size: 1199 }, { max_send_buffer: 0 }].each do |fields|
      assert_raises(ArgumentError, fields.inspect) { Config.new(**fields) }
    end
    assert_equal 0, Config.new(connection_id_length: 0).connection_id_length
  end

  # The receive windows can grow from the initial ones.
  def test_windows
    assert_raises(ArgumentError) { Config.new(initial_max_stream_data_bidi_remote: 7 * 1024 * 1024) }
    assert_raises(ArgumentError) { Config.new(initial_max_data: 16 * 1024 * 1024) }
    assert_raises(ArgumentError) { Config.new(max_stream_receive_window: 11 * 1024 * 1024) }
    assert Config.new(max_stream_receive_window: 10 * 1024 * 1024, max_receive_window: 15 * 1024 * 1024)
  end

  # Until CUBIC comes, NewReno is the default; a name becomes its class.
  def test_congestion_control
    assert_same QUIC::Congestion::NewReno, Config.new.congestion_control
    assert_same QUIC::Congestion::NewReno, Config.new(congestion_control: :new_reno).congestion_control
    own = Class.new(QUIC::Congestion::NewReno)
    assert_same own, Config.new(congestion_control: own).congestion_control
    assert_raises(ArgumentError) { Config.new(congestion_control: :bbr) }
  end

  # RFC 9002 "Initial and Minimum Congestion Window".
  def test_initial_window
    window = Config.new.initial_window
    assert_equal [12_000, 14_720, 18_000], [1200, 1472, 9000].map { |mds| window.call(mds) }
    doubled = Ractor.shareable_lambda { |mds| 20 * mds }
    config = Config.new(initial_window: doubled)
    assert_same doubled, config.initial_window
    assert Ractor.shareable?(config)
  end

  def test_initial_window_misuse
    # A lambda made in a method has the test for its self, which no Ractor
    # can share.
    assert_raises(ArgumentError) { Config.new(initial_window: ->(mds) { 10 * mds }) }
    assert_raises(ArgumentError) { Config.new(initial_window: Ractor.shareable_lambda { |mds| mds }) }
    assert_raises(ArgumentError) { Config.new(initial_window: Ractor.shareable_lambda { |mds| mds * 2.5 }) }
  end

  def test_transport_parameters
    config = Config.new(max_idle_timeout: 10.0, max_datagram_frame_size: 65_535)
    client = config.transport_parameters(initial_source_connection_id: "c".b * 8)
    assert_equal [10.0, 65_535, 768 * 1024, "c".b * 8, nil],
      client.to_h.values_at(:max_idle_timeout, :max_datagram_frame_size, :initial_max_data, :initial_source_connection_id,
        :original_destination_connection_id)
    assert_equal 0, Config.new.transport_parameters(initial_source_connection_id: "".b).max_datagram_frame_size
    server = config.transport_parameters(initial_source_connection_id: "s".b * 8, original_destination_connection_id: "o".b * 8,
      stateless_reset_token: "t".b * 16)
    assert_equal server, QUIC::TransportParameters.decode(server.encode, sender: :server)
  end
end
