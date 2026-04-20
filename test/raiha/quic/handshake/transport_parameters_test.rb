require "test_helper"
require "raiha/quic/handshake/transport_parameters"

class RaihaQuicHandshakeTransportParametersTest < Minitest::Test
  def test_default_values
    params = Raiha::Quic::Handshake::TransportParameters.new
    assert_equal 30_000, params.max_idle_timeout
    assert_equal 65527, params.max_udp_payload_size
    assert_equal 3, params.ack_delay_exponent
    assert_equal 25, params.max_ack_delay
    assert_equal 2, params.active_connection_id_limit
    refute params.disable_active_migration
  end

  def test_serialize_deserialize_roundtrip
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.max_idle_timeout = 60_000
    params.initial_max_data = 1048576
    params.initial_max_stream_data_bidi_local = 65536
    params.initial_max_stream_data_bidi_remote = 65536
    params.initial_max_stream_data_uni = 65536
    params.initial_max_streams_bidi = 100
    params.initial_max_streams_uni = 50
    params.active_connection_id_limit = 4

    serialized = params.serialize
    parsed = Raiha::Quic::Handshake::TransportParameters.deserialize(serialized)

    assert_equal 60_000, parsed.max_idle_timeout
    assert_equal 1048576, parsed.initial_max_data
    assert_equal 65536, parsed.initial_max_stream_data_bidi_local
    assert_equal 65536, parsed.initial_max_stream_data_bidi_remote
    assert_equal 65536, parsed.initial_max_stream_data_uni
    assert_equal 100, parsed.initial_max_streams_bidi
    assert_equal 50, parsed.initial_max_streams_uni
    assert_equal 4, parsed.active_connection_id_limit
  end

  def test_disable_active_migration
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.disable_active_migration = true

    serialized = params.serialize
    parsed = Raiha::Quic::Handshake::TransportParameters.deserialize(serialized)

    assert parsed.disable_active_migration
  end

  def test_connection_id_params
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.original_destination_connection_id = "\x01\x02\x03\x04".b
    params.initial_source_connection_id = "\x05\x06\x07\x08".b

    serialized = params.serialize
    parsed = Raiha::Quic::Handshake::TransportParameters.deserialize(serialized)

    assert_equal "\x01\x02\x03\x04".b, parsed.original_destination_connection_id
    assert_equal "\x05\x06\x07\x08".b, parsed.initial_source_connection_id
  end

  def test_stateless_reset_token
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.stateless_reset_token = "\x00" * 16

    serialized = params.serialize
    parsed = Raiha::Quic::Handshake::TransportParameters.deserialize(serialized)

    assert_equal "\x00" * 16, parsed.stateless_reset_token
  end

  def test_validate_peer_accepts_defaults
    Raiha::Quic::Handshake::TransportParameters.new.validate_peer!
  end

  def test_validate_peer_rejects_small_max_udp_payload_size
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.max_udp_payload_size = 1199

    assert_raises(Raiha::Quic::Qerr::TransportParameterError) { params.validate_peer! }
  end

  def test_validate_peer_rejects_ack_delay_exponent_above_20
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.ack_delay_exponent = 21

    assert_raises(Raiha::Quic::Qerr::TransportParameterError) { params.validate_peer! }
  end

  def test_validate_peer_rejects_max_ack_delay_at_or_above_2_to_14
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.max_ack_delay = 1 << 14

    assert_raises(Raiha::Quic::Qerr::TransportParameterError) { params.validate_peer! }
  end

  def test_validate_peer_rejects_active_connection_id_limit_below_2
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.active_connection_id_limit = 1

    assert_raises(Raiha::Quic::Qerr::TransportParameterError) { params.validate_peer! }
  end

  def test_validate_peer_rejects_excessive_initial_max_streams_bidi
    params = Raiha::Quic::Handshake::TransportParameters.new
    params.initial_max_streams_bidi = (1 << 60) + 1

    assert_raises(Raiha::Quic::Qerr::TransportParameterError) { params.validate_peer! }
  end
end
