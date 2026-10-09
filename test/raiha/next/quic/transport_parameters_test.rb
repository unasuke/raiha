require "raiha/next/test_helper"
require "raiha/next/quic"

class RaihaNextQUICTransportParametersTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  TP = QUIC::TransportParameters

  def tp(id, value) = QUIC::Wire::Varint.encode(id) + QUIC::Wire::Varint.encode(value.bytesize) + value.b

  def varint(value) = QUIC::Wire::Varint.encode(value)

  def assert_rejected(bytes, message = nil)
    error = assert_raises(QUIC::Wire::Malformed, message) { TP.decode(bytes) }
    assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, error.code
  end

  # RFC 9000 "Transport Parameter Definitions", and RFC 9221 for
  # max_datagram_frame_size.
  def test_defaults
    defaults = TP.new
    assert_equal [0.0, 65_527, 0, 3, 0.025, false, 2, 0],
      defaults.to_h.values_at(:max_idle_timeout, :max_udp_payload_size, :initial_max_data, :ack_delay_exponent,
        :max_ack_delay, :disable_active_migration, :active_connection_id_limit, :max_datagram_frame_size)
    assert_equal_bin "".b, defaults.encode
    assert_equal defaults, TP.decode("".b)
  end

  def test_encode
    parameters = TP.new(max_idle_timeout: 30.0, max_ack_delay: 0.02, disable_active_migration: true, initial_max_streams_bidi: 100)
    assert_equal_bin tp(0x01, varint(30_000)) + tp(0x08, varint(100)) + tp(0x0b, varint(20)) + tp(0x0c, ""), parameters.encode
  end

  def test_round_trip
    parameters = TP.new(
      max_idle_timeout: 30.0, max_udp_payload_size: 1452, initial_max_data: 786_432,
      initial_max_stream_data_bidi_local: 524_288, initial_max_stream_data_bidi_remote: 524_288, initial_max_stream_data_uni: 524_288,
      initial_max_streams_bidi: 100, initial_max_streams_uni: 3, ack_delay_exponent: 8, max_ack_delay: 0.1,
      disable_active_migration: true, active_connection_id_limit: 4, max_datagram_frame_size: 65_535
    )
    assert_equal parameters, TP.decode(parameters.encode)
  end

  # RFC 9000 "Reserved Transport Parameters": unknown IDs, the reserved
  # 31 * N + 27 among them, are skipped whatever they hold.
  def test_unknown_and_reserved_are_ignored
    bytes = tp(27, "\xff\xff") + tp(31 * 1000 + 27, "") + tp(0x3fff, "x" * 300) + tp(0x04, varint(10))
    assert_equal TP.new(initial_max_data: 10), TP.decode(bytes)
  end

  def test_values_against_the_rules
    {
      "max_udp_payload_size under 1200" => tp(0x03, varint(1199)),
      "ack_delay_exponent over 20" => tp(0x0a, varint(21)),
      "max_ack_delay of 2^14 ms" => tp(0x0b, varint(1 << 14)),
      "active_connection_id_limit under 2" => tp(0x0e, varint(1)),
      "initial_max_streams_bidi past 2^60" => tp(0x08, varint((1 << 60) + 1)),
      "initial_max_streams_uni past 2^60" => tp(0x09, varint((1 << 60) + 1))
    }.each { |name, bytes| assert_rejected(bytes, name) }
    assert_equal 16.383, TP.decode(tp(0x0b, varint((1 << 14) - 1))).max_ack_delay
    assert_equal 1 << 60, TP.decode(tp(0x08, varint(1 << 60))).initial_max_streams_bidi
  end

  def test_encodings_against_the_rules
    {
      "bytes past a varint" => tp(0x04, varint(10) + "\x00"),
      "a varint cut short" => tp(0x04, "\x40"),
      "disable_active_migration with a value" => tp(0x0c, "\x01"),
      "a length past the end" => "\x04\x05\x01",
      "an ID cut short" => "\x40"
    }.each { |name, bytes| assert_rejected(bytes.b, name) }
  end

  def test_misuse
    [{ max_udp_payload_size: 1199 }, { ack_delay_exponent: 21 }, { max_ack_delay: 16.384 }, { active_connection_id_limit: 1 },
     { initial_max_streams_uni: (1 << 60) + 1 }, { max_idle_timeout: -1.0 }].each do |fields|
      assert_raises(ArgumentError, fields.inspect) { TP.new(**fields) }
    end
  end
end
