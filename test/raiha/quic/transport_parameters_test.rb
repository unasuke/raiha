require "test_helper"
require "raiha/quic"

class RaihaNextQUICTransportParametersTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  TP = QUIC::TransportParameters

  def tp(id, value) = QUIC::Wire::Varint.encode(id) + QUIC::Wire::Varint.encode(value.bytesize) + value.b

  def varint(value) = QUIC::Wire::Varint.encode(value)

  SCID = "c".b * 8

  # Parameters from a client, with the initial_source_connection_id every
  # end sends.
  def decode(bytes) = TP.decode(bytes.b + tp(0x0f, SCID), sender: :client)

  def with_scid(**fields) = TP.new(initial_source_connection_id: SCID, **fields)

  def assert_rejected(bytes, message = nil, sender: :client)
    error = assert_raises(QUIC::Wire::Malformed, message) { TP.decode(bytes.b, sender:) }
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
    assert_equal with_scid, decode("")
  end

  def test_encode
    parameters = TP.new(max_idle_timeout: 30.0, max_ack_delay: 0.02, disable_active_migration: true, initial_max_streams_bidi: 100)
    assert_equal_bin tp(0x01, varint(30_000)) + tp(0x08, varint(100)) + tp(0x0b, varint(20)) + tp(0x0c, ""), parameters.encode
  end

  def test_round_trip
    parameters = with_scid(
      max_idle_timeout: 30.0, max_udp_payload_size: 1452, initial_max_data: 786_432,
      initial_max_stream_data_bidi_local: 524_288, initial_max_stream_data_bidi_remote: 524_288, initial_max_stream_data_uni: 524_288,
      initial_max_streams_bidi: 100, initial_max_streams_uni: 3, ack_delay_exponent: 8, max_ack_delay: 0.1,
      disable_active_migration: true, active_connection_id_limit: 4, max_datagram_frame_size: 65_535
    )
    assert_equal parameters, TP.decode(parameters.encode, sender: :client)
  end

  # RFC 9000 "Reserved Transport Parameters": unknown IDs, the reserved
  # 31 * N + 27 among them, are skipped whatever they hold.
  def test_unknown_and_reserved_are_ignored
    bytes = tp(27, "\xff\xff") + tp(31 * 1000 + 27, "") + tp(0x3fff, "x" * 300) + tp(0x04, varint(10))
    assert_equal with_scid(initial_max_data: 10), decode(bytes)
  end

  def test_values_against_the_rules
    {
      "max_udp_payload_size under 1200" => tp(0x03, varint(1199)),
      "ack_delay_exponent over 20" => tp(0x0a, varint(21)),
      "max_ack_delay of 2^14 ms" => tp(0x0b, varint(1 << 14)),
      "active_connection_id_limit under 2" => tp(0x0e, varint(1)),
      "initial_max_streams_bidi past 2^60" => tp(0x08, varint((1 << 60) + 1)),
      "initial_max_streams_uni past 2^60" => tp(0x09, varint((1 << 60) + 1))
    }.each { |name, bytes| assert_rejected(bytes + tp(0x0f, SCID), name) }
    assert_equal 16.383, decode(tp(0x0b, varint((1 << 14) - 1))).max_ack_delay
    assert_equal 1 << 60, decode(tp(0x08, varint(1 << 60))).initial_max_streams_bidi
  end

  def test_encodings_against_the_rules
    {
      "bytes past a varint" => tp(0x04, varint(10) + "\x00"),
      "a varint cut short" => tp(0x04, "\x40"),
      "disable_active_migration with a value" => tp(0x0c, "\x01"),
      "a length past the end" => "\x04\x05\x01",
      "an ID cut short" => "\x40"
    }.each { |name, bytes| assert_rejected(tp(0x0f, SCID) + bytes, name) }
  end

  def preferred_address
    TP::PreferredAddress.new(ipv4: ["192.0.2.1", 443], ipv6: ["2001:db8::1", 8443], connection_id: "p".b * 8, stateless_reset_token: "r".b * 16)
  end

  def server_parameters
    with_scid(original_destination_connection_id: "o".b * 8, stateless_reset_token: "s".b * 16,
      preferred_address:, retry_source_connection_id: "y".b * 8)
  end

  def test_server_parameters
    assert_equal server_parameters, TP.decode(server_parameters.encode, sender: :server)
    # Zero-length connection IDs are connection IDs too.
    empty = TP.new(original_destination_connection_id: "".b, initial_source_connection_id: "".b)
    assert_equal empty, TP.decode(empty.encode, sender: :server)
  end

  # RFC 9000 "Preferred Address": all zeros stand for no address of the
  # family.
  def test_preferred_address
    expected = "\xc0\x00\x02\x01\x01\xbb".b + "\x20\x01\x0d\xb8".b + "\x00".b * 11 + "\x01\x20\xfb\x08".b + "p".b * 8 + "r".b * 16
    assert_equal_bin expected, preferred_address.encode
    only_v6 = preferred_address.with(ipv4: nil)
    assert_equal_bin "\x00".b * 6, only_v6.encode.byteslice(0, 6)
    assert_equal only_v6, TP::PreferredAddress.read(QUIC::Wire::Reader.new(only_v6.encode))
    assert_raises(ArgumentError) { preferred_address.with(ipv4: ["2001:db8::1", 443]) }
    assert_raises(ArgumentError) { preferred_address.with(ipv6: ["192.0.2.1", 443]) }
  end

  # RFC 9000 "Transport Parameter Definitions": the parameters only a
  # server sends.
  # A client moves to IPv6 before IPv4, of the families it sends to, and
  # to no unspecified or multicast address, nor a loopback one unless the
  # server's is.
  def test_choosing_a_preferred_address
    both = %i[ipv4 ipv6]
    server = ["192.0.2.9", 443]
    assert_equal ["2001:db8::1", 8443], preferred_address.choose(families: both, server:)
    assert_equal ["192.0.2.1", 443], preferred_address.choose(families: %i[ipv4], server:)
    assert_nil preferred_address.with(ipv6: nil).choose(families: %i[ipv6], server:)
    ["::", "ff02::1", "::1", "::ffff:224.0.0.1"].each do |host|
      assert_equal ["192.0.2.1", 443], preferred_address.with(ipv6: [host, 443]).choose(families: both, server:), host
    end
    ["0.0.0.0", "224.0.0.1", "127.0.0.1"].each do |host|
      assert_nil preferred_address.with(ipv4: [host, 443], ipv6: nil).choose(families: both, server:), host
    end
    assert_equal ["::1", 443], preferred_address.with(ipv6: ["::1", 443]).choose(families: both, server: ["127.0.0.1", 443])
  end

  def test_server_only_parameters_from_a_client
    { 0x00 => "o" * 8, 0x02 => "s" * 16, 0x0d => preferred_address.encode, 0x10 => "y" * 8 }.each do |id, value|
      assert_rejected(tp(0x0f, SCID) + tp(id, value), "0x#{id.to_s(16)}")
    end
  end

  # RFC 9000 "Authenticating Connection IDs".
  def test_required_connection_ids
    assert_rejected(tp(0x04, varint(1)), "no initial_source_connection_id")
    assert_rejected(tp(0x0f, SCID), "no original_destination_connection_id", sender: :server)
    assert_rejected(tp(0x00, "o" * 8), "no initial_source_connection_id", sender: :server)
  end

  def test_connection_ids_and_tokens_against_the_rules
    {
      "a 21-byte connection ID" => tp(0x00, "o" * 8) + tp(0x0f, "c" * 21),
      "a stateless reset token of 15 bytes" => tp(0x00, "o" * 8) + tp(0x0f, SCID) + tp(0x02, "s" * 15),
      "a preferred address with an empty connection ID" =>
        tp(0x00, "o" * 8) + tp(0x0f, SCID) + tp(0x0d, "\x00" * 24 + "\x00" + "r" * 16),
      "a preferred address cut short" => tp(0x00, "o" * 8) + tp(0x0f, SCID) + tp(0x0d, preferred_address.encode.byteslice(0, 40)),
      "a preferred address with zero-length connection IDs" => tp(0x00, "o" * 8) + tp(0x0f, "") + tp(0x0d, preferred_address.encode)
    }.each { |name, bytes| assert_rejected(bytes, name, sender: :server) }
  end

  # Known vulnerabilities (QUIC), decoding the same bytes twice: a
  # parameter twice is an error, whichever it is.
  def test_duplicates
    assert_rejected(tp(0x0f, SCID) + tp(0x04, varint(10)) + tp(0x04, varint(1 << 30)), "initial_max_data twice")
    assert_rejected(tp(0x0f, SCID) + tp(0x0f, "d" * 8), "initial_source_connection_id twice")
    assert_rejected(tp(0x0f, SCID) + tp(0x0c, "") + tp(0x0c, ""), "disable_active_migration twice")
    assert_rejected(tp(0x0f, SCID) + tp(27, "") + tp(27, ""), "a reserved parameter twice")
    assert_rejected(tp(0x0f, SCID) + tp(0x3fff, "a") + tp(0x3fff, "b"), "an unknown parameter twice")
    # The same ID in another encoding is the same ID.
    assert_rejected(tp(0x0f, SCID) + tp(0x04, varint(10)) + "\x40\x04\x01\x0a", "initial_max_data twice, the second in two bytes")
  end

  def test_misuse
    [{ max_udp_payload_size: 1199 }, { ack_delay_exponent: 21 }, { max_ack_delay: 16.384 }, { active_connection_id_limit: 1 },
     { initial_max_streams_uni: (1 << 60) + 1 }, { max_idle_timeout: -1.0 }, { initial_source_connection_id: "c".b * 21 },
     { stateless_reset_token: "s".b * 15 }, { initial_max_data: -1 }, { initial_max_stream_data_uni: 1 << 62 },
     { max_datagram_frame_size: -1 }, { max_idle_timeout: (1 << 62) / 1000.0 }].each do |fields|
      assert_raises(ArgumentError, fields.inspect) { TP.new(**fields) }
    end
  end
end
