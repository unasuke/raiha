require "test_helper"
require "raiha/quic/wire/long_header"
require "raiha/quic/wire/short_header"

class RaihaQuicWireLongHeaderTest < Minitest::Test
  def test_parse_initial_packet
    # Build a minimal Initial packet header
    buf = Raiha::Quic::Wire::Buffer.new
    first_byte = 0xc0 | (0x00 << 4) | 0x00  # Long header, Initial, PN length 1
    buf.write_uint8(first_byte)
    buf.write_uint32(0x00000001) # Version 1
    buf.write_uint8(8)           # DCID length
    buf.write("\x01\x02\x03\x04\x05\x06\x07\x08".b)
    buf.write_uint8(0)           # SCID length
    buf.write_varint(0)          # Token length
    buf.write_varint(20)         # Payload length

    buf.seek(0)
    header = Raiha::Quic::Wire::LongHeader.parse(buf)

    assert header.long_header?
    refute header.short_header?
    assert header.initial?
    refute header.handshake?
    refute header.zero_rtt?
    refute header.retry?
    assert_equal 0x00000001, header.version
    assert_equal 8, header.destination_connection_id.length
    assert_equal 0, header.source_connection_id.length
    assert_equal 20, header.payload_length
    assert_equal 1, header.packet_number_length
  end

  def test_parse_handshake_packet
    buf = Raiha::Quic::Wire::Buffer.new
    first_byte = 0xc0 | (0x02 << 4) | 0x01  # Long header, Handshake, PN length 2
    buf.write_uint8(first_byte)
    buf.write_uint32(0x00000001)
    buf.write_uint8(4)
    buf.write("\xaa\xbb\xcc\xdd".b)
    buf.write_uint8(4)
    buf.write("\x11\x22\x33\x44".b)
    buf.write_varint(100)

    buf.seek(0)
    header = Raiha::Quic::Wire::LongHeader.parse(buf)

    assert header.handshake?
    assert_equal 4, header.destination_connection_id.length
    assert_equal 4, header.source_connection_id.length
    assert_equal 100, header.payload_length
    assert_equal 2, header.packet_number_length
  end

  def test_serialize_initial_roundtrip
    header = Raiha::Quic::Wire::LongHeader.new
    header.packet_type = Raiha::Quic::Wire::LongHeader::PacketType::INITIAL
    header.version = 0x00000001
    header.destination_connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes("\x01\x02\x03\x04".b)
    header.source_connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes("".b)
    header.packet_number_length = 1
    header.token = "".b

    serialized = header.serialize
    refute_empty serialized
    assert_equal 0xc0, serialized.getbyte(0) & 0xf0  # Long header + Initial
  end

  def test_header_parse_dispatches_long_header
    buf = Raiha::Quic::Wire::Buffer.new
    buf.write_uint8(0xc0) # Long header
    buf.write_uint32(1)   # Version
    buf.write_uint8(0)    # DCID len
    buf.write_uint8(0)    # SCID len
    buf.write_varint(0)   # Token len (Initial)
    buf.write_varint(0)   # Payload len

    buf.seek(0)
    header = Raiha::Quic::Wire::Header.parse(buf)
    assert_instance_of Raiha::Quic::Wire::LongHeader, header
  end
end

class RaihaQuicWireShortHeaderTest < Minitest::Test
  def test_parse_short_header
    buf = Raiha::Quic::Wire::Buffer.new
    first_byte = 0x40 | 0x04 | 0x01  # Fixed bit + key_phase + PN length 2
    buf.write_uint8(first_byte)
    buf.write("\x01\x02\x03\x04\x05\x06\x07\x08".b)

    buf.seek(0)
    header = Raiha::Quic::Wire::ShortHeader.parse(buf, connection_id_length: 8)

    refute header.long_header?
    assert header.short_header?
    assert header.key_phase
    refute header.spin_bit
    assert_equal 2, header.packet_number_length
    assert_equal 8, header.destination_connection_id.length
  end

  def test_serialize_roundtrip
    header = Raiha::Quic::Wire::ShortHeader.new
    header.destination_connection_id = Raiha::Quic::Protocol::ConnectionID.from_bytes("\xab\xcd".b)
    header.packet_number_length = 1
    header.key_phase = false
    header.spin_bit = true

    serialized = header.serialize
    buf = Raiha::Quic::Wire::Buffer.new(serialized)
    parsed = Raiha::Quic::Wire::ShortHeader.parse(buf, connection_id_length: 2)

    assert parsed.spin_bit
    refute parsed.key_phase
    assert_equal 1, parsed.packet_number_length
    assert_equal "\xab\xcd".b, parsed.destination_connection_id.serialize
  end
end
