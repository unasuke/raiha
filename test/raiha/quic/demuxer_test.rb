require "test_helper"
require "raiha/quic/demuxer"
require "raiha/connection"

class RaihaQuicDemuxerTest < Minitest::Test
  def test_routes_long_header_packet_to_registered_connection
    demuxer = Raiha::Quic::Demuxer.new

    cid_bytes = "ABCDEFGH".b
    connection = ConnectionDouble.new
    demuxer.register(cid_bytes, connection)

    datagram = build_long_header_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: cid_bytes,
      scid: "XYZW1234".b
    )

    response = demuxer.dispatch(datagram, peer_address: ["127.0.0.1", 12345])

    assert_nil response
    assert_equal 1, connection.received.length
    assert_equal datagram, connection.received.first[:data]
    assert_equal ["127.0.0.1", 12345], connection.received.first[:peer_address]
  end

  def test_unsupported_version_returns_version_negotiation_response
    demuxer = Raiha::Quic::Demuxer.new(
      supported_versions: [Raiha::Quic::Protocol::Version::V1]
    )

    datagram = build_long_header_datagram(
      version: 0x1a2a3a4a, # not in supported list
      dcid: "ABCDEFGH".b,
      scid: "12345678".b
    )

    response = demuxer.dispatch(datagram)
    refute_nil response

    parsed = Raiha::Quic::Wire::VersionNegotiation.parse(response)
    refute_nil parsed
    # RFC 9000 §6.1: VN swaps SCID/DCID from the triggering packet.
    assert_equal "12345678".b, parsed[:dest_connection_id]
    assert_equal "ABCDEFGH".b, parsed[:src_connection_id]
    assert_includes parsed[:supported_versions], Raiha::Quic::Protocol::Version::V1
  end

  def test_unknown_dcid_with_supported_version_drops_silently
    demuxer = Raiha::Quic::Demuxer.new
    datagram = build_long_header_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: "UNKNOWN!".b,
      scid: "client12".b
    )

    assert_nil demuxer.dispatch(datagram)
  end

  def test_dispatch_drops_truncated_datagram
    demuxer = Raiha::Quic::Demuxer.new
    assert_nil demuxer.dispatch("\xc0\x00\x00".b)
  end

  def test_unregister_stops_routing
    demuxer = Raiha::Quic::Demuxer.new
    cid_bytes = "ABCDEFGH".b
    connection = ConnectionDouble.new
    demuxer.register(cid_bytes, connection)
    demuxer.unregister(cid_bytes)

    datagram = build_long_header_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: cid_bytes,
      scid: "XYZW1234".b
    )

    assert_nil demuxer.dispatch(datagram)
    assert_empty connection.received
  end

  def test_short_header_routes_to_registered_connection
    demuxer = Raiha::Quic::Demuxer.new(server_connection_id_length: 8)
    cid_bytes = "12345678".b
    connection = ConnectionDouble.new
    demuxer.register(cid_bytes, connection)

    datagram = build_short_header_datagram(dcid: cid_bytes, payload_size: 30)
    response = demuxer.dispatch(datagram)

    assert_nil response
    assert_equal 1, connection.received.length
  end

  def test_short_header_unknown_dcid_emits_stateless_reset
    reset_key = "k" * 32
    demuxer = Raiha::Quic::Demuxer.new(
      server_connection_id_length: 8,
      stateless_reset_key: reset_key
    )

    dcid_bytes = "UNKNOWN1".b
    datagram = build_short_header_datagram(dcid: dcid_bytes, payload_size: 60)

    response = demuxer.dispatch(datagram)
    refute_nil response
    assert_operator response.bytesize, :>=, Raiha::Quic::StatelessReset::MIN_PACKET_LENGTH
    assert response.bytesize < datagram.bytesize, "reset must be smaller than the trigger"

    expected_token = Raiha::Quic::StatelessReset.derive_token(reset_key, dcid_bytes)
    assert_equal expected_token, response.byteslice(-Raiha::Quic::StatelessReset::TOKEN_LENGTH, Raiha::Quic::StatelessReset::TOKEN_LENGTH)
  end

  def test_short_header_unknown_dcid_without_reset_key_drops_silently
    demuxer = Raiha::Quic::Demuxer.new(server_connection_id_length: 8)
    datagram = build_short_header_datagram(dcid: "UNKNOWN1".b, payload_size: 60)

    assert_nil demuxer.dispatch(datagram)
  end

  def test_initial_without_token_under_require_retry_emits_retry_packet
    demuxer = Raiha::Quic::Demuxer.new(
      retry_key: "k".b * 32,
      require_retry: true
    )
    odcid = "ABCDEFGH".b
    client_scid = "CL12CL34".b
    datagram = build_initial_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: odcid,
      scid: client_scid,
      token: "".b
    )

    response = demuxer.dispatch(datagram, peer_address: ["192.0.2.5", 4242])
    refute_nil response

    assert Raiha::Quic::Wire::Retry.verify_integrity_tag(
      data: response,
      original_destination_connection_id: odcid
    )
  end

  def test_retry_token_round_trip_marks_initial_validated
    retry_key = "k".b * 32
    demuxer = Raiha::Quic::Demuxer.new(
      retry_key: retry_key,
      require_retry: true
    )
    odcid = "ABCDEFGH".b
    client_scid = "CL12CL34".b
    peer_address = ["192.0.2.5", 4242]
    peer_bytes = "192.0.2.5:4242"

    first = build_initial_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: odcid,
      scid: client_scid,
      token: "".b
    )
    retry_packet = demuxer.dispatch(first, peer_address: peer_address)
    refute_nil retry_packet

    # Pull the SCID and token out of the Retry the demuxer just sent.
    retry_scid, retry_token = parse_retry_packet(retry_packet)

    second = build_initial_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: retry_scid,
      scid: client_scid,
      token: retry_token
    )
    response = demuxer.dispatch(second, peer_address: peer_address)
    assert_nil response
    assert_equal odcid, demuxer.validated_original_dcid(retry_scid),
      "ODCID should be recoverable for the connection factory"
  end

  def test_retry_rejects_token_with_wrong_peer_address
    retry_key = "k".b * 32
    demuxer = Raiha::Quic::Demuxer.new(retry_key: retry_key, require_retry: true)

    odcid = "ABCDEFGH".b
    client_scid = "CL12CL34".b
    first = build_initial_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: odcid, scid: client_scid, token: "".b
    )
    retry_packet = demuxer.dispatch(first, peer_address: ["192.0.2.5", 4242])
    retry_scid, retry_token = parse_retry_packet(retry_packet)

    second = build_initial_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: retry_scid, scid: client_scid, token: retry_token
    )

    # Different peer address: validation must fail and the demuxer
    # silently drops the second Initial.
    response = demuxer.dispatch(second, peer_address: ["198.51.100.7", 9999])
    assert_nil response
    assert_nil demuxer.validated_original_dcid(retry_scid)
  end

  def test_register_accepts_connection_id_object
    demuxer = Raiha::Quic::Demuxer.new
    cid = Raiha::Quic::Protocol::ConnectionID.from_bytes("ABCDEFGH".b)
    connection = ConnectionDouble.new
    demuxer.register(cid, connection)

    datagram = build_long_header_datagram(
      version: Raiha::Quic::Protocol::Version::V1,
      dcid: "ABCDEFGH".b,
      scid: "XYZW1234".b
    )

    demuxer.dispatch(datagram)
    assert_equal 1, connection.received.length
  end

  private def build_initial_datagram(version:, dcid:, scid:, token:)
    buf = String.new(encoding: "BINARY")
    buf << [0xc0].pack("C") # Initial: long header form, fixed bit, type = 0
    buf << [version].pack("N")
    buf << [dcid.bytesize].pack("C")
    buf << dcid
    buf << [scid.bytesize].pack("C")
    buf << scid
    buf << encode_varint(token.bytesize)
    buf << token
    buf << [0].pack("C") # payload length placeholder
    buf
  end

  # Strip the SCID + token from a Retry packet emitted by the demuxer.
  private def parse_retry_packet(packet)
    body = packet.byteslice(0, packet.bytesize - Raiha::Quic::Wire::Retry::INTEGRITY_TAG_LENGTH)
    pos = 1 + 4 # first byte + version
    dcid_length = body.getbyte(pos)
    pos += 1 + dcid_length
    scid_length = body.getbyte(pos)
    pos += 1
    scid = body.byteslice(pos, scid_length)
    pos += scid_length
    token = body.byteslice(pos, body.bytesize - pos)
    [scid, token]
  end

  private def encode_varint(value)
    if value < 64
      [value].pack("C")
    elsif value < 16_384
      [value | 0x4000].pack("n")
    elsif value < 1_073_741_824
      [value | 0x80000000].pack("N")
    else
      [value | 0xc000_0000_0000_0000].pack("Q>")
    end
  end

  private def build_short_header_datagram(dcid:, payload_size:)
    buf = String.new(encoding: "BINARY")
    # Short header: bit 7 = 0, fixed bit (bit 6) = 1.
    buf << [0x40].pack("C")
    buf << dcid
    buf << SecureRandom.random_bytes(payload_size)
    buf
  end

  private def build_long_header_datagram(version:, dcid:, scid:)
    buf = String.new(encoding: "BINARY")
    buf << [0xc0].pack("C")
    buf << [version].pack("N")
    buf << [dcid.bytesize].pack("C")
    buf << dcid
    buf << [scid.bytesize].pack("C")
    buf << scid
    buf << [0].pack("C") # token length (Initial)
    buf << [0].pack("C") # payload length placeholder
    buf
  end

  class ConnectionDouble
    attr_reader :received

    def initialize
      @received = []
    end

    def handle_packet(data, peer_address: nil, ecn: :not_ect)
      @received << { data: data, peer_address: peer_address, ecn: ecn }
    end
  end
end
