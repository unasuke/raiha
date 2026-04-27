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
