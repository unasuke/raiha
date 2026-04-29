require "test_helper"
require "raiha/server"

class RaihaServerTest < Minitest::Test
  def test_initialize
    server = Raiha::Server.new
    assert_empty server.connections
  end

  def test_accept_nonblock_returns_nil_when_empty
    server = Raiha::Server.new
    assert_nil server.accept_nonblock
  end

  def test_close_before_listen
    server = Raiha::Server.new
    server.close # should not raise
  end

  def test_handle_packet_emits_version_negotiation_for_unsupported_version
    server = Raiha::Server.new
    datagram = build_initial(version: 0x1a2a3a4a, dcid: "ABCDEFGH".b, scid: "12345678".b)

    response = server.handle_packet(datagram, ["127.0.0.1", 4433])
    refute_nil response
    parsed = Raiha::Quic::Wire::VersionNegotiation.parse(response)
    refute_nil parsed
  end

  def test_handle_packet_creates_connection_for_first_initial
    server = Raiha::Server.new
    datagram = build_initial(version: Raiha::Quic::Protocol::Version::V1, dcid: "ABCDEFGH".b, scid: "12345678".b)

    server.handle_packet(datagram, ["127.0.0.1", 4433])
    assert_equal 1, server.connections.size

    conn = server.accept_nonblock
    refute_nil conn
    assert_equal :server, conn.perspective.value
  end

  def test_short_header_for_unknown_dcid_emits_stateless_reset_when_key_set
    server = Raiha::Server.new(stateless_reset_key: "k".b * 32)
    datagram = "\x40".b + "UNKNOWN1".b + SecureRandom.random_bytes(40)

    response = server.handle_packet(datagram, ["127.0.0.1", 4433])
    refute_nil response
    assert_operator response.bytesize, :>=, Raiha::Quic::StatelessReset::MIN_PACKET_LENGTH
  end

  private def build_initial(version:, dcid:, scid:)
    buf = String.new(encoding: "BINARY")
    buf << [0xc0].pack("C")
    buf << [version].pack("N")
    buf << [dcid.bytesize].pack("C")
    buf << dcid
    buf << [scid.bytesize].pack("C")
    buf << scid
    buf << [0].pack("C") # token length
    buf << [0].pack("C") # payload length placeholder
    buf
  end
end
