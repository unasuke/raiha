require "test_helper"
require "support/quic_pair"

# RFC 9000 "Handling Version Negotiation Packets", for a client of version
# 1 alone.
class RaihaQUICConnectionVersionNegotiationTest < Minitest::Test
  include QUICPair

  # A client that has sent its first Initial, and the header of it.
  def started
    client = client_connection
    [client, QUIC::Wire::Packet.parse(client.transmits(now: 0.0).first.payload, dcid_length: 8).header]
  end

  def negotiation(header, versions: [0x0a0a0a0a], dcid: header.scid, scid: header.dcid)
    QUIC::Wire::VersionNegotiation.new(dcid:, scid:, versions:).encode
  end

  # A Version Negotiation without version 1 that echoes the client's
  # connection IDs: the client gives up, sending nothing.
  def test_the_client_abandons_the_connection
    client, header = started
    client.receive(negotiation(header), from: SERVER, now: 0.01)
    assert client.closed?
    assert_equal QUIC::ErrorCode::CONNECTION_REFUSED, client.close_reason.code
    closed = [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::Closed)
    assert_equal [true], closed.map(&:by_peer)
    assert_empty client.transmits(now: 0.01)
    assert_nil client.next_timeout
  end

  def test_one_that_lists_version_1_is_dropped
    client, header = started
    client.receive(negotiation(header, versions: [0x0a0a0a0a, QUIC::Version::V1.number]), from: SERVER, now: 0.01)
    refute client.closed?
  end

  # Echoing both connection IDs shows the server saw the Initial.
  def test_one_that_does_not_echo_is_dropped
    client, header = started
    client.receive(negotiation(header, dcid: "x".b * 8), from: SERVER, now: 0.01)
    client.receive(negotiation(header, scid: "x".b * 8), from: SERVER, now: 0.01)
    refute client.closed?
  end

  def test_one_after_the_server_answered_is_dropped
    client = client_connection
    server = server_connection
    first = client.transmits(now: 0.0).first.payload
    header = QUIC::Wire::Packet.parse(first, dcid_length: 8).header
    server.receive(first, from: CLIENT, now: 0.0)
    server.transmits(now: 0.0).each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    client.receive(negotiation(header), from: SERVER, now: 0.01)
    refute client.closed?
  end
end
