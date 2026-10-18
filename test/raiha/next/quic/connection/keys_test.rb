require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9001 "Discarding Unused Keys".
class RaihaNextQUICConnectionKeysTest < Minitest::Test
  include NextQUICPair

  def closed(connection) = [].tap { |events| connection.each_event { events << _1 } }.grep(QUIC::Event::Closed)

  # An Initial packet with `payload` sealed with the Initial keys of
  # `odcid`, as `role` would send it to a connection whose ID is `dcid`.
  def forged_initial(odcid:, dcid:, role:, payload:)
    keys = QUIC::Crypto::Initial.derive(dcid: odcid, version: QUIC::Version::V1).public_send(role)
    header = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid:, scid: "s".b * 8)
    QUIC::Wire::Packet.seal(header, packet_number: 1000, packet_number_length: 2, payload: payload.ljust(1150, "\0".b), keys:)
  end

  # Once the handshake is under way neither end reads Initial packets, so
  # an on-path observer who saw the client's first Destination Connection
  # ID cannot close either with one.
  def test_initial_keys_go
    client = client_connection
    server = server_connection
    first = client.transmits(now: 0.0).first.payload
    server.receive(first, from: CLIENT, now: 0.0)
    reply = server.transmits(now: 0.0).first.payload
    client.receive(reply, from: SERVER, now: 0.0)
    client_header = QUIC::Wire::Packet.parse(first, dcid_length: 8).header
    server_header = QUIC::Wire::Packet.parse(reply, dcid_length: 8).header
    now = handshake(client, server)
    closed(client)
    closed(server)
    close = "\x1c\x00\x00\x00".b
    client.receive(forged_initial(odcid: client_header.dcid, dcid: client_header.scid, role: :server, payload: close), from: SERVER, now:)
    server.receive(forged_initial(odcid: client_header.dcid, dcid: server_header.scid, role: :client, payload: close), from: CLIENT, now:)
    refute client.draining?
    refute server.draining?
    assert_empty closed(client)
    assert_empty closed(server)
  end
end
