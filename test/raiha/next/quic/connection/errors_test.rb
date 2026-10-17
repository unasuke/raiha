require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# 250 "Errors": what the network sends never raises. A header that does
# not read is dropped, since anyone could have sent it; what breaks a
# packet that opened closes the connection with its error.
class RaihaNextQUICConnectionErrorsTest < Minitest::Test
  include NextQUICPair

  def closed(connection) = [].tap { |events| connection.each_event { events << _1 } }.grep(QUIC::Event::Closed)

  # A second Initial from the client, sealed with its Initial keys, with
  # `payload` for frames.
  def initial(client_datagram, payload, packet_number: 1)
    first = QUIC::Wire::Packet.parse(client_datagram, dcid_length: 8)
    keys = QUIC::Crypto::Initial.derive(dcid: first.header.dcid, version: QUIC::Version::V1).client
    packet = QUIC::Wire::Packet.seal(first.header, packet_number:, packet_number_length: 1, payload: payload.ljust(1100, "\0".b), keys:)
    packet
  end

  def test_a_frame_that_does_not_read_closes
    client = client_connection
    server = server_connection
    datagram = client.transmits(now: 0.0).first.payload
    server.receive(datagram, from: CLIENT, now: 0.0)
    # A CRYPTO frame longer than what is left of the packet.
    server.receive(initial(datagram, "\x06\x00\x7f\xff".b), from: CLIENT, now: 0.0)
    assert server.closing?
    assert_equal [QUIC::ErrorCode::FRAME_ENCODING_ERROR], closed(server).map { _1.error.code }
  end

  # A frame not allowed in Initial packets: PROTOCOL_VIOLATION.
  def test_a_frame_out_of_place_closes
    client = client_connection
    server = server_connection
    datagram = client.transmits(now: 0.0).first.payload
    server.receive(datagram, from: CLIENT, now: 0.0)
    server.receive(initial(datagram, "\x1e".b), from: CLIENT, now: 0.0)
    assert_equal [QUIC::ErrorCode::PROTOCOL_VIOLATION], closed(server).map { _1.error.code }
  end

  # Headers that do not read, or packets that do not open, close nothing.
  def test_forged_packets_close_nothing
    client = client_connection
    server = server_connection
    now = handshake(client, server)
    closed(server)
    ["\xc0\x00\x00\x00\x01".b, "\xc0\x00\x00\x00\x01\x08".b + "x" * 50, "\x40".b + "y" * 60, "\xff".b * 1200].each do |forged|
      server.receive(forged, from: CLIENT, now:)
    end
    refute server.closing?
    assert_empty closed(server)
  end
end
