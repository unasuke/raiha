require "test_helper"
require "support/quic_pair"

# A server connection takes the packets of only an ACK its Endpoint sent
# the client before the connection was made as its own.
class RaihaQUICConnectionEarlyAckTest < Minitest::Test
  include QUICPair

  EARLY = [QUIC::Connection::EarlyAck.new(packet_number: 0, bytes: 50, time: 0.0)].freeze

  # The client's first Initial, and its header.
  def first_initial
    datagram = client_connection.transmits(now: 0.0).first.payload
    [datagram, QUIC::Wire::Packet.parse(datagram, dcid_length: 8).header]
  end

  # The client's Initial packet `packet_number` to the server with `frames`,
  # padded to 1200 bytes.
  def client_initial(header, frames, packet_number:)
    keys = QUIC::Crypto::Initial.derive(dcid: header.dcid, version: QUIC::Version::V1).client
    long = QUIC::Wire::LongHeader.new(type: :initial, version: QUIC::Version::V1, dcid: header.dcid, scid: header.scid)
    payload = QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3).ljust(1200, "\0".b)
    QUIC::Wire::Packet.seal(long, packet_number:, packet_number_length: 2, payload:, keys:)
  end

  # The server's Initial packets go on from the number after the early
  # ACK's, and its bytes count toward the amplification limit.
  def test_the_packet_numbers_and_the_bytes
    datagram, header = first_initial
    server = server_connection(early_acks: EARLY)
    server.receive(datagram, from: CLIENT, now: 0.0)
    assert_equal 3 * datagram.bytesize - 50, server.path.amplification_budget
    keys = QUIC::Crypto::Initial.derive(dcid: header.dcid, version: QUIC::Version::V1).server
    sent = server.transmits(now: 0.0).first.payload
    assert_equal 1, QUIC::Wire::Packet.parse(sent, dcid_length: 8).unmask(keys.header_protection, largest: nil).packet_number
  end

  # An ACK of the early ACK's packet is of one the connection sent; without
  # it, the same is a PROTOCOL_VIOLATION.
  def test_an_ack_of_the_early_ack
    [[EARLY, nil], [[], QUIC::ErrorCode::PROTOCOL_VIOLATION]].each do |early_acks, code|
      datagram, header = first_initial
      server = server_connection(early_acks:)
      server.receive(datagram, from: CLIENT, now: 0.0)
      ack = QUIC::Wire::Frame::Ack.new(ranges: [0..0], delay: 0.0)
      server.receive(client_initial(header, [ack], packet_number: 1), from: CLIENT, now: 0.01)
      code ? assert_equal(code, server.close_reason&.code) : assert_nil(server.close_reason)
    end
  end

  # The early ACKs are the connection's first packets, numbered from 0.
  def test_early_acks_in_order
    assert_raises(ArgumentError) do
      server_connection(early_acks: [QUIC::Connection::EarlyAck.new(packet_number: 1, bytes: 50, time: 0.0)])
    end
  end
end
