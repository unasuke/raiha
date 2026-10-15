require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# 250 appendix, acceptance test (1): two connections back to back
# complete the handshake with no socket, Fiber or real time.
class RaihaNextQUICConnectionHandshakeTest < Minitest::Test
  include NextQUICPair

  def test_two_connections_complete_the_handshake
    client = client_connection
    server = server_connection
    handshake(client, server)
    assert client.handshake_complete?
    assert server.handshake_complete?
    [client, server].each do |connection|
      connected = [].tap { |events| connection.each_event { events << _1 } }.grep(QUIC::Event::Connected)
      assert_equal ["hq-interop"], connected.map { _1.handshake.alpn }
    end
  end

  # RFC 9000 "Datagram Size": a client's datagram with an Initial packet
  # in it is 1200 bytes at least.
  def test_the_client_initial_is_padded
    client = client_connection
    transmits = client.transmits(now: 0.0)
    assert_equal 1, transmits.size
    assert_equal QUIC::Connection::MIN_INITIAL_DATAGRAM, transmits.first.payload.bytesize
    assert_equal SERVER, transmits.first.destination
    assert_empty client.transmits(now: 0.0)
  end

  # The first Initial is sealed with keys from its Destination Connection
  # ID, so that the server can read it.
  def test_the_server_reads_the_client_initial
    client = client_connection
    datagram = client.transmits(now: 0.0).first.payload
    packet = QUIC::Wire::Packet.parse(datagram, dcid_length: 8)
    initial = QUIC::Crypto::Initial.derive(dcid: packet.header.dcid, version: QUIC::Version::V1)
    unmasked = packet.unmask(initial.client.header_protection, largest: nil)
    frames = QUIC::Wire::Frame.parse(unmasked.open(initial.client.aead), packet_type: :initial, ack_delay_exponent: 3)
    assert_equal [0], unmasked.packet_number.then { [_1] }
    assert_equal 1, frames.grep(QUIC::Wire::Frame::Crypto).first.data.getbyte(0)
  end
end
