require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9002 "Probe Timeout", as loss recovery's design, "Probes", has a
# connection send them: what is new, else the oldest packet's duties
# again, else a PING.
class RaihaNextQUICConnectionPtoTest < Minitest::Test
  include NextQUICPair

  def crypto_offsets(datagram, dcid)
    packet = QUIC::Wire::Packet.parse(datagram, dcid_length: 8)
    keys = QUIC::Crypto::Initial.derive(dcid:, version: QUIC::Version::V1).client
    payload = packet.unmask(keys.header_protection, largest: nil).open(keys.aead)
    QUIC::Wire::Frame.parse(payload, packet_type: :initial, ack_delay_exponent: 3).grep(QUIC::Wire::Frame::Crypto).map(&:offset)
  end

  # A server that says nothing: at the PTO the client sends its
  # ClientHello again, twice, each in a padded datagram.
  def test_the_client_hello_again
    client = client_connection
    first = client.transmits(now: 0.0).first.payload
    dcid = QUIC::Wire::Packet.parse(first, dcid_length: 8).header.dcid
    now = client.next_timeout
    assert_in_delta 0.999, now, 0.001
    client.handle_timeout(now:)
    probes = client.transmits(now:)
    assert_equal [1200, 1200], probes.map { _1.payload.bytesize }
    assert_equal [[0], [0]], probes.map { crypto_offsets(_1.payload, dcid) }
    assert_empty client.transmits(now:)
    server = server_connection
    server.receive(probes.first.payload, from: CLIENT, now:)
    refute_empty server.transmits(now:)
  end

  # The client's last flight lost on the way: its PTO sends Finished
  # again, and the server completes.
  def test_a_lost_finished
    client = client_connection
    server = server_connection
    now = 0.0
    client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
    server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) }
    client.transmits(now:)
    refute server.handshake_complete?
    now = client.next_timeout
    client.handle_timeout(now:)
    client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
    assert server.handshake_complete?
  end
end
