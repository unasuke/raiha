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

  # The types of the packets coalesced in `datagram`.
  def packet_types(datagram)
    types = []
    offset = 0
    while offset < datagram.bytesize
      packet = QUIC::Wire::Packet.parse(datagram, offset:, dcid_length: 8)
      types << (packet.header.is_a?(QUIC::Wire::LongHeader) ? packet.header.type : :one_rtt)
      offset = packet.end_offset
    end
    types
  end

  # A server whose first flight is lost: at the PTO of its Initial space it
  # probes its Handshake space too, each probe datagram carrying both, as
  # the client may have the keys of only one (RFC 9002 "Sending Probe
  # Packets"); one of them is enough for the client to go on.
  def test_the_server_probes_initial_and_handshake_together
    client = client_connection
    server = server_connection
    now = 0.0
    client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
    server.transmits(now:)
    now = server.next_timeout
    server.handle_timeout(now:)
    probes = server.transmits(now:)
    assert_equal 2, probes.size
    probes.each { |probe| assert_equal %i[initial handshake], packet_types(probe.payload).uniq }
    client.receive(probes.last.payload, from: SERVER, now:)
    assert client.handshake_complete?
  end

  # A server whose first flight is lost hears the ClientHello again, from
  # the client's PTO: it sends its flight again at once, Initial and
  # Handshake together, as a client that sends CRYPTO data again has not had
  # all of it, twice a connection at most (RFC 9002 "Speeding up Handshake
  # Completion"); the third time it acknowledges alone. The server's own
  # timer is never run here.
  def test_the_server_sends_again_at_once_on_a_client_hello_again
    client = client_connection
    server = server_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.1) }
    server.transmits(now: 0.1)
    [true, true, false].each do |again|
      now = client.next_timeout
      client.handle_timeout(now:)
      client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
      sent = server.transmits(now:)
      if again
        assert sent.any? { packet_types(_1.payload).uniq == %i[initial handshake] }
      else
        assert sent.all? { _1.payload.bytesize < 100 }
      end
    end
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
