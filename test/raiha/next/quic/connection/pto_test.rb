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

  # A PTO sends two datagrams, whatever spaces they carry (RFC 9002
  # "Sending Probe Packets"): with an RSA certificate the Handshake probe
  # fills each, and the 0.5-RTT data in flight, which does not fit, goes
  # in no third. The client's ClientHello again lets the server send them.
  def test_a_pto_sends_two_datagrams_whatever_spaces_fit
    tls_config = server_config
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity(key: NextTestPKI.key(:rsa))], random: Random.new(2))
    initial_window = Ractor.shareable_lambda { |max_datagram_size| 3 * max_datagram_size }
    server = QUIC::Connection.server(config: QUIC::Config.new(initial_window:), tls_config:, keyring:, time: NOW, now: 0.0)
    client = client_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    server.stream_write(server.open_stream, "x" * 20_000, fin: true)
    server.transmits(now: 0.0)
    now = client.next_timeout
    client.handle_timeout(now:)
    client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now: 0.001) }
    server.transmits(now: 0.001)
    now = server.next_timeout
    server.handle_timeout(now:)
    probes = server.transmits(now:)
    assert_equal 2, probes.size
    probes.each { |probe| assert_equal %i[initial handshake], packet_types(probe.payload).uniq }
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

  # What a server sends again at once is no probe: it waits on the
  # congestion window as anything else that elicits an ACK (RFC 9002
  # "Congestion Control"). With a window of two datagrams its first flight
  # and 0.5-RTT data fill, the ClientHello again sends nothing more in
  # flight.
  def test_the_server_sends_again_at_once_within_its_window
    initial_window = Ractor.shareable_lambda { |max_datagram_size| 2 * max_datagram_size }
    client = client_connection
    server = server_connection(config: QUIC::Config.new(initial_window:))
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.1) }
    server.stream_write(server.open_stream, "x" * 10_000, fin: true)
    server.transmits(now: 0.1)
    full = server.path.bytes_in_flight
    assert_operator full + server.path.max_datagram_size, :>, server.path.window
    now = client.next_timeout
    client.handle_timeout(now:)
    client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
    server.transmits(now:)
    assert_equal full, server.path.bytes_in_flight
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

  # The frames of the server's 1-RTT packet in each datagram, PADDING left
  # out.
  def one_rtt_frames(keylog, datagrams)
    datagrams.map { |transmit| (server_one_rtt(keylog, transmit.payload, phase: 0)&.last || []).grep_v(QUIC::Wire::Frame::Padding) }
  end

  # A server done with the handshake sends a PMTU probe of a PING, then
  # HANDSHAKE_DONE, and neither comes, nor any ACK: its probes carry
  # HANDSHAKE_DONE again, not a PING for the PMTU probe that is older.
  def test_probes_carry_what_was_lost_past_a_pmtu_probe
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection
    now = 0.0
    10.times do
      break if server.handshake_complete?
      client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
      break if server.handshake_complete?
      server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) }
      now += 0.001
    end
    lost = one_rtt_frames(keylog, server.transmits(now:))
    assert_equal [QUIC::Wire::Frame::Ping], lost.first.map(&:class), "the first is a PMTU probe"
    assert(lost.flatten.any?(QUIC::Wire::Frame::HandshakeDone))
    now = server.next_timeout
    server.handle_timeout(now:)
    probes = one_rtt_frames(keylog, server.transmits(now:))
    assert(probes.flatten.any?(QUIC::Wire::Frame::HandshakeDone), probes.inspect)
  end
end
