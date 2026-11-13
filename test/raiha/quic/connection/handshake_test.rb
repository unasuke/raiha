require "test_helper"
require "support/quic_pair"

# Two connections back to back complete the handshake with no socket,
# Fiber or real time.
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

  # A server answers from the address the client's first Initial came to,
  # so that one with several addresses answers from the right one; a
  # client leaves its own address to the OS, and to the server what it
  # makes of a change.
  def test_the_server_answers_from_the_address_it_was_reached_at
    client = client_connection
    server = server_connection
    client.transmits(now: 0.0).each do |transmit|
      assert_nil transmit.source
      server.receive(transmit.payload, from: CLIENT, to: SERVER, now: 0.0)
    end
    transmits = server.transmits(now: 0.0)
    refute_empty transmits
    assert_equal [[CLIENT, SERVER]], transmits.map { [_1.destination, _1.source] }.uniq
    transmits.each { client.receive(_1.payload, from: SERVER, to: CLIENT, now: 0.001) }
    assert_equal [nil], client.transmits(now: 0.001).map(&:source).uniq
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

  # An Initial that does not open, which anyone could send, changes
  # nothing on a server: the client that comes next connects.
  def test_a_forged_initial_takes_nothing_over
    server = server_connection
    forged = client_connection(random: Random.new(9)).transmits(now: 0.0).first.payload.dup
    forged.setbyte(forged.bytesize - 1, forged.getbyte(forged.bytesize - 1) ^ 1)
    server.receive(forged, from: ["203.0.113.66", 4444], now: 0.0)
    assert_empty server.transmits(now: 0.0)
    client = client_connection
    handshake(client, server)
    assert server.handshake_complete?
  end

  # RFC 9001 "Handshake Confirmed": a server confirms as it completes, a
  # client once HANDSHAKE_DONE comes.
  def test_confirmation
    client = client_connection
    server = server_connection
    now = 0.0
    until server.handshake_complete?
      client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, now:) }
      server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) } unless server.handshake_complete?
    end
    assert server.handshake_confirmed?
    assert client.handshake_complete?
    refute client.handshake_confirmed?
    server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) }
    assert client.handshake_confirmed?
  end

  # A server does not take HANDSHAKE_DONE or NEW_TOKEN, which only a
  # server sends: PROTOCOL_VIOLATION.
  def test_frames_only_a_server_sends_from_a_client
    { "\x1e".b => 0x1e, QUIC::Wire::Frame.encode([QUIC::Wire::Frame::NewToken.new(token: "t".b)], ack_delay_exponent: 3) => 0x07 }.each do |payload, type|
      keylog = Keylog.new
      client = client_connection(keylog:)
      server = server_connection
      first = client.transmits(now: 0.0).first.payload
      server.receive(first, from: CLIENT, now: 0.0)
      reply = server.transmits(now: 0.0)
      server_id = QUIC::Wire::Packet.parse(reply.first.payload, dcid_length: 8).header.scid
      reply.each { client.receive(_1.payload, from: SERVER, now: 0.0) }
      handshake(client, server)
      server.receive(client_one_rtt(keylog, dcid: server_id, payload:), from: CLIENT, now: 1.0)
      assert server.closing?
      assert_equal [QUIC::ErrorCode::PROTOCOL_VIOLATION, type], [server.close_reason.code, server.close_reason.frame_type]
    end
  end

  # Every datagram of a client with an Initial packet in it is 1200 bytes,
  # those with a Handshake packet after it too.
  def test_every_client_initial_datagram_is_padded
    client = client_connection
    server = server_connection
    sizes = []
    now = 0.0
    6.times do
      client.transmits(now:).each do |transmit|
        sizes << transmit.payload.bytesize if QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).header.type == :initial
        server.receive(transmit.payload, from: CLIENT, now:)
      end
      server.transmits(now:).each { client.receive(_1.payload, from: SERVER, now:) }
      now += 0.001
    end
    assert_operator sizes.size, :>=, 2
    assert sizes.all? { _1 >= QUIC::Connection::MIN_INITIAL_DATAGRAM }, sizes.inspect
  end

  # A server pads a datagram with an Initial packet that elicits an ACK.
  def test_the_server_pads_its_initial
    client = client_connection
    server = server_connection
    server.receive(client.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0)
    first = server.transmits(now: 0.0).first.payload
    assert_operator first.bytesize, :>=, QUIC::Connection::MIN_INITIAL_DATAGRAM
  end
end
