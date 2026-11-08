require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Connection Migration": what a connection takes from an address
# its path does not go to.
class RaihaNextQUICConnectionMigrationTest < Minitest::Test
  include NextQUICPair

  ELSEWHERE = ["198.51.100.7", 61_000].freeze

  # Before the handshake is confirmed, a server drops what comes from an
  # address other than the client's first, and the handshake goes no
  # further until it comes from there again.
  def test_a_server_drops_a_new_address_before_confirmation
    client = client_connection
    server = server_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    server.transmits(now: 0.0).each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    flight = client.transmits(now: 0.001)
    flight.each { server.receive(_1.payload, from: ELSEWHERE, now: 0.001) }
    refute server.handshake_complete?
    flight.each { server.receive(_1.payload, from: CLIENT, now: 0.001) }
    assert server.handshake_complete?
  end

  # A server done with the handshake, its connection ID "s" * 8, given
  # `ids` more IDs of the client's, "c0000001" on; the client's key log;
  # the client's ID in use; and the time.
  def connected(ids: 3)
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8)
    now = handshake(client, server)
    server.each_event { nil }
    issued = (1..ids).map do |sequence_number|
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to: 0, connection_id: format("c%07d", sequence_number).b,
        stateless_reset_token: format("%016d", sequence_number).b)
    end
    server.receive(packet(keylog, QUIC::Wire::Frame::Ping.new, *issued, number: 900), from: CLIENT, to: SERVER, now:)
    now += 0.03
    server.handle_timeout(now:)
    first = server.transmits(now:).first.payload
    [server, keylog, QUIC::Wire::Packet.parse(first, dcid_length: 8).header.dcid, now]
  end

  # A client's 1-RTT packet to `dcid` with `frames`.
  def packet(keylog, *frames, number:, dcid: "s".b * 8)
    client_one_rtt(keylog, dcid:, payload: QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3), packet_number: number)
  end

  # Each of the server's datagrams at `now` as its destination, size,
  # Destination Connection ID and frames, PADDING left out.
  def sent(server, keylog, now)
    server.transmits(now:).map do |transmit|
      dcid = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).header.dcid
      frames = server_one_rtt(keylog, transmit.payload, phase: 0)&.last || []
      [transmit.destination, transmit.payload.bytesize, dcid, frames.reject { _1.is_a?(QUIC::Wire::Frame::Padding) }]
    end
  end

  def ping = QUIC::Wire::Frame::Ping.new

  # RFC 9000 "Responding to Connection Migration": a packet that is no
  # probe, the largest of its space, from a new address moves the server
  # there at once, and the first datagram on the new path carries a
  # PATH_CHALLENGE. With the Destination Connection ID as before, a NAT
  # rebinding, the server goes on with the client's ID in use.
  def test_a_rebinding_moves_the_server
    server, keylog, id, now = connected
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    (destination, _, dcid, frames), *rest = sent(server, keylog, now)
    assert_equal [ELSEWHERE, id], [destination, dcid]
    assert_equal 1, frames.grep(QUIC::Wire::Frame::PathChallenge).size
    assert_empty rest.reject { _1.first == ELSEWHERE }
  end

  # With another Destination Connection ID, the new path sends with an ID
  # of the client's no path sent with, and the one in use before is
  # retired once the path is validated, its amplification limit no longer
  # holding back a datagram of a full size.
  def test_a_migration_with_a_new_id
    server, keylog, _, now = connected
    server.receive(packet(keylog, ping, number: 1000, dcid: "x".b * 8), from: ELSEWHERE, to: SERVER, now:)
    datagrams = sent(server, keylog, now)
    assert_equal [[ELSEWHERE, "c0000001"]], datagrams.map { [_1[0], _1[2]] }.uniq
    challenge = datagrams.flat_map(&:last).grep(QUIC::Wire::Frame::PathChallenge).first
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data: challenge.data), number: 1001, dcid: "x".b * 8), from: ELSEWHERE,
      to: SERVER, now:)
    retired = sent(server, keylog, now).flat_map(&:last).grep(QUIC::Wire::Frame::RetireConnectionID)
    assert_equal [0], retired.map(&:sequence_number)
  end

  # A packet from a new address that is not the largest of its space,
  # sent before a later one came, moves nothing.
  def test_an_older_packet_moves_nothing
    server, keylog, _, now = connected
    server.receive(packet(keylog, ping, number: 1001), from: CLIENT, to: SERVER, now:)
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    assert_equal [CLIENT], sent(server, keylog, now).map(&:first).uniq
  end

  # With another Destination Connection ID and no ID of the client's left
  # to send with, there is no move.
  def test_no_move_with_no_id
    server, keylog, _, now = connected(ids: 0)
    server.receive(packet(keylog, ping, number: 1000, dcid: "x".b * 8), from: ELSEWHERE, to: SERVER, now:)
    assert_equal [CLIENT], sent(server, keylog, now).map(&:first).uniq
  end

  # Until the new path is validated, the server sends there no more than
  # three times what came on it; the PATH_RESPONSE lifts the limit.
  def test_the_amplification_limit_of_the_new_path
    server, keylog, _, now = connected
    stream_id = server.open_stream(direction: :uni)
    server.stream_write(stream_id, "x".b * 100_000)
    moving = packet(keylog, ping, number: 1000)
    server.receive(moving, from: ELSEWHERE, to: SERVER, now:)
    before = sent(server, keylog, now)
    assert_operator before.sum { _2 }, :<=, 3 * moving.bytesize
    challenge = before.flat_map(&:last).grep(QUIC::Wire::Frame::PathChallenge).first
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data: challenge.data), number: 1001), from: ELSEWHERE, to: SERVER, now:)
    assert_operator sent(server, keylog, now).sum { _2 }, :>, 3 * moving.bytesize
  end

  # A client whose own address changes under it, which the OS chooses,
  # takes what the server sends to the new one.
  def test_a_client_takes_what_comes_to_a_new_address_of_its_own
    client = client_connection
    server = server_connection
    now = handshake(client, server)
    client.each_event { nil }
    first = server.open_stream(direction: :uni)
    server.stream_write(first, "hello", fin: true)
    server.transmits(now:).each { client.receive(_1.payload, from: SERVER, to: CLIENT, now:) }
    second = server.open_stream(direction: :uni)
    server.stream_write(second, "again", fin: true)
    server.transmits(now:).each { client.receive(_1.payload, from: SERVER, to: ELSEWHERE, now:) }
    readable = [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::StreamReadable)
    assert_equal [first, second], readable.map(&:stream_id)
  end

  # A client takes nothing from a server address it did not migrate to.
  def test_a_client_drops_another_server_address
    client = client_connection
    server = server_connection
    now = handshake(client, server)
    client.each_event { nil }
    stream_id = server.open_stream(direction: :uni)
    server.stream_write(stream_id, "hello", fin: true)
    datagrams = server.transmits(now:)
    datagrams.each { client.receive(_1.payload, from: ELSEWHERE, now:) }
    assert_empty [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::StreamReadable)
    datagrams.each { client.receive(_1.payload, from: SERVER, now:) }
    refute_empty [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::StreamReadable)
  end
end
