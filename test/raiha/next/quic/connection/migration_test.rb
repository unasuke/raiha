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
  def connected(ids: 3, config: QUIC::Config.new)
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, config:)
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

  # The PATH_CHALLENGE of each path in `datagrams`, by destination.
  def challenges(datagrams)
    datagrams.each_with_object({}) do |(destination, _, dcid, frames), all|
      frames.grep(QUIC::Wire::Frame::PathChallenge).each { all[destination] = [dcid, _1.data] }
    end
  end

  # RFC 9000 "Responding to Connection Migration": a packet that is no
  # probe, the largest of its space, from a new address moves the server
  # there at once, and the first datagram on the new path carries a
  # PATH_CHALLENGE. With the Destination Connection ID as before, a NAT
  # rebinding, the server goes on with the client's ID in use, and
  # validates the path it left again with an ID no path sent with (RFC 9000
  # "Off-Path Packet Forwarding").
  def test_a_rebinding_moves_the_server
    server, keylog, id, now = connected
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    datagrams = sent(server, keylog, now)
    assert_equal ELSEWHERE, datagrams.first.first
    assert_equal({ ELSEWHERE => id, CLIENT => "c0000001" }, challenges(datagrams).transform_values(&:first))
  end

  # With no ID left that no path sent with, the path left is not
  # validated again: one ID would go to two addresses.
  def test_a_rebinding_with_no_id_for_the_path_left
    server, keylog, id, now = connected(ids: 0)
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    assert_equal({ ELSEWHERE => id }, challenges(sent(server, keylog, now)).transform_values(&:first))
  end

  # With another Destination Connection ID, the new path sends with an ID
  # of the client's no path sent with, and the path left validates again
  # with the ID it had.
  def test_a_migration_with_a_new_id
    server, keylog, id, now = connected
    server.receive(packet(keylog, ping, number: 1000, dcid: "x".b * 8), from: ELSEWHERE, to: SERVER, now:)
    assert_equal({ ELSEWHERE => "c0000001", CLIENT => id }, challenges(sent(server, keylog, now)).transform_values(&:first))
  end

  # The new path unanswered, the server goes back to the path it left,
  # which answered, and retires the ID the failed path sent with.
  def test_back_to_the_path_last_validated
    server, keylog, _, now = connected
    server.receive(packet(keylog, ping, number: 1000, dcid: "x".b * 8), from: ELSEWHERE, to: SERVER, now:)
    _, data = challenges(sent(server, keylog, now)).fetch(CLIENT)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data:), number: 1001), from: CLIENT, to: SERVER, now:)
    retired = []
    until now > 10.0 || !retired.empty?
      now = server.next_timeout
      server.handle_timeout(now:)
      datagrams = sent(server, keylog, now)
      retired = datagrams.flat_map(&:last).grep(QUIC::Wire::Frame::RetireConnectionID).map(&:sequence_number)
    end
    assert_equal [1], retired
    assert_equal [CLIENT], datagrams.map(&:first).uniq
    refute server.closed?
  end

  # Runs the server's timers until `until` says so or ten seconds pass;
  # the datagrams it sent last.
  def run_timers(server, keylog, now, &until_)
    datagrams = []
    until now > 10.0 || server.closed?
      now = server.next_timeout
      server.handle_timeout(now:)
      datagrams = server.closed? ? [] : sent(server, keylog, now)
      break if until_.(datagrams)
    end
    datagrams
  end

  # A rebinding, then probes from three new addresses that push the path
  # left out of the paths being validated, and the new path left
  # unanswered until the server goes back to the path it left; the server,
  # the key log, the time, and the datagrams it sent then.
  def gone_back_after_probes
    server, keylog, _, now = connected(ids: 5, config: QUIC::Config.new(active_connection_id_limit: 8))
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    sent(server, keylog, now)
    (1..3).each do |i|
      probe = packet(keylog, QUIC::Wire::Frame::PathChallenge.new(data: [i].pack("Q>")), number: 1000 + i)
      server.receive(probe, from: ["203.0.113.1", 20_000 + i], to: SERVER, now:)
    end
    sent(server, keylog, now)
    datagrams = run_timers(server, keylog, now) { |sent| sent.any? { _1.first == CLIENT } }
    [server, keylog, server.next_timeout, datagrams]
  end

  # Pushed out by probes, the path left stays the one to go back to when
  # the new path fails, and, gone back to, is validated anew (RFC 9000
  # "Off-Path Packet Forwarding"): answered, the connection goes on there.
  def test_probes_leave_the_path_to_go_back_to
    server, keylog, now, datagrams = gone_back_after_probes
    refute server.closed?
    _, data = challenges(datagrams).fetch(CLIENT)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data:), number: 1100), from: CLIENT, to: SERVER, now:)
    run_timers(server, keylog, now) { false }
    refute server.closed?, server.close_reason&.reason
  end

  # The path gone back to unanswered too, nothing validated is left.
  def test_the_path_gone_back_to_is_validated_anew
    server, keylog, now, = gone_back_after_probes
    run_timers(server, keylog, now) { false }
    assert_equal "no validated path", server.close_reason&.reason
  end

  # The answer to a short challenge validates the new path's address, but
  # the path is not the one to go back to until a full datagram is
  # answered: that unanswered, the server goes back to the path it left.
  def test_a_short_answer_does_not_make_the_path_to_go_back_to
    server, keylog, _, now = connected
    server.receive(packet(keylog, ping, number: 1000, dcid: "x".b * 8), from: ELSEWHERE, to: SERVER, now:)
    first = challenges(sent(server, keylog, now))
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data: first.fetch(CLIENT).last), number: 1001), from: CLIENT, to: SERVER,
      now:)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data: first.fetch(ELSEWHERE).last), number: 1002), from: ELSEWHERE,
      to: SERVER, now:)
    full = sent(server, keylog, now).select { _1.first == ELSEWHERE }
    assert(full.any? { |_, size, _, frames| size == 1200 && frames.any?(QUIC::Wire::Frame::PathChallenge) })
    datagrams = run_timers(server, keylog, now) { |sent| sent.any? { _1.first == CLIENT } }
    refute server.closed?
    assert(datagrams.any? { _1.first == CLIENT })
  end

  # Keeps the addresses a connection tells it of.
  class Peers
    attr_reader :addresses

    def initialize = @addresses = []

    def add(_connection, address) = @addresses << address

    def remove(_connection, address) = @addresses.delete(address)
  end

  # A connection tells its Endpoint's peers of the address of a path it
  # moves to, and of one it leaves for good, so that a stateless reset
  # from there finds it; only a reset with the token of the ID it sends
  # with on a path to that address is one.
  def test_the_addresses_of_the_paths_and_stateless_resets
    peers = Peers.new
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, peers:)
    now = handshake(client, server)
    issued = QUIC::Wire::Frame::NewConnectionID.new(sequence_number: 1, retire_prior_to: 0, connection_id: "c0000001".b,
      stateless_reset_token: "r".b * 16)
    server.receive(packet(keylog, issued, number: 900), from: CLIENT, to: SERVER, now:)
    server.receive(packet(keylog, ping, number: 1000, dcid: "x".b * 8), from: ELSEWHERE, to: SERVER, now:)
    assert_equal [ELSEWHERE], peers.addresses
    reset = QUIC::StatelessReset.packet(token: "r".b * 16, length: 42, random: Random.new(5))
    refute server.take_stateless_reset(reset, from: CLIENT, now:)
    assert server.take_stateless_reset(reset, from: ELSEWHERE, now:)
  end

  # A path that fails and is left for good takes its address out.
  def test_a_failed_path_takes_its_address_out
    peers = Peers.new
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, peers:)
    now = handshake(client, server)
    server.receive(packet(keylog, ping, number: 999), from: CLIENT, to: SERVER, now:)
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    assert_equal [ELSEWHERE], peers.addresses
    sent(server, keylog, now)
    run_timers(server, keylog, now) { |datagrams| datagrams.any? { _1.first == CLIENT } }
    refute server.closed?
    assert_empty peers.addresses
  end

  # Neither path answering, there is no validated path to go back to: the
  # connection closes at once with nothing sent.
  def test_no_validated_path_left
    server, keylog, _, now = connected
    server.receive(packet(keylog, ping, number: 1000), from: ELSEWHERE, to: SERVER, now:)
    sent(server, keylog, now)
    until server.closed? || now > 10.0
      now = server.next_timeout
      server.handle_timeout(now:)
      sent(server, keylog, now) unless server.closed?
    end
    assert server.closed?
    assert_equal [QUIC::ErrorCode::NO_ERROR, "no validated path"], [server.close_reason.code, server.close_reason.reason]
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
    before = sent(server, keylog, now).select { _1.first == ELSEWHERE }
    assert_operator before.sum { _2 }, :<=, 3 * moving.bytesize
    _, data = challenges(before).fetch(ELSEWHERE)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data:), number: 1001), from: ELSEWHERE, to: SERVER, now:)
    assert_operator sent(server, keylog, now).select { _1.first == ELSEWHERE }.sum { _2 }, :>, 3 * moving.bytesize
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
