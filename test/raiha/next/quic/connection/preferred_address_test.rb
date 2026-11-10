require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Migration to a Preferred Address", at the server: what comes to
# the address it offered moves it there only once it has validated the
# path itself.
class RaihaNextQUICConnectionPreferredAddressTest < Minitest::Test
  include NextQUICPair

  PREFERRED = ["192.0.2.2", 4434].freeze
  ELSEWHERE = ["198.51.100.7", 61_000].freeze

  # A server at SERVER offering PREFERRED, done with the handshake, given
  # three more IDs of the client's; the client's key log; and the time.
  def connected
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, config: QUIC::Config.new(preferred_address: { ipv4: PREFERRED }))
    now = 0.0
    until client.handshake_complete? && server.handshake_complete?
      client.transmits(now:).each { server.receive(_1.payload, from: CLIENT, to: SERVER, now:) }
      server.transmits(now:).each { client.receive(_1.payload, from: SERVER, to: CLIENT, now:) }
      now += 0.001
    end
    server.each_event { nil }
    issued = (1..3).map do |sequence_number|
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to: 0, connection_id: format("c%07d", sequence_number).b,
        stateless_reset_token: format("%016d", sequence_number).b)
    end
    server.receive(packet(keylog, *issued, number: 900), from: CLIENT, to: SERVER, now:)
    server.transmits(now:)
    [server, keylog, now]
  end

  # A client's 1-RTT packet with `frames`.
  def packet(keylog, *frames, number:)
    client_one_rtt(keylog, dcid: "s".b * 8, payload: QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3), packet_number: number)
  end

  # The server's datagrams once its delayed ACK is due, `now` and its
  # timers run, as the address each goes from and the data of the
  # PATH_CHALLENGE it carries, if any.
  def sent(server, keylog, now)
    server.handle_timeout(now: now + 0.03)
    server.transmits(now: now + 0.03).map do |transmit|
      frames = server_one_rtt(keylog, transmit.payload, phase: 0)&.last || []
      [transmit.source, frames.grep(QUIC::Wire::Frame::PathChallenge).first&.data]
    end
  end

  # The data of the PATH_CHALLENGE the server sent from PREFERRED.
  def challenge(datagrams) = datagrams.find { |source, data| source == PREFERRED && data }&.last

  # A client's packet of `frames` in a datagram of 1200 bytes, as the
  # client pads its probes to an address that needs no validating.
  def padded(*frames) = [*frames, QUIC::Wire::Frame::Padding.new(length: 1200)]

  def ping = QUIC::Wire::Frame::Ping.new

  def answer(data) = QUIC::Wire::Frame::PathResponse.new(data:)

  # A probe to PREFERRED is answered from there with a challenge of the
  # server's; a packet that is no probe to PREFERRED moves nothing while
  # the challenge is unanswered, and the ACK goes from SERVER; the answer
  # moves the server, the newest packet having come to PREFERRED.
  def test_the_server_validates_the_path_before_it_moves
    server, keylog, now = connected
    server.receive(packet(keylog, *padded(QUIC::Wire::Frame::PathChallenge.new(data: "abcdefgh".b)), number: 1000), from: CLIENT,
      to: PREFERRED, now:)
    data = challenge(sent(server, keylog, now))
    refute_nil data
    server.receive(packet(keylog, ping, number: 1001), from: CLIENT, to: PREFERRED, now: now += 0.03)
    assert_equal [SERVER], sent(server, keylog, now).map(&:first).uniq
    server.receive(packet(keylog, answer(data), number: 1002), from: CLIENT, to: PREFERRED, now: now += 0.03)
    server.receive(packet(keylog, ping, number: 1003), from: CLIENT, to: PREFERRED, now:)
    assert_equal [PREFERRED], sent(server, keylog, now).map(&:first).uniq
  end

  # A packet that is no probe to PREFERRED, with no probe before it, makes
  # a path the server validates and does not move to yet; the answer
  # moves it.
  def test_a_packet_that_is_no_probe_first
    server, keylog, now = connected
    server.receive(packet(keylog, *padded(ping), number: 1000), from: CLIENT, to: PREFERRED, now:)
    datagrams = sent(server, keylog, now)
    data = challenge(datagrams)
    refute_nil data
    assert_equal [SERVER], datagrams.reject { |source, data| source == PREFERRED && data }.map(&:first).uniq
    server.receive(packet(keylog, answer(data), number: 1001), from: CLIENT, to: PREFERRED, now: now += 0.03)
    server.receive(packet(keylog, ping, number: 1002), from: CLIENT, to: PREFERRED, now:)
    assert_equal [PREFERRED], sent(server, keylog, now).map(&:first).uniq
  end

  # A newer packet that is no probe back at SERVER before the answer: the
  # answer validates the path, and the server stays.
  def test_the_newest_packet_back_at_the_first_address
    server, keylog, now = connected
    server.receive(packet(keylog, *padded(ping), number: 1000), from: CLIENT, to: PREFERRED, now:)
    data = challenge(sent(server, keylog, now))
    server.receive(packet(keylog, ping, number: 1001), from: CLIENT, to: SERVER, now: now += 0.03)
    server.receive(packet(keylog, answer(data), number: 1002), from: CLIENT, to: PREFERRED, now:)
    assert_equal [SERVER], sent(server, keylog, now).map(&:first).uniq
  end

  # The client at PREFERRED from another address than before seems to have
  # moved too: once the server has moved, it validates the path left again
  # (RFC 9000 "Off-Path Packet Forwarding"), as it does not when the
  # client's address is the same.
  def test_a_new_client_address_at_the_preferred_address
    server, keylog, now = connected
    server.receive(packet(keylog, *padded(ping), number: 1000), from: ELSEWHERE, to: PREFERRED, now:)
    data = challenge(sent(server, keylog, now))
    server.receive(packet(keylog, answer(data), number: 1001), from: ELSEWHERE, to: PREFERRED, now: now += 0.03)
    server.receive(packet(keylog, ping, number: 1002), from: ELSEWHERE, to: PREFERRED, now:)
    assert_includes sent(server, keylog, now).select { |_, data| data }.map(&:first), SERVER
  end

  # Moved to PREFERRED, the server drops a packet to SERVER numbered past
  # what it had received, which moves nothing back, and takes one numbered
  # before, late on the way: the next ACK has the late one and not the
  # newer.
  def test_newer_packets_to_the_first_address_are_dropped
    server, keylog, now = connected
    server.receive(packet(keylog, *padded(ping), number: 1000), from: CLIENT, to: PREFERRED, now:)
    data = challenge(sent(server, keylog, now))
    server.receive(packet(keylog, answer(data), number: 1001), from: CLIENT, to: PREFERRED, now: now += 0.03)
    server.receive(packet(keylog, ping, number: 1002), from: CLIENT, to: SERVER, now:)
    server.receive(packet(keylog, ping, number: 950), from: CLIENT, to: SERVER, now:)
    now += 0.03
    server.handle_timeout(now:)
    transmits = server.transmits(now:)
    assert_equal [PREFERRED], transmits.map(&:source).uniq
    acked = transmits.flat_map { server_one_rtt(keylog, _1.payload, phase: 0)&.last || [] }.grep(QUIC::Wire::Frame::Ack)
      .flat_map { |ack| ack.ranges.flat_map(&:to_a) }
    assert_includes acked, 950
    refute_includes acked, 1002
  end

  # Moved to PREFERRED with the client at another address, the server
  # takes a newer packet to SERVER, which takes the connection back there,
  # as one from the client would when an attacker forwarded copies.
  def test_newer_packets_to_the_first_address_after_the_client_seemed_to_move
    server, keylog, now = connected
    server.receive(packet(keylog, *padded(ping), number: 1000), from: ELSEWHERE, to: PREFERRED, now:)
    data = challenge(sent(server, keylog, now))
    server.receive(packet(keylog, answer(data), number: 1001), from: ELSEWHERE, to: PREFERRED, now: now += 0.03)
    server.receive(packet(keylog, ping, number: 1002), from: CLIENT, to: SERVER, now:)
    now += 0.03
    server.handle_timeout(now:)
    acks = server.transmits(now:).select { (server_one_rtt(keylog, _1.payload, phase: 0)&.last || []).grep(QUIC::Wire::Frame::Ack).any? }
    assert_equal [[SERVER, CLIENT]], acks.map { [_1.source, _1.destination] }.uniq
  end
end
