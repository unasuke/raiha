require "test_helper"
require "support/quic_pair"

# RFC 9000 "Path Validation", on a server a client probes from a new
# address: the probe is answered with a probe on that path, with an ID of
# the client's no path sent with; the challenge goes again, twice as late
# each time, until it is answered or the path fails.
class RaihaQUICConnectionPathValidationTest < Minitest::Test
  include QUICPair

  NEW = ["198.51.100.7", 61_000].freeze

  # A server done with the handshake, its connection ID "s" * 8, given
  # `ids` more IDs of the client's, "c0000001" on; the client's key log;
  # and the time.
  def connected(ids: 3, config: QUIC::Config.new, peers: nil)
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, config:, peers:)
    now = handshake(client, server)
    server.each_event { nil }
    issued = (1..ids).map do |sequence_number|
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to: 0, connection_id: format("c%07d", sequence_number).b,
        stateless_reset_token: format("%016d", sequence_number).b)
    end
    issued.each_slice(30).with_index { |frames, index| server.receive(packet(keylog, *frames, number: 900 + index), from: CLIENT, now:) }
    server.transmits(now:)
    [server, keylog, now]
  end

  # A client's 1-RTT packet to "s" * 8 with `frames`.
  def packet(keylog, *frames, number:)
    client_one_rtt(keylog, dcid: "s".b * 8, payload: QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3), packet_number: number)
  end

  def challenge(data) = QUIC::Wire::Frame::PathChallenge.new(data:)

  # Each of the server's datagrams at `now` as its destination, size,
  # Destination Connection ID and frames, PADDING left out.
  def sent(server, keylog, now)
    server.transmits(now:).map do |transmit|
      dcid = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).header.dcid
      frames = server_one_rtt(keylog, transmit.payload, phase: 0)&.last || []
      [transmit.destination, transmit.payload.bytesize, dcid, frames.reject { _1.is_a?(QUIC::Wire::Frame::Padding) }]
    end
  end

  def on(path, datagrams) = datagrams.select { _1.first == path }

  # A probe from a new address is answered on that path with a probe: the
  # PATH_RESPONSE and a PATH_CHALLENGE of the server's own in the first
  # datagram, with the client's lowest ID no path sent with. Three times
  # what came on the path is short of 1200 bytes, and the datagram goes as
  # small as it is, so that the rest of the limit takes the challenges
  # after.
  def test_a_probe_is_answered_with_a_probe
    server, keylog, now = connected
    probe = packet(keylog, challenge("abcdefgh".b), number: 1000)
    server.receive(probe, from: NEW, to: SERVER, now:)
    (destination, size, dcid, frames), *rest = on(NEW, sent(server, keylog, now))
    assert_equal [NEW, "c0000001"], [destination, dcid]
    assert_equal [QUIC::Wire::Frame::PathResponse.new(data: "abcdefgh".b)], frames.grep(QUIC::Wire::Frame::PathResponse)
    assert_equal 1, frames.grep(QUIC::Wire::Frame::PathChallenge).size
    assert_operator size, :<, probe.bytesize + 20
    assert_empty rest
  end

  # The answer to a challenge in a datagram short of 1200 bytes validates
  # the address, and the next challenge goes at once in a datagram of 1200
  # bytes, to validate what the path carries (RFC 9000 "Initiating Path
  # Validation"); its answer ends the validation.
  def test_a_short_challenge_is_followed_by_a_full_one
    server, keylog, now = connected
    server.receive(packet(keylog, challenge("abcdefgh".b), number: 1000), from: NEW, to: SERVER, now:)
    first = on(NEW, sent(server, keylog, now)).first.last.grep(QUIC::Wire::Frame::PathChallenge).first
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data: first.data), number: 1001), from: NEW, to: SERVER, now:)
    (_, size, _, frames), = on(NEW, sent(server, keylog, now))
    assert_equal 1200, size
    full = frames.grep(QUIC::Wire::Frame::PathChallenge).first
    refute_nil full
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data: full.data), number: 1002), from: NEW, to: SERVER, now:)
    assert_empty on(NEW, sent(server, keylog, now + 30.0).tap { server.handle_timeout(now: now + 30.0) })
  end

  # Unanswered, the challenge goes again one PTO of the new path on, then
  # two more; at three times the larger PTO the path fails, and the
  # client's ID it sent with is retired.
  def test_an_unanswered_challenge
    server, keylog, now = connected
    server.receive(packet(keylog, challenge("abcdefgh".b), number: 1000), from: NEW, to: SERVER, now:)
    sent(server, keylog, now)
    pto = 0.333 + 4 * 0.1665 + 0.025
    times = []
    t = now
    while t < now + 4.0
      t = server.next_timeout
      server.handle_timeout(now: t)
      datagrams = sent(server, keylog, t)
      times << (t - now).round(3) if on(NEW, datagrams).any? { |*, frames| frames.any?(QUIC::Wire::Frame::PathChallenge) }
      retired = datagrams.flat_map(&:last).grep(QUIC::Wire::Frame::RetireConnectionID).map(&:sequence_number)
      break unless retired.empty?
    end
    assert_equal [pto.round(3)], times
    assert_equal 1, retired.first
    assert_in_delta now + 3 * pto, t, 0.01
  end

  # Retire Prior To retiring the ID a path being validated sends with,
  # its next challenge goes with an ID no path sent with.
  def test_a_path_s_id_retired
    server, keylog, now = connected
    server.receive(packet(keylog, challenge("abcdefgh".b), number: 1000), from: NEW, to: SERVER, now:)
    assert_equal ["c0000001"], on(NEW, sent(server, keylog, now)).map { _1[2] }
    issued = QUIC::Wire::Frame::NewConnectionID.new(sequence_number: 4, retire_prior_to: 2, connection_id: "c0000004".b,
      stateless_reset_token: format("%016d", 4).b)
    server.receive(packet(keylog, issued, number: 1001), from: CLIENT, to: SERVER, now:)
    datagrams = []
    while datagrams.empty?
      now = server.next_timeout
      server.handle_timeout(now:)
      datagrams = on(NEW, sent(server, keylog, now))
    end
    assert_equal ["c0000003"], datagrams.map { _1[2] }.uniq
  end

  # With no ID of the client's left that no path sent with, a probe from
  # a new address goes unanswered.
  def test_no_id_to_answer_with
    server, keylog, now = connected(ids: 0)
    server.receive(packet(keylog, challenge("abcdefgh".b), number: 1000), from: NEW, to: SERVER, now:)
    assert_empty on(NEW, sent(server, keylog, now))
  end

  # Keeps the addresses a connection tells it of.
  class Peers
    attr_reader :addresses

    def initialize = @addresses = []

    def add(_connection, address) = @addresses << address

    def remove(_connection, address) = @addresses.delete(address)
  end

  # Probes from a thousand addresses leave the server with three paths
  # besides the one in use, the newest, each the older's going as a newer
  # comes, and the Endpoint's peers with their addresses alone
  # (CVE-2026-12707).
  def test_probes_from_a_thousand_addresses
    peers = Peers.new
    server, keylog, now = connected(ids: 1000, config: QUIC::Config.new(active_connection_id_limit: 1001), peers:)
    (1..1000).each do |i|
      server.receive(packet(keylog, challenge([i].pack("Q>")), number: 2000 + i), from: ["203.0.113.1", 10_000 + i], to: SERVER, now:)
    end
    destinations = sent(server, keylog, now).map(&:first).uniq - [CLIENT]
    assert_equal [10_998, 10_999, 11_000], destinations.map(&:last).sort
    assert_equal destinations.sort, peers.addresses.sort
  end
end
