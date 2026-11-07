require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Path Validation Responses": a PATH_CHALLENGE is answered with
# a PATH_RESPONSE of its data, once, in a datagram of its own, past the
# congestion window; only the last challenge waits for its answer.
class RaihaNextQUICConnectionPathChallengeTest < Minitest::Test
  include NextQUICPair

  # A server done with the handshake, its connection ID "s" * 8, the
  # client's key log, and the time.
  def connected
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8)
    now = handshake(client, server)
    server.each_event { nil }
    [server, keylog, now]
  end

  # A client's 1-RTT packet with a PATH_CHALLENGE of each of `data`.
  def challenges(keylog, *data, packet_number:)
    frames = data.map { QUIC::Wire::Frame::PathChallenge.new(data: _1) }
    client_one_rtt(keylog, dcid: "s".b * 8, payload: QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3), packet_number:)
  end

  # The frames of each of the server's datagrams at `now`.
  def sent(server, keylog, now) = server.transmits(now:).map { [_1.payload.bytesize, server_one_rtt(keylog, _1.payload, phase: 0)&.last] }

  def test_a_challenge_is_answered_in_a_datagram_of_its_own
    server, keylog, now = connected
    server.receive(challenges(keylog, "abcdefgh".b, packet_number: 1000), from: CLIENT, now:)
    (size, frames), *rest = sent(server, keylog, now)
    assert_equal 1200, size
    assert_equal [QUIC::Wire::Frame::PathResponse.new(data: "abcdefgh".b)], frames.reject { _1.is_a?(QUIC::Wire::Frame::Padding) }
    # RFC 9000 "Off-Path Packet Forwarding": a challenge on the path in
    # use is answered with a packet that is no probe as well.
    assert(rest.any? { |_, others| others&.any?(QUIC::Wire::Frame::Ping) })
    assert(rest.none? { |_, others| others&.any?(QUIC::Wire::Frame::PathResponse) })
  end

  # A thousand challenges in a packet, or one in each of many packets
  # while the congestion window is full, leave one waiting, the last, and
  # its answer goes all the same (CVE-2023-49295, CVE-2023-6193).
  def test_a_flood_of_challenges
    server, keylog, now = connected
    data = (0...1000).map { [_1].pack("Q>") }
    server.receive(challenges(keylog, *data, packet_number: 1000), from: CLIENT, now:)
    responses = sent(server, keylog, now).flat_map { _2 || [] }.grep(QUIC::Wire::Frame::PathResponse)
    assert_equal [data.last], responses.map(&:data)

    stream_id = server.open_stream
    server.stream_write(stream_id, "x".b * 1_000_000)
    sent(server, keylog, now)
    assert server.path.bytes_in_flight + 1200 > server.path.window, "the window is full"
    (1..50).each { server.receive(challenges(keylog, [_1].pack("Q>"), packet_number: 2000 + _1), from: CLIENT, now:) }
    (size, frames), *rest = sent(server, keylog, now)
    assert_equal [1200, [QUIC::Wire::Frame::PathResponse.new(data: [50].pack("Q>"))]],
      [size, frames.reject { _1.is_a?(QUIC::Wire::Frame::Padding) }]
    # Only ACKs go besides, which wait on nothing either.
    assert_equal [[QUIC::Wire::Frame::Ack]], rest.map { |_, others| others.map(&:class).uniq }.uniq
  end
end
