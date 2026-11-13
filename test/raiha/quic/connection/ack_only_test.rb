require "test_helper"
require "support/quic_pair"
require "support/quic_recovery"

# A client that only receives, with windows that need no credit, sends
# packets of an ACK alone, which its peer never acknowledges; once a round
# trip one carries a PING, so that the server acknowledges it and the
# client can let go of what its ACKs acknowledged (RFC 9000 "Limiting
# Ranges by Tracking ACK Frames").
class RaihaNextQUICConnectionAckOnlyTest < Minitest::Test
  include NextQUICPair

  # A client and a server whose datagrams reach each other 10 ms later,
  # `rounds` round trips from the first Initial on; once the handshake is
  # confirmed, the server writes `bytes` to the client every round trip
  # while `writing` says so. Gives the client's 1-RTT packets from then and
  # the datagrams each round trip sent. The client sends no probe of the
  # path MTU, which would elicit an ACK of its own.
  def exchange(rounds:, bytes:, writing: ->(_) { true })
    tracer = NextQUICRecovery::RecordingTracer.new
    @client = client_connection(tracer:, config: QUIC::Config.new(initial_max_data: 4 << 20, initial_max_stream_data_bidi_remote: 4 << 20,
      enable_pmtud: false))
    server = server_connection
    now = 0.0
    stream_id = nil
    from = nil
    counts = []
    rounds.times do |round|
      sent = @client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now: now + 0.01) }.size
      now += 0.01
      if server.handshake_confirmed?
        stream_id ||= server.open_stream
        from ||= tracer.of(:packet_sent).size
        server.stream_write(stream_id || flunk, "x" * bytes) if writing.call(round)
      end
      sent += server.transmits(now:).each { |transmit| @client.receive(transmit.payload, from: SERVER, now: now + 0.01) }.size
      now += 0.01
      counts << sent
    end
    [tracer.of(:packet_sent).drop(from || flunk).select { _1[:header].packet_type == :one_rtt }, counts]
  end

  def ping?(packet) = packet[:frames].last.is_a?(QUIC::Wire::Frame::Ping)

  def test_a_ping_once_a_round_trip
    sent, = exchange(rounds: 100, bytes: 6000)
    assert sent.all? { |packet| packet[:frames].first.is_a?(QUIC::Wire::Frame::Ack) && packet[:frames].size <= 2 }
    pings = sent.select { ping?(_1) }
    assert_operator pings.size, :>, 10
    refute sent.each_cons(2).any? { |a, b| ping?(a) && ping?(b) }
    assert pings.each_cons(2).all? { |a, b| b[:now] - a[:now] >= @client.stats.min_rtt }
    lowest = sent.map { |packet| packet[:frames].first.ranges.last.first }
    assert_operator lowest.last, :>, lowest.first
  end

  # Once the server has nothing more to send, the PING of the client's last
  # ACK brings an ACK alone, which needs none: the two go quiet.
  def test_quiet_when_done
    sent, counts = exchange(rounds: 60, bytes: 6000, writing: ->(round) { round < 30 })
    assert sent.any? { ping?(_1) }
    assert_equal [0] * 20, counts.last(20)
  end
end
