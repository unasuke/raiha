require "test_helper"
require "support/quic_pair"
require "support/quic_recovery"

# Pacing what goes in flight (RFC 9002 "Pacing"): with a window far above
# RFC 9002's initial window, and an RTT long enough that the pacing rate
# gives less than that in a millisecond, a burst of that initial window
# goes at once, and the rest as the pacer's bucket fills, the connection's
# next timeout saying when. A datagram of ACKs alone waits on nothing.
class RaihaNextQUICConnectionPacingTest < Minitest::Test
  include NextQUICPair

  # A window of a hundred datagrams, ten times the pacer's bucket, of 1200
  # bytes each: no probe of the path MTU grows them.
  WIDE = QUIC::Config.new(initial_window: Ractor.shareable_lambda { |max_datagram_size| 100 * max_datagram_size }, enable_pmtud: false)

  # A client and a server done with the handshake 100 ms a round, the
  # server's packets traced by `tracer`, and the time then.
  def connected(tracer: nil)
    client = client_connection(config: QUIC::Config.new(enable_pmtud: false))
    server = server_connection(config: WIDE, tracer:)
    now = handshake(client, server, step: 0.1)
    [client, server].each { |connection| connection.each_event { nil } }
    [client, server, now]
  end

  # The bytes of the datagrams `connection` sends at `now`.
  def sent(connection, now) = connection.transmits(now:).sum { _1.payload.bytesize }

  def test_a_burst_then_the_rest_as_the_bucket_fills
    client, server, now = connected
    stream = client.open_stream
    client.stream_write(stream, "x" * 4_000, fin: true)
    client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
    response = "y".b * 60_000
    server.stream_write(stream, response, fin: true)
    first = sent(server, now)
    assert_operator first, :<=, QUIC::Config::DEFAULT_INITIAL_WINDOW.call(1200) + 1200
    assert_operator first, :>=, 10_000
    # Nothing more at the same instant: the bucket is empty, and the next
    # timeout is when it holds a datagram again, rounded up to a
    # millisecond.
    assert_equal 0, sent(server, now)
    release = server.next_timeout
    assert_operator release, :>, now
    assert_operator release, :<=, now + 0.002
    assert_operator sent(server, release), :>, 0
  end

  # While pacing holds back the rest of a response, the ACK of three
  # datagrams of the client goes at once (RFC 9002 "Pacing"), and nothing
  # of the response with it.
  def test_an_ack_alone_is_not_paced
    tracer = NextQUICRecovery::RecordingTracer.new
    client, server, now = connected(tracer:)
    server.stream_write(server.open_stream, "y".b * 60_000, fin: true)
    sent(server, now)
    assert_equal 0, sent(server, now)
    client.stream_write(client.open_stream, "x" * 3_000, fin: true)
    client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
    from = tracer.of(:packet_sent).size
    assert_operator sent(server, now), :>, 0
    frames = tracer.of(:packet_sent).drop(from).flat_map { _1[:frames] }
    refute_empty frames
    assert frames.all?(QUIC::Wire::Frame::Ack), frames.map(&:class).inspect
  end
end
