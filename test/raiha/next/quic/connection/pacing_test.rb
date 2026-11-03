require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# Pacing what goes in flight (RFC 9002 "Pacing"): with a window far above
# RFC 9002's initial window, and an RTT long enough that the pacing rate
# gives less than that in a millisecond, a burst of that initial window
# goes at once, and the rest as the pacer's bucket fills, the connection's
# next timeout saying when.
class RaihaNextQUICConnectionPacingTest < Minitest::Test
  include NextQUICPair

  # A window of a hundred datagrams, ten times the pacer's bucket.
  WIDE = QUIC::Config.new(initial_window: Ractor.shareable_lambda { |max_datagram_size| 100 * max_datagram_size })

  # A client and a server done with the handshake 100 ms a round, and the
  # time then.
  def connected
    client = client_connection
    server = server_connection(config: WIDE)
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
end
