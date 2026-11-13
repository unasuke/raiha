require "test_helper"
require "support/quic_pair"

# The priorities of RFC 9218 on the streams a Connection sends: the
# streams of a lower urgency go first, and those not incremental of one
# urgency one by one.
class RaihaNextQUICConnectionStreamPriorityTest < Minitest::Test
  include NextQUICPair

  # A client and a server done with the handshake, and the time then.
  def connected
    client = client_connection
    server = server_connection
    now = handshake(client, server)
    [client, server].each { |connection| connection.each_event { nil } }
    [client, server, now]
  end

  # The streams the server has something to read on after the first
  # `count` datagrams of the client.
  def readable_after(client, server, now, count)
    client.transmits(now:).first(count).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
    server.readable_streams.to_a.sort
  end

  def test_the_more_urgent_stream_goes_first
    client, server, now = connected
    first, second = Array.new(2) { client.open_stream }
    client.stream_write(first, "a" * 3000)
    client.stream_write(second, "b" * 3000)
    client.stream_priority(second, urgency: 1, incremental: true)
    assert_equal [second], readable_after(client, server, now, 2)
  end

  def test_streams_not_incremental_go_one_by_one
    client, server, now = connected
    streams = Array.new(2) { client.open_stream }
    streams.each do |stream_id|
      client.stream_write(stream_id, "x" * 3000)
      client.stream_priority(stream_id, urgency: 3, incremental: false)
    end
    assert_equal [streams.first], readable_after(client, server, now, 2)
  end

  def test_the_priority_is_checked
    client, = connected
    stream_id = client.open_stream
    assert_raises(ArgumentError) { client.stream_priority(stream_id, urgency: 8, incremental: true) }
    assert_raises(ArgumentError) { client.stream_priority(stream_id, urgency: "1", incremental: true) }
    assert_raises(ArgumentError) { client.stream_priority(stream_id, urgency: 1, incremental: nil) }
    assert_raises(QUIC::Error::StreamError) { client.stream_priority(100, urgency: 1, incremental: true) }
  end
end
