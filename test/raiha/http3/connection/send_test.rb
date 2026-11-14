require "test_helper"
require "support/http3_pair"

# What waits for the transport: given a stream at a time, kept when the
# transport takes less, and held until the stream is writable again.
class RaihaHTTP3ConnectionSendTest < Minitest::Test
  include HTTP3Pair

  def started
    client = HTTP3::Connection.client
    client.start(**CLIENT_STREAMS)
    actions(client)
    client
  end

  # The transport takes `limit` bytes of each write at most.
  def given(connection, limit)
    [].tap do |writes|
      connection.each_send do |stream_id, data, fin|
        taken = [data.bytesize, limit].min
        writes << [stream_id, data.byteslice(0, taken), fin && taken == data.bytesize]
        taken
      end
    end
  end

  def test_what_the_transport_does_not_take_waits_until_writable
    client = started
    assert_equal [[2, "\x00", false], [2, "\x04\x05", false], [6, "\x02", false], [10, "\x03", false]], given(client, 2)
    assert_empty given(client, 100)
    client.stream_writable(2)
    rest = given(client, 100)
    assert_equal [2], rest.map(&:first)
    assert_equal HTTP3::Frame.encode(HTTP3::Settings.new.to_frame).byteslice(2..), rest.first[1]
  end

  def test_the_block_says_how_much_it_took
    client = started
    assert_raises(ArgumentError) { client.each_send { |_, data, _| data.bytesize + 1 } }
    assert_raises(ArgumentError) { client.each_send { nil } }
  end

  def test_writable_for_a_stream_with_nothing_waiting
    client = started
    sent(client)
    client.stream_writable(2)
    client.stream_writable(100)
    assert_empty sent(client)
  end
end
