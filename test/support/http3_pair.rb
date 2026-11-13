require "raiha/http3"

# HTTP/3 Connections of the next release of raiha with no transport under
# them: what one gives to send is read off, or handed to the other end
# stream by stream, the IDs being the same on both ends as in QUIC.
module NextHTTP3Pair
  HTTP3 = Raiha::HTTP3

  # The client's streams for the control stream and QPACK, and the
  # server's.
  CLIENT_STREAMS = { control: 2, encoder: 6, decoder: 10 }.freeze
  SERVER_STREAMS = { control: 3, encoder: 7, decoder: 11 }.freeze

  # What `connection` gives to send, all of it taken, by stream: the
  # bytes, and whether the stream ended.
  def sent(connection)
    streams = Hash.new { |hash, stream_id| hash[stream_id] = ["".b, false] }
    connection.each_send do |stream_id, data, fin|
      streams[stream_id][0] << data
      streams[stream_id][1] ||= fin
      data.bytesize
    end
    streams.to_h
  end

  # What `connection` asks of the transport; Action::Priority only when
  # `priorities`, as most requests ask for one.
  def actions(connection, priorities: false)
    [].tap { |all| connection.each_action { all << _1 if priorities || !_1.is_a?(HTTP3::Action::Priority) } }
  end
end
