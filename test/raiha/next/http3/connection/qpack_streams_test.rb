require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# The QPACK streams between two HTTP/3 Connections: the peer's encoder
# stream goes to this end's decoder, its decoder stream to this end's
# encoder, and what this end's have to write goes on its own streams.
class RaihaNextHTTP3ConnectionQPACKStreamsTest < Minitest::Test
  include NextHTTP3Pair

  QPACK = HTTP3::QPACK

  def server(**settings)
    server = HTTP3::Connection.server(settings: HTTP3::Settings.new(**settings))
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server)
    server
  end

  def capacity(value) = QPACK::Writer.new.integer(value, 5, 0x20).to_s

  # Insert with Literal Name; a string's prefix has its H bit in it.
  def insert(name, value) = QPACK::Writer.new.string(name, 6, 0x40).string(value, 8).to_s

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  # Past the capacity this end allows, which is none by default.
  def test_the_peers_encoder_stream_goes_to_the_decoder
    server = server()
    server.stream_data(6, "\x02".b + capacity(4096))
    assert_equal QPACK::ErrorCode::ENCODER_STREAM_ERROR, closed_with(server)
  end

  # An entry inserted is owed an Insert Count Increment, which goes on
  # this end's decoder stream.
  def test_the_decoders_instructions_go_on_this_ends_decoder_stream
    server = server(qpack_max_table_capacity: 4096)
    bytes = "\x02".b + capacity(4096) + insert("x-name", "value")
    bytes.each_char { |byte| server.stream_data(6, byte) }
    assert_nil closed_with(server)
    assert_equal({ 11 => ["\x01".b, false] }, sent(server))
    assert_empty sent(server)
  end

  # Once the connection is closed, what the decoder still owes goes
  # nowhere.
  def test_no_instructions_after_closing
    server = server(qpack_max_table_capacity: 4096)
    server.stream_data(6, "\x02".b + capacity(4096) + insert("x-name", "value"))
    server.stream_data(10, "\x03\x80".b)
    assert_equal QPACK::ErrorCode::DECODER_STREAM_ERROR, closed_with(server)
    assert_empty sent(server)
  end

  # This end's encoder inserts nothing: a Section Acknowledgment for it
  # is QPACK_DECODER_STREAM_ERROR, a Stream Cancellation is taken.
  def test_the_peers_decoder_stream_goes_to_the_encoder
    server = server()
    server.stream_data(10, "\x03\x40".b)
    assert_nil closed_with(server)
    server.stream_data(10, "\x80".b)
    assert_equal QPACK::ErrorCode::DECODER_STREAM_ERROR, closed_with(server)
  end
end
