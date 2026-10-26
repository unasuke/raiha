require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# An HTTP/3 Connection made and given its streams: the control stream
# with this end's SETTINGS, the QPACK streams, and their priority.
class RaihaNextHTTP3ConnectionStartTest < Minitest::Test
  include NextHTTP3Pair

  def test_the_streams_of_a_client
    client = HTTP3::Connection.client
    client.start(**CLIENT_STREAMS)
    settings = HTTP3::Frame.encode(HTTP3::Settings.new.to_frame)
    assert_equal({ 2 => ["\x00".b + settings, false], 6 => ["\x02".b, false], 10 => ["\x03".b, false] }, sent(client))
    assert_equal [2, 6, 10].map { HTTP3::Action::Priority.new(stream_id: _1, urgency: 0, incremental: true) }, actions(client)
    assert_empty sent(client)
  end

  # A server takes Extended CONNECT unless told otherwise (RFC 9220).
  def test_the_settings_of_a_server
    server = HTTP3::Connection.server
    server.start(**SERVER_STREAMS)
    settings = HTTP3::Settings.new(enable_connect_protocol: true).to_frame
    assert_equal "\x00".b + HTTP3::Frame.encode(settings), sent(server).fetch(3).first
  end

  def test_the_streams_are_checked
    client = HTTP3::Connection.client
    assert_raises(ArgumentError) { client.start(**SERVER_STREAMS) }
    assert_raises(ArgumentError) { client.start(control: 2, encoder: 2, decoder: 6) }
    assert_raises(ArgumentError) { client.start(control: 0, encoder: 6, decoder: 10) }
    client.start(**CLIENT_STREAMS)
    assert_raises(HTTP3::Error::Usage) { client.start(control: 14, encoder: 18, decoder: 22) }
  end

  def test_the_arguments_are_checked
    assert_raises(ArgumentError) { HTTP3::Connection.client(settings: HTTP3::Settings.new(max_field_section_size: nil)) }
    assert_raises(ArgumentError) { HTTP3::Connection.client(transport_ordering: :none) }
    assert_raises(ArgumentError) { HTTP3::Connection.server(max_send_buffer: 0) }
  end
end
