require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# A client's first HTTP/3 layer of a 0-RTT attempt, given the server's
# SETTINGS it remembered: they stand for the server's until those come,
# which must then keep a QPACK capacity remembered (RFC 9204 "Maximum
# Dynamic Table Capacity") and H3_DATAGRAM (RFC 9297).
class RaihaNextHTTP3ConnectionRememberedSettingsTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame

  # The client the server's control stream, with `settings`, went to: the
  # error code it closed with, or nil.
  def closed_with(client, settings)
    client.stream_data(3, "\x00".b + Frame.encode(settings.to_frame))
    actions(client).grep(HTTP3::Action::Close).first&.error_code
  end

  def test_compatible_settings
    remembered = HTTP3::Settings.new(qpack_max_table_capacity: 4096, h3_datagram: true)
    client = HTTP3::Connection.client(remembered:)
    assert_nil closed_with(client, HTTP3::Settings.new(qpack_max_table_capacity: 4096, h3_datagram: true, max_field_section_size: 1))
    assert_equal 1, client.peer_settings.max_field_section_size
    # A capacity of 0 remembered binds nothing.
    assert_nil closed_with(HTTP3::Connection.client(remembered: HTTP3::Settings.new), HTTP3::Settings.new(qpack_max_table_capacity: 100))
  end

  def test_settings_that_are_not
    remembered = HTTP3::Settings.new(qpack_max_table_capacity: 4096, h3_datagram: true)
    assert_equal HTTP3::QPACK::ErrorCode::DECODER_STREAM_ERROR,
      closed_with(HTTP3::Connection.client(remembered:), HTTP3::Settings.new(qpack_max_table_capacity: 1024, h3_datagram: true))
    assert_equal HTTP3::QPACK::ErrorCode::DECODER_STREAM_ERROR,
      closed_with(HTTP3::Connection.client(remembered:), HTTP3::Settings.new(h3_datagram: true))
    assert_equal HTTP3::ErrorCode::SETTINGS_ERROR,
      closed_with(HTTP3::Connection.client(remembered:), HTTP3::Settings.new(qpack_max_table_capacity: 4096))
  end

  # Until the server's come, a request goes by the remembered ones.
  def test_remembered_ones_stand_for_the_servers
    connect = [[":method", "CONNECT"], [":protocol", "websocket"], [":scheme", "https"], [":path", "/"], [":authority", "example.com"]]
    client = HTTP3::Connection.client(remembered: HTTP3::Settings.new(enable_connect_protocol: true))
    assert_nil client.peer_settings
    client.send_request(0, connect)
    assert_raises(ArgumentError) { HTTP3::Connection.client.send_request(0, connect) }
    assert_raises(ArgumentError) { HTTP3::Connection.client(remembered: {}) }
  end

  # What a server's 0-RTT is taken only if the same of: its settings by
  # identifier.
  def test_the_context_of_a_servers_settings
    settings = HTTP3::Settings.new(enable_connect_protocol: true, max_field_section_size: 1000)
    assert_equal [0x06, 1000, 0x08, 1].map { HTTP3::Varint.encode(_1) }.join.b, settings.early_data_context
    refute_equal settings.early_data_context, HTTP3::Settings.new.early_data_context
  end
end
