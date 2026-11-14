require "test_helper"
require "support/http3_pair"

# The priorities of RFC 9218 on HTTP/3 requests: the Priority header
# field, PRIORITY_UPDATE before and after a request opens, a server's
# response overriding, and the order the streams are given to send in.
class RaihaHTTP3ConnectionPriorityTest < Minitest::Test
  include HTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  SETTINGS = Frame.encode(HTTP3::Settings.new.to_frame)

  def server
    server = HTTP3::Connection.server
    server.start(**SERVER_STREAMS)
    sent(server)
    actions(server, priorities: true)
    server.stream_data(2, "\x00".b + SETTINGS)
    server
  end

  def priority(stream_id, urgency, incremental) = HTTP3::Action::Priority.new(stream_id:, urgency:, incremental:)

  def priorities(connection) = actions(connection, priorities: true).grep(HTTP3::Action::Priority)

  def headers(fields, stream_id: 0) = Frame.encode(Frame::Headers.new(field_section: QPACK::Encoder.new.encode(stream_id, fields.map { QPACK::Field.new(name: _1, value: _2) })))

  def update(stream_id, value, push: false) = Frame.encode(Frame::PriorityUpdate.new(element_id: stream_id, priority: value, push:))

  def closed_with(connection) = actions(connection).grep(HTTP3::Action::Close).first&.error_code

  # A request asks with its Priority header fields, the defaults when it
  # has none.
  def test_the_priority_a_request_asks_for
    server = server()
    server.stream_data(0, headers(GET))
    server.stream_data(4, headers(GET + [["priority", "u=1"], ["priority", "i"]], stream_id: 4))
    server.stream_data(8, headers(GET + [["priority", "u=9, x=?1"]], stream_id: 8))
    assert_equal [priority(0, 3, false), priority(4, 1, true), priority(8, 3, false)], priorities(server)
  end

  # "The PRIORITY_UPDATE Frame": the latest signal wins, and one for a
  # request not opened yet waits for it.
  def test_priority_updates
    server = server()
    server.stream_data(2, update(4, "u=0") + update(4, "u=2, i"))
    assert_empty priorities(server)
    server.stream_data(4, headers(GET + [["priority", "u=6"]], stream_id: 4))
    assert_equal [priority(4, 2, true)], priorities(server)
    server.stream_data(2, update(4, "i"))
    assert_equal [priority(4, 3, true)], priorities(server)
    server.stream_data(2, update(4, "u=(1 2"))
    assert_empty priorities(server)
    assert_nil closed_with(server)
  end

  def test_priority_updates_this_end_does_not_take
    [update(2, "u=1"), update(0, "u=1", push: true)].each do |frame|
      server = server()
      server.stream_data(2, frame)
      assert_equal HTTP3::ErrorCode::ID_ERROR, closed_with(server)
    end
  end

  # Those for requests not opened yet are kept for MAX_PENDING_PRIORITIES
  # of them; the rest are dropped.
  def test_priority_updates_kept_for_so_many
    server = server()
    limit = HTTP3::Connection::MAX_PENDING_PRIORITIES
    server.stream_data(2, (1..limit + 1).map { update(_1 * 4, "u=0") }.join)
    [4, (limit + 1) * 4].each { |stream_id| server.stream_data(stream_id, headers(GET, stream_id:)) }
    assert_equal [priority(4, 0, false), priority((limit + 1) * 4, 3, false)], priorities(server)
  end

  # "Merging Client- and Server-Driven Priority Parameters": the response
  # overrides what it gives.
  def test_a_server_overrides
    server = server()
    server.stream_data(0, headers(GET + [["priority", "u=5, i"]]))
    priorities(server)
    server.send_headers(0, [[":status", "200"], ["priority", "u=1"]])
    server.update_priority(0, urgency: 0, incremental: false)
    assert_equal [priority(0, 1, true), priority(0, 0, false)], priorities(server)
    server.update_priority(0, incremental: true)
    server.update_priority(0, urgency: 6)
    assert_equal [priority(0, 0, true), priority(0, 6, true)], priorities(server)
    assert_raises(HTTP3::Error::Usage) { server.update_priority(4, urgency: 0, incremental: false) }
  end

  # The most urgent stream is given to the transport first.
  def test_the_order_of_sending
    server = server()
    server.stream_data(0, headers(GET + [["priority", "u=6"]]))
    server.stream_data(4, headers(GET + [["priority", "u=1"]], stream_id: 4))
    [0, 4].each { |stream_id| server.send_headers(stream_id, [[":status", "200"]], fin: true) }
    order = []
    server.each_send { |stream_id, data, _| order << stream_id if stream_id & 0x3 == 0; data.bytesize }
    assert_equal [4, 0], order
  end

  # A client asks with PRIORITY_UPDATE, and sends what it sends by it.
  def test_a_client_asks
    client = HTTP3::Connection.client
    assert_raises(HTTP3::Error::Usage) { client.send_request(0, GET).then { client.update_priority(0, urgency: 0, incremental: true) } }
    client.start(**CLIENT_STREAMS)
    sent(client)
    priorities(client)
    client.send_request(4, GET + [["priority", "u=2"]])
    client.update_priority(4, urgency: 0, incremental: true)
    assert_equal [priority(4, 2, false), priority(4, 0, true)], priorities(client)
    assert_equal update(4, "u=0, i"), sent(client).fetch(2).first
  end
end
