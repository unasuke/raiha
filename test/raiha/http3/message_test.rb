require "test_helper"
require "raiha/http3"

# RFC 9114 "Malformed Requests and Responses" on field sections.
class RaihaNextHTTP3MessageTest < Minitest::Test
  Message = Raiha::HTTP3::Message

  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze

  def request(headers, extended_connect: false) = Message.request(headers, extended_connect:)

  def assert_malformed(headers, extended_connect: false)
    assert_raises(Message::Malformed, headers.inspect) { request(headers, extended_connect:) }
  end

  def test_requests
    assert_nil request(GET)
    assert_nil request([[":method", "GET"], [":scheme", "https"], [":path", "/"], ["host", "example.com"]])
    assert_nil request(GET + [["host", "example.com"], ["te", "trailers"], ["accept", "*/*"]])
    assert_nil request([[":method", "OPTIONS"], [":scheme", "https"], [":authority", "a"], [":path", "*"]])
    assert_nil request([[":method", "GET"], [":scheme", "urn"], [":path", "x"]])
    assert_equal 5, request(GET + [["content-length", "5"], ["content-length", "5"]])
  end

  # RFC 9114 "The CONNECT Method", and Extended CONNECT (RFC 9220) only
  # when this end took it.
  def test_connect
    assert_nil request([[":method", "CONNECT"], [":authority", "example.com:443"]])
    extended = [[":method", "CONNECT"], [":protocol", "websocket"], [":scheme", "https"], [":authority", "a"], [":path", "/chat"]]
    assert_nil request(extended, extended_connect: true)
    assert_malformed extended
    assert_malformed extended.reject { |name, _| name == ":path" }, extended_connect: true
    assert_malformed [[":method", "GET"], [":protocol", "websocket"], [":scheme", "https"], [":authority", "a"], [":path", "/"]], extended_connect: true
    assert_malformed [[":method", "CONNECT"], [":authority", "a"], [":path", "/"]]
    assert_malformed [[":method", "CONNECT"]]
  end

  def test_pseudo_header_fields
    assert_malformed [[":method", "GET"], ["accept", "*/*"], [":scheme", "https"], [":authority", "a"], [":path", "/"]]
    assert_malformed GET + [[":foo", "x"]]
    assert_malformed GET + [[":path", "/again"]]
    assert_malformed GET + [[":status", "200"]]
    %w[:method :scheme :path].each { |name| assert_malformed GET.reject { _1.first == name } }
    assert_malformed GET.map { |name, value| name == ":path" ? [name, ""] : [name, value] }
  end

  # RFC 9114 "Request Pseudo-Header Fields": the :path of http and https
  # is an absolute path, or "*" for OPTIONS.
  def test_the_path
    with = ->(method, path) { [[":method", method], [":scheme", "https"], [":authority", "a"], [":path", path]] }
    assert_nil request(with.("GET", "/a/b?c=d"))
    ["a", "?x", "*", "https://example.com/", "example.com:443"].each { |path| assert_malformed with.("GET", path) }
    assert_malformed with.("OPTIONS", "**")
  end

  def test_names_and_values
    assert_malformed GET + [["Accept", "*/*"]]
    assert_malformed GET + [["bad name", "x"]]
    assert_malformed GET + [["", "x"]]
    ["a\x00b", "a\rb", "a\nb"].each { |value| assert_malformed GET + [["x-value", value]] }
  end

  def test_fields_of_one_connection
    %w[connection keep-alive proxy-connection transfer-encoding upgrade].each { |name| assert_malformed GET + [[name, "x"]] }
    assert_malformed GET + [["te", "gzip"]]
  end

  # RFC 9114 "Request Pseudo-Header Fields".
  def test_the_authority
    no_authority = GET.reject { _1.first == ":authority" }
    assert_malformed no_authority
    assert_malformed GET + [["host", "other.example"]]
    assert_malformed no_authority + [["host", "a"], ["host", "a"]]
    assert_malformed GET.map { |name, value| name == ":authority" ? [name, ""] : [name, value] }
    assert_malformed GET.map { |name, value| name == ":authority" ? [name, "user@example.com"] : [name, value] }
  end

  def test_content_length
    assert_malformed GET + [["content-length", "5"], ["content-length", "6"]]
    assert_malformed GET + [["content-length", "-1"]]
    assert_malformed GET + [["content-length", "5, 5"]]
  end

  def test_responses
    assert_equal [200, nil], Message.response([[":status", "200"], ["content-type", "text/plain"]])
    assert_equal [103, nil], Message.response([[":status", "103"]])
    assert_equal [204, 0], Message.response([[":status", "204"], ["content-length", "0"]])
    [[], [[":status", "20"]], [[":status", "600"]], [[":status", "200"], [":path", "/"]], [["x", "y"], [":status", "200"]]].each do |headers|
      assert_raises(Message::Malformed, headers.inspect) { Message.response(headers) }
    end
  end

  def test_trailers
    assert_nil Message.trailers([["x-checksum", "abc"]])
    assert_raises(Message::Malformed) { Message.trailers([[":status", "200"]]) }
  end
end
