require "test_helper"
require "tmpdir"
require "raiha/http3/server"
require "raiha/http3/request"

class RaihaHTTP3ServerTest < Minitest::Test
  def setup
    @stream = StreamDouble.new
    @connection = ConnectionDouble.new(@stream)
    @server = Raiha::HTTP3::Server.new(connection: @connection)
  end

  def test_serve_static_returns_file_for_get
    Dir.mktmpdir do |root|
      File.binwrite(File.join(root, "hello.txt"), "Hello, world!")

      request = build_request(method: "GET", path: "/hello.txt")
      @server.serve_static(@stream, request, root: root)

      status, headers, body = decode_response(@stream)
      assert_equal "200", status
      assert_equal "Hello, world!", body
      assert_includes headers, ["content-length", "13"]
    end
  end

  def test_serve_static_strips_query_string
    Dir.mktmpdir do |root|
      File.binwrite(File.join(root, "hello.txt"), "ok")
      request = build_request(method: "GET", path: "/hello.txt?cache=1")
      @server.serve_static(@stream, request, root: root)

      status, _, body = decode_response(@stream)
      assert_equal "200", status
      assert_equal "ok", body
    end
  end

  def test_serve_static_returns_404_for_missing_file
    Dir.mktmpdir do |root|
      request = build_request(method: "GET", path: "/missing.txt")
      @server.serve_static(@stream, request, root: root)

      status, _, _ = decode_response(@stream)
      assert_equal "404", status
    end
  end

  def test_serve_static_blocks_traversal
    Dir.mktmpdir do |outer|
      root = File.join(outer, "www")
      Dir.mkdir(root)
      File.binwrite(File.join(outer, "secret.txt"), "secret")

      request = build_request(method: "GET", path: "/../secret.txt")
      @server.serve_static(@stream, request, root: root)

      status, _, _ = decode_response(@stream)
      assert_equal "404", status
    end
  end

  def test_serve_static_rejects_non_get_method
    Dir.mktmpdir do |root|
      File.binwrite(File.join(root, "hello.txt"), "ok")
      request = build_request(method: "POST", path: "/hello.txt")
      @server.serve_static(@stream, request, root: root)

      status, _, _ = decode_response(@stream)
      assert_equal "405", status
    end
  end

  def test_serve_static_handles_invalid_uri
    Dir.mktmpdir do |root|
      request = build_request(method: "GET", path: "")
      @server.serve_static(@stream, request, root: root)

      status, _, _ = decode_response(@stream)
      assert_equal "404", status
    end
  end

  private def build_request(method:, path:)
    headers = [
      [":method", method],
      [":scheme", "https"],
      [":authority", "example.com"],
      [":path", path],
    ]
    Raiha::HTTP3::Request.new(headers: headers)
  end

  private def decode_response(stream)
    payload = stream.sent_payload
    buffer = Raiha::Quic::Wire::Buffer.new(payload)

    status = nil
    headers = []
    body = String.new(encoding: "BINARY")
    decoder = Raiha::HTTP3::QPACK::Decoder.new

    until buffer.eof?
      frame = Raiha::HTTP3::Frame.parse(buffer)
      case frame
      when Raiha::HTTP3::HeadersFrame
        decoded = decoder.decode(frame.encoded_field_section)
        status = decoded.find { |n, _| n == ":status" }&.last
        headers = decoded.reject { |n, _| n.start_with?(":") }
      when Raiha::HTTP3::DataFrame
        body << frame.data
      end
    end
    [status, headers, body]
  end

  class StreamDouble
    attr_reader :sent_payload

    def initialize
      @stream_id = StreamIdDouble.new
      @sent_payload = String.new(encoding: "BINARY")
    end

    def stream_id
      @stream_id
    end

    def append(payload)
      @sent_payload << payload
    end

    class StreamIdDouble
      def value
        0
      end
    end
  end

  class ConnectionDouble
    def initialize(stream)
      @stream = stream
    end

    def send_stream_data(_stream_id, payload, fin: false)
      @stream.append(payload)
    end
  end
end
