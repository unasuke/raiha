require "test_helper"
require "support/http3_udp"
require "json"

# A server of the next release of raiha over UDP against the h3i harness
# (test/support/h3i_harness), which connects as a client, sends what the
# named case says and prints what came back as a ConnectionSummary in
# JSON. The server answers every request that has come whole with 200.
class NextHTTP3H3iTest < Minitest::Test
  include NextHTTP3UDP

  HARNESS = File.expand_path("../../../tmp/h3i_harness/release/h3i_harness", __dir__)

  def setup
    skip "h3i harness not built" unless File.executable?(HARNESS)
  end

  def test_get_request_returns_200
    summary = run_case("get_200")
    assert_equal "200", response_status(summary, 0), summary.inspect
    assert_nil summary.dig("error", "peer_error"), summary.inspect
  end

  # RFC 9114 "SETTINGS": a SETTINGS frame on a request stream is
  # H3_FRAME_UNEXPECTED, for the connection.
  def test_settings_on_request_stream_is_rejected
    summary = run_case("settings_on_request_stream")
    assert_equal HTTP3::ErrorCode::FRAME_UNEXPECTED, summary.dig("error", "peer_error", "error_code"), summary.inspect
  end

  # RFC 9114 "Malformed Requests and Responses": content shorter than its
  # content-length is H3_MESSAGE_ERROR, for the stream.
  def test_content_length_mismatch_is_rejected
    summary = run_case("content_length_mismatch")
    assert_equal HTTP3::ErrorCode::MESSAGE_ERROR, reset_stream_error_code(summary, 0), summary.inspect
  end

  # Runs the harness for `name` against a server until it prints its
  # summary, and gives the summary.
  private def run_case(name)
    summary = nil
    server(alpn: ALPN) do |socket, quic|
      app = Server.new(quic, body: "Hello from raiha".b)
      peer(HARNESS, name, "127.0.0.1:#{socket.addr[1]}") do |output|
        done = drive(socket, quic, seconds: 20) do
          app.step(mono)
          summary = extract_json(output)
        end
        assert done, output
      end
    end
    summary
  end

  # The line the harness prints its summary on.
  private def extract_json(output)
    line = output.each_line.find { _1.start_with?("{") } or return nil
    JSON.parse(line)
  rescue JSON::ParserError
    nil
  end

  # The :status of the HEADERS frames that came on `stream_id`.
  private def response_status(summary, stream_id)
    frames_on(summary, stream_id).each do |frame|
      status = frame.dig("enriched_headers", "headers")&.find { _1["name"] == ":status" }
      return status["value"] if status
    end
    nil
  end

  private def reset_stream_error_code(summary, stream_id)
    frames_on(summary, stream_id).filter_map { _1.dig("reset_stream", "error_code") }.first
  end

  private def frames_on(summary, stream_id) = summary.dig("stream_map", "stream_frame_map", stream_id.to_s) || []
end
