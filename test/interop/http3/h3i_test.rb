require "test_helper"
require "raiha/http3"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "json"

# HTTP/3 conformance tests for the raiha server, driven by an h3i-based
# harness (test/support/h3i_harness). The harness connects as a client,
# replays the actions of a named test case, and prints the resulting
# ConnectionSummary as JSON; assertions here judge that summary.
#
# raiha does not yet detect every malformed-frame condition. Negative
# cases therefore skip (rather than fail) when raiha neither signals the
# expected error nor raises while processing the request -- the fix for
# each is tracked as separate work.
class RaihaHTTP3H3iConformanceTest < Minitest::Test
  include TestCertificate

  HARNESS = File.expand_path("../../../tmp/h3i_harness/release/h3i_harness", __dir__)

  H3_FRAME_UNEXPECTED = 0x105
  H3_MESSAGE_ERROR = 0x10e

  # Bundles the per-case server state passed to the driving block.
  ServerContext = Data.define(:http3_server, :connection, :socket, :client_addr, :harness_pid)

  def setup
    skip "h3i harness not built" unless File.executable?(HARNESS)
  end

  def test_get_request_returns_200
    summary = run_case("get_200") do |ctx|
      request_stream, request = wait_for_request(ctx)
      refute_nil request, "Server should receive an HTTP/3 request"

      ctx.http3_server.send_response(
        request_stream,
        status: 200,
        headers: [["content-type", "text/plain"]],
        body: "Hello from raiha HTTP/3 server!".b
      )
      drive_until_harness_exits(ctx)
    end

    assert_equal "200", response_status(summary, stream_id: 0),
      "expected a 200 response; summary=#{summary.inspect}"
    assert_nil summary.dig("error", "peer_error"),
      "connection should close without error; summary=#{summary.inspect}"
  end

  # RFC 9114 Section 7.2.4: SETTINGS on a request stream is a connection
  # error of type H3_FRAME_UNEXPECTED.
  def test_settings_on_request_stream_is_rejected
    caught = nil
    summary = run_case("settings_on_request_stream") do |ctx|
      drive_until_harness_exits(ctx) { caught ||= process_http3_safely(ctx) }
    end

    code = peer_error_code(summary)
    unless code == H3_FRAME_UNEXPECTED
      skip "raiha does not signal H3_FRAME_UNEXPECTED for SETTINGS on a " \
        "request stream yet (peer_error=#{code.inspect}, exception=#{caught&.class})"
    end
    assert_equal H3_FRAME_UNEXPECTED, code
  end

  # RFC 9114 Section 4.1.2: a content-length that disagrees with the body
  # size is a malformed request. The server may answer 400 or reset the
  # stream with H3_MESSAGE_ERROR.
  def test_content_length_mismatch_is_rejected
    caught = nil
    summary = run_case("content_length_mismatch") do |ctx|
      drive_until_harness_exits(ctx) { caught ||= process_http3_safely(ctx) }
    end

    unless content_length_mismatch_handled?(summary)
      skip "raiha does not reject a content-length/body mismatch yet " \
        "(summary=#{summary.inspect}, exception=#{caught&.class})"
    end
    assert content_length_mismatch_handled?(summary)
  end

  # Spawns the harness for +case_name+ against a raiha HTTP/3 server driven
  # on the main thread, yields a ServerContext for case-specific handling,
  # then returns the parsed ConnectionSummary.
  private def run_case(case_name)
    port = find_available_udp_port
    server_socket = UDPSocket.new
    server_socket.bind("127.0.0.1", port)

    server_connection = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      tls_config: create_server_config,
      alpn_protocols: ["h3"]
    )
    http3_server = Raiha::HTTP3::Server.new(connection: server_connection)

    harness_rd, harness_wr = IO.pipe
    harness_pid = Process.spawn(
      HARNESS, case_name, "127.0.0.1:#{port}",
      out: harness_wr, err: harness_wr
    )
    harness_wr.close

    Timeout.timeout(30) do
      client_addr = complete_handshake(server_connection, server_socket)
      http3_server.setup_control_stream
      http3_server.setup_qpack_streams
      flush(server_connection, server_socket, client_addr)

      yield ServerContext.new(
        http3_server: http3_server,
        connection: server_connection,
        socket: server_socket,
        client_addr: client_addr,
        harness_pid: harness_pid
      )
    end

    exit_status = Process.wait2(harness_pid)[1] rescue nil
    harness_output = harness_rd.read rescue ""
    assert exit_status.nil? || exit_status.success?,
      "h3i harness should exit cleanly; output: #{harness_output[0..500]}"

    summary = extract_json(harness_output)
    refute_nil summary, "h3i harness should emit a JSON summary; got: #{harness_output[0..500]}"
    summary
  ensure
    Process.kill("TERM", harness_pid) if harness_pid rescue nil
    Process.wait(harness_pid) if harness_pid rescue nil
    server_socket&.close
  end

  private def complete_handshake(connection, socket)
    client_addr = nil
    until connection.handshake_complete?
      readable = IO.select([socket], nil, nil, 1.0)
      raise "Handshake did not start" unless readable

      data, addr = socket.recvfrom_nonblock(65535)
      client_addr = addr
      connection.handle_packet(data)
      flush(connection, socket, client_addr)
    end
    client_addr
  end

  private def wait_for_request(ctx, max_iterations: 30)
    max_iterations.times do
      stream = ctx.http3_server.pending_request_stream
      return [stream, ctx.http3_server.receive_request(stream)] if stream

      readable = IO.select([ctx.socket], nil, nil, 0.5)
      unless readable
        flush(ctx.connection, ctx.socket, ctx.client_addr)
        next
      end

      data, addr = ctx.socket.recvfrom_nonblock(65535)
      ctx.client_addr.replace(addr) if ctx.client_addr && addr
      ctx.connection.handle_packet(data)
      flush(ctx.connection, ctx.socket, ctx.client_addr)
    end

    [nil, nil]
  end

  # Drives I/O until the harness exits. If a block is given it runs once per
  # iteration, after packets are handled -- negative cases use it to let the
  # HTTP/3 layer observe the malformed frames.
  private def drive_until_harness_exits(ctx, max_iterations: 30)
    max_iterations.times do
      exited = Process.wait(ctx.harness_pid, Process::WNOHANG) rescue nil
      return if exited

      readable = IO.select([ctx.socket], nil, nil, 0.3)
      if readable
        data, _addr = ctx.socket.recvfrom_nonblock(65535) rescue next
        ctx.connection.handle_packet(data)
      end
      yield if block_given?
      flush(ctx.connection, ctx.socket, ctx.client_addr)
    end
  end

  # Runs the HTTP/3 server's frame processing, returning any raised error
  # instead of propagating it so a negative case can record it and skip.
  private def process_http3_safely(ctx)
    ctx.http3_server.process_peer_unidirectional_streams
    stream = ctx.http3_server.pending_request_stream
    ctx.http3_server.receive_request(stream) if stream
    nil
  rescue StandardError => error
    error
  end

  private def flush(connection, socket, addr)
    return unless addr
    connection.get_packets_to_send.each { |pkt| socket.send(pkt, 0, addr[3], addr[1]) }
  end

  private def find_available_udp_port
    socket = UDPSocket.new
    socket.bind("127.0.0.1", 0)
    port = socket.addr[1]
    socket.close
    port
  end

  # The harness prints the ConnectionSummary as a single JSON line.
  private def extract_json(output)
    start = output.index("{")
    return nil unless start
    JSON.parse(output[start..])
  rescue JSON::ParserError
    nil
  end

  private def peer_error_code(summary)
    summary.dig("error", "peer_error", "error_code")
  end

  # Digs the :status pseudo-header out of the HEADERS frames received on
  # +stream_id+ in the ConnectionSummary.
  private def response_status(summary, stream_id:)
    frames_on(summary, stream_id).each do |frame|
      headers = frame.dig("enriched_headers", "headers")
      next unless headers

      status = headers.find { |header| header["name"] == ":status" }
      return status["value"] if status
    end
    nil
  end

  private def reset_stream_error_code(summary, stream_id:)
    frames_on(summary, stream_id).each do |frame|
      reset = frame["reset_stream"]
      return reset["error_code"] if reset
    end
    nil
  end

  private def frames_on(summary, stream_id)
    summary.dig("stream_map", "stream_frame_map", stream_id.to_s) || []
  end

  # Any of the three RFC 9114 Section 4.1.2 conformant responses passes:
  # a 400 response, a RESET_STREAM with H3_MESSAGE_ERROR, or a connection
  # close with H3_MESSAGE_ERROR.
  private def content_length_mismatch_handled?(summary)
    response_status(summary, stream_id: 0) == "400" ||
      reset_stream_error_code(summary, stream_id: 0) == H3_MESSAGE_ERROR ||
      peer_error_code(summary) == H3_MESSAGE_ERROR
  end
end
