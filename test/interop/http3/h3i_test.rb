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
class RaihaHTTP3H3iConformanceTest < Minitest::Test
  include TestCertificate

  HARNESS = File.expand_path("../../../tmp/h3i_harness/release/h3i_harness", __dir__)

  def setup
    skip "h3i harness not built" unless File.executable?(HARNESS)
  end

  def test_get_request_returns_200
    summary = run_case("get_200") do |http3_server, connection, socket, client_addr|
      request_stream, request = wait_for_request(http3_server, connection, socket, client_addr)
      refute_nil request, "Server should receive an HTTP/3 request"

      http3_server.send_response(
        request_stream,
        status: 200,
        headers: [["content-type", "text/plain"]],
        body: "Hello from raiha HTTP/3 server!".b
      )
    end

    assert_equal "200", response_status(summary, stream_id: 0),
      "expected a 200 response; summary=#{summary.inspect}"
    assert_nil summary.dig("error", "peer_error"),
      "connection should close without error; summary=#{summary.inspect}"
  end

  # Spawns the harness for +case_name+ against a raiha HTTP/3 server driven
  # on the main thread, yields for case-specific request handling, then
  # returns the parsed ConnectionSummary.
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

      yield http3_server, server_connection, server_socket, client_addr

      drive_until_harness_exits(server_connection, server_socket, client_addr, harness_pid)
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

  private def wait_for_request(http3_server, connection, socket, client_addr, max_iterations: 30)
    max_iterations.times do
      stream = http3_server.pending_request_stream
      return [stream, http3_server.receive_request(stream)] if stream

      readable = IO.select([socket], nil, nil, 0.5)
      unless readable
        flush(connection, socket, client_addr)
        next
      end

      data, addr = socket.recvfrom_nonblock(65535)
      client_addr.replace(addr) if client_addr && addr
      connection.handle_packet(data)
      flush(connection, socket, client_addr)
    end

    [nil, nil]
  end

  private def drive_until_harness_exits(connection, socket, client_addr, harness_pid, max_iterations: 30)
    max_iterations.times do
      exited = Process.wait(harness_pid, Process::WNOHANG) rescue nil
      return if exited

      readable = IO.select([socket], nil, nil, 0.3)
      if readable
        data, _addr = socket.recvfrom_nonblock(65535) rescue next
        connection.handle_packet(data)
      end
      flush(connection, socket, client_addr)
    end
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

  # Digs the :status pseudo-header out of the HEADERS frames received on
  # +stream_id+ in the ConnectionSummary.
  private def response_status(summary, stream_id:)
    frames = summary.dig("stream_map", "stream_frame_map", stream_id.to_s) || []
    frames.each do |frame|
      headers = frame.dig("enriched_headers", "headers")
      next unless headers

      status = headers.find { |header| header["name"] == ":status" }
      return status["value"] if status
    end
    nil
  end
end
