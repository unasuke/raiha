require "test_helper"
require "raiha/http3"
require "raiha/connection"
require "support/test_certificate"
require "socket"
require "timeout"
require "json"

class RaihaHTTP3QuicheServerInteropTest < Minitest::Test
  include TestCertificate

  QUICHE_CLIENT = File.expand_path("../../../tmp/quiche/target/release/quiche-client", __dir__)

  def setup
    skip "quiche-client not found" unless File.executable?(QUICHE_CLIENT)
  end

  def test_quiche_client_get_request_to_raiha_http3_server
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

    response_body = "Hello from raiha HTTP/3 server!".b

    client_rd, client_wr = IO.pipe
    client_pid = Process.spawn(
      QUICHE_CLIENT,
      "--no-verify",
      "--no-grease",
      # Force QUICv1 wire version: quiche sends GREASE by default which requires
      # the server to emit a Version Negotiation packet, not yet implemented.
      "--wire-version", "00000001",
      "--dump-json",
      "https://127.0.0.1:#{port}/test",
      out: client_wr, err: client_wr
    )
    client_wr.close

    Timeout.timeout(30) do
      client_addr = complete_handshake(server_connection, server_socket)
      http3_server.setup_control_stream
      flush(server_connection, server_socket, client_addr)

      request_stream, request = wait_for_request(http3_server, server_connection, server_socket, client_addr)
      refute_nil request, "Server should receive an HTTP/3 request"
      assert_equal "GET", request.method
      assert_equal "/test", request.path

      http3_server.send_response(
        request_stream,
        status: 200,
        headers: [["content-type", "text/plain"]],
        body: response_body
      )

      # Drive I/O until quiche-client exits successfully
      drive_until_client_exits(server_connection, server_socket, client_addr, client_pid)
    end

    exit_status = Process.wait2(client_pid)[1] rescue nil
    assert exit_status.nil? || exit_status.success?, "quiche-client should exit cleanly"

    client_output = client_rd.read rescue ""
    json = extract_json(client_output)
    refute_nil json, "quiche-client should emit JSON response; got: #{client_output[0..500]}"
    assert_equal response_body, json["body"] if json.key?("body")
  ensure
    Process.kill("TERM", client_pid) if client_pid rescue nil
    Process.wait(client_pid) if client_pid rescue nil
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

  private def drive_until_client_exits(connection, socket, client_addr, client_pid, max_iterations: 30)
    max_iterations.times do
      exited = Process.wait(client_pid, Process::WNOHANG) rescue nil
      return if exited

      readable = IO.select([socket], nil, nil, 0.3)
      if readable
        data, addr = socket.recvfrom_nonblock(65535) rescue next
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

  # quiche-client --dump-json prints a JSON document; extract it from stdout.
  private def extract_json(output)
    start = output.index("{")
    return nil unless start
    JSON.parse(output[start..])
  rescue JSON::ParserError
    nil
  end
end
