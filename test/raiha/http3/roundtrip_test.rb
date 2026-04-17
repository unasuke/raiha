require "test_helper"
require "raiha/http3"
require "raiha/connection"
require "support/test_certificate"

class RaihaHTTP3RoundtripTest < Minitest::Test
  include TestCertificate

  def test_get_request_response
    client_conn, server_conn = complete_handshake

    http3_client = Raiha::HTTP3::Client.new(connection: client_conn)
    http3_server = Raiha::HTTP3::Server.new(connection: server_conn)

    # Client sends GET request
    stream = http3_client.send_request(
      method: "GET", scheme: "https", authority: "example.com", path: "/"
    )

    # Transmit client → server
    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }

    # Server receives and processes request
    server_stream = server_conn.streams.get_stream(stream.stream_id.value)
    refute_nil server_stream
    request = http3_server.receive_request(server_stream)

    assert_equal "GET", request.method
    assert_equal "/", request.path
    assert_equal "https", request.scheme
    assert_equal "example.com", request.authority

    # Server sends response
    http3_server.send_response(
      server_stream,
      status: 200,
      headers: [["content-type", "text/plain"]],
      body: "Hello, World!"
    )

    # Transmit server → client
    server_conn.get_packets_to_send.each { |p| client_conn.handle_packet(p) }

    # Client receives response
    client_stream = client_conn.streams.get_stream(stream.stream_id.value)
    response = http3_client.receive_response(client_stream)

    assert_equal 200, response.status
    assert_equal "Hello, World!", response.body
    content_type = response.headers.find { |n, _| n == "content-type" }&.last
    assert_equal "text/plain", content_type
  end

  def test_post_request_with_body
    client_conn, server_conn = complete_handshake

    http3_client = Raiha::HTTP3::Client.new(connection: client_conn)
    http3_server = Raiha::HTTP3::Server.new(connection: server_conn)

    body = '{"key":"value"}'
    stream = http3_client.send_request(
      method: "POST", scheme: "https", authority: "api.example.com", path: "/data",
      headers: [["content-type", "application/json"]],
      body: body
    )

    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }

    server_stream = server_conn.streams.get_stream(stream.stream_id.value)
    request = http3_server.receive_request(server_stream)

    assert_equal "POST", request.method
    assert_equal "/data", request.path
    assert_equal body, request.body

    http3_server.send_response(server_stream, status: 201, body: "created")
    server_conn.get_packets_to_send.each { |p| client_conn.handle_packet(p) }

    client_stream = client_conn.streams.get_stream(stream.stream_id.value)
    response = http3_client.receive_response(client_stream)
    assert_equal 201, response.status
    assert_equal "created", response.body
  end

  private def complete_handshake
    dest_cid = Raiha::Quic::Protocol::ConnectionID.generate
    client_conn = Raiha::Connection.new(
      perspective: :client,
      src_connection_id: Raiha::Quic::Protocol::ConnectionID.generate,
      dest_connection_id: dest_cid
    )
    server_conn = Raiha::Connection.new(
      perspective: :server,
      src_connection_id: dest_cid,
      dest_connection_id: dest_cid,
      tls_config: create_server_config
    )

    client_conn.start_handshake
    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }
    server_conn.get_packets_to_send.each { |p| client_conn.handle_packet(p) }
    client_conn.get_packets_to_send.each { |p| server_conn.handle_packet(p) }

    [client_conn, server_conn]
  end
end
