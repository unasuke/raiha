require "test_helper"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSRoundtripTest < Minitest::Test
  def test_roundtrip1
    client = Raiha::TLS::Client.new
    server = Raiha::TLS::Server.new

    client_first_request = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::WAIT_SH, client.state

    server.receive(client_first_request.join)
    assert_equal Raiha::TLS::Server::State::RECVD_CH, server.state

    server_first_response = server.datagrams_to_send
    assert server_first_response

    client.receive(server_first_response.join)
    assert_equal Raiha::TLS::Client::State::WAIT_SEND_FINISHED, client.state

    client_second_request = client.datagrams_to_send
    assert_equal Raiha::TLS::Client::State::CONNECTED, client.state
    assert client.finished?

    server.receive(client_second_request.join)
    assert_equal Raiha::TLS::Server::State::CONNECTED, server.state
    assert server.connected?
  end
end
