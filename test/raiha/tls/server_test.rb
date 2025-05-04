require "test_helper"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSServerTest < Minitest::Test
  def test_receive_client_hello
    server = Raiha::TLS::Server.new
    client = Raiha::TLS::Client.new

    server.receive(client.datagrams_to_send.join)
    assert_equal Raiha::TLS::Server::State::RECVD_CH, server.state
  end

  def test_receive_invalid_client_hello
    # invalid legacy version
    server = Raiha::TLS::Server.new
    client = Raiha::TLS::Client.new
    client_request = client.datagrams_to_send
    client_request[0][9..10] = "\x03\x04" # Replace clienthello version to invalid legacy version, too hardcorded...
    server.receive(client_request.join)
    assert_equal Raiha::TLS::Server::State::ERROR_OCCURED, server.state
  end
end
