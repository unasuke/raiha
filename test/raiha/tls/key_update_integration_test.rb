require "test_helper"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSKeyUpdateIntegrationTest < Minitest::Test
  def test_key_update_after_handshake
    client, server = establish_connection

    # Client sends application data before key update
    encrypted = client.encrypt_application_data("hello before key update")
    assert encrypted

    # Client sends KeyUpdate
    key_update_records = client.send_key_update(request_update: :update_not_requested)
    assert key_update_records
    refute_empty key_update_records

    # Client sends application data after key update (with new keys)
    encrypted_after = client.encrypt_application_data("hello after key update")
    assert encrypted_after
  end

  def test_key_update_with_request
    client, server = establish_connection

    # Client sends KeyUpdate with update_requested
    key_update_records = client.send_key_update(request_update: :update_requested)
    assert key_update_records
    refute_empty key_update_records

    # Client can still encrypt after updating keys
    encrypted = client.encrypt_application_data("after key update")
    assert encrypted
  end

  private def establish_connection
    client = Raiha::TLS::Client.new
    server = Raiha::TLS::Server.new

    client_first = client.datagrams_to_send
    server.receive(client_first.join)
    server_response = server.datagrams_to_send
    client.receive(server_response.join)
    client_finished = client.datagrams_to_send
    server.receive(client_finished.join)

    assert_equal Raiha::TLS::Client::State::CONNECTED, client.state
    assert_equal Raiha::TLS::Server::State::CONNECTED, server.state

    [client, server]
  end
end
