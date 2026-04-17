require "test_helper"
require "support/test_certificate"
require "raiha/tls/client"
require "raiha/tls/server"

class RaihaTLSSessionResumptionTest < Minitest::Test
  include TestCertificate

  def test_server_issues_new_session_ticket
    client, server = establish_connection

    # Server issues a NewSessionTicket after handshake
    ticket_record = server.build_new_session_ticket
    client.receive(ticket_record)

    # Client should have stored the ticket
    ticket_entry = client.instance_variable_get(:@session_ticket_store).get("")
    refute_nil ticket_entry
    refute_nil ticket_entry[:psk]
    refute_nil ticket_entry[:ticket]
  end

  def test_client_includes_psk_in_second_connection
    first_client, first_server = establish_connection

    # Server issues ticket
    ticket_record = first_server.build_new_session_ticket
    first_client.receive(ticket_record)

    # Extract the ticket store from first client
    ticket_store = first_client.instance_variable_get(:@session_ticket_store)

    # Create new client with the same ticket store
    second_client = Raiha::TLS::Client.new
    second_client.instance_variable_set(:@session_ticket_store, ticket_store)

    # Build ClientHello - should include PSK extension
    second_client.datagrams_to_send
    client_hello = second_client.instance_variable_get(:@client_hello)

    psk_ext = client_hello.extensions.find { |e| e.is_a?(Raiha::TLS::Handshake::Extension::PreSharedKey) }
    refute_nil psk_ext, "ClientHello should include PreSharedKey extension"
    assert_equal 1, psk_ext.identities.length
    assert_equal 1, psk_ext.binders.length

    psk_modes = client_hello.extensions.find { |e| e.is_a?(Raiha::TLS::Handshake::Extension::PskKeyExchangeModes) }
    refute_nil psk_modes, "ClientHello should include PskKeyExchangeModes extension"
    assert_includes psk_modes.modes, :psk_dhe_ke
  end

  private def establish_connection
    client = Raiha::TLS::Client.new
    server = Raiha::TLS::Server.new(config: create_server_config)

    client_hello = client.datagrams_to_send
    server.receive(client_hello.join)
    server_flight = server.datagrams_to_send
    client.receive(server_flight.join)
    client_finished = client.datagrams_to_send
    server.receive(client_finished.join)

    assert_equal Raiha::TLS::Client::State::CONNECTED, client.state
    assert_equal Raiha::TLS::Server::State::CONNECTED, server.state

    [client, server]
  end
end
