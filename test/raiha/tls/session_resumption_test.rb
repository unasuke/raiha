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

  def test_application_data_persists_with_ticket
    _client, server = establish_connection

    # RFC 9001 §4.6.1: server attaches its QUIC transport parameters
    # blob (opaque to TLS) when issuing the ticket; client side stores
    # them too via the QUIC adapter, but we exercise the server-side
    # attachment path here to keep the test at the TLS layer.
    server.build_new_session_ticket(application_data: "remembered-tp".b)

    server_store = server.instance_variable_get(:@session_ticket_store)
    last_entry = server_store.instance_variable_get(:@tickets).values.last
    assert_equal "remembered-tp".b, last_entry[:application_data]
  end

  def test_replay_with_consumed_ticket_rejects_early_data
    server_ticket_store, client_hello_record = build_resumption_client_hello

    # First resumption: server accepts early data and marks the ticket
    # consumed. A fresh server reusing the same ticket store rejects the
    # replay (RFC 9001 §5.1).
    first_server = build_resumption_server(server_ticket_store)
    first_server.receive(client_hello_record)
    assert first_server.early_data_available, "first resumption should accept early data"

    second_server = build_resumption_server(server_ticket_store)
    second_server.receive(client_hello_record)

    refute second_server.early_data_available,
      "replayed ticket must not be accepted for early data"
  end

  def test_stale_ticket_age_rejects_early_data
    first_client, first_server = establish_connection
    ticket_record = first_server.build_new_session_ticket
    first_client.receive(ticket_record)

    server_ticket_store = first_server.instance_variable_get(:@session_ticket_store)
    client_ticket_store = first_client.instance_variable_get(:@session_ticket_store)

    # Push the client's stored received_at well into the past so the
    # claimed ticket_age the server reconstructs falls outside the 10s
    # acceptance window.
    client_entry = client_ticket_store.instance_variable_get(:@tickets).values.last
    client_entry[:received_at] = Time.now - 60

    second_client = Raiha::TLS::Client.new
    second_client.instance_variable_set(:@session_ticket_store, client_ticket_store)
    client_hello_record = second_client.datagrams_to_send.join

    second_server = build_resumption_server(server_ticket_store)
    second_server.receive(client_hello_record)

    refute second_server.early_data_available,
      "claimed ticket age outside the window must reject early data"
  end

  def test_psk_resumption_completes_handshake
    first_client, first_server = establish_connection
    first_client.receive(first_server.build_new_session_ticket)

    second_client, second_server = make_resumption_pair(first_client, first_server)
    drive_resumption_handshake(second_client, second_server)

    assert_equal Raiha::TLS::Client::State::CONNECTED, second_client.state
    assert_equal Raiha::TLS::Server::State::CONNECTED, second_server.state
    assert second_server.psk_mode?, "second server should be in PSK mode"
    refute second_client.peer_authenticated?,
      "PSK resumption skips Certificate; client should not have peer cert"
  end

  def test_double_resumption_completes_handshake
    first_client, first_server = establish_connection
    first_client.receive(first_server.build_new_session_ticket)

    second_client, second_server = make_resumption_pair(first_client, first_server)
    drive_resumption_handshake(second_client, second_server)
    assert_equal Raiha::TLS::Client::State::CONNECTED, second_client.state
    assert second_server.psk_mode?

    client_store = second_client.instance_variable_get(:@session_ticket_store)
    previous_psk = client_store.instance_variable_get(:@tickets).values.last[:psk]

    # Second ticket issued over the PSK-resumed connection
    second_client.receive(second_server.build_new_session_ticket)

    third_client, third_server = make_resumption_pair(second_client, second_server)
    drive_resumption_handshake(third_client, third_server)
    assert_equal Raiha::TLS::Client::State::CONNECTED, third_client.state
    assert third_server.psk_mode?, "third server should also resume via PSK"

    latest_psk = client_store.instance_variable_get(:@tickets).values.last[:psk]
    refute_equal previous_psk, latest_psk,
      "new ticket should carry a freshly-derived PSK"
  end

  def test_full_handshake_fallback_when_server_ticket_store_empty
    first_client, first_server = establish_connection
    first_client.receive(first_server.build_new_session_ticket)

    second_client = Raiha::TLS::Client.new
    second_client.instance_variable_set(
      :@session_ticket_store,
      first_client.instance_variable_get(:@session_ticket_store)
    )
    # Second server has no knowledge of the ticket -> falls back to full handshake
    second_server = Raiha::TLS::Server.new(config: create_server_config)

    drive_resumption_handshake(second_client, second_server)

    assert_equal Raiha::TLS::Client::State::CONNECTED, second_client.state
    assert_equal Raiha::TLS::Server::State::CONNECTED, second_server.state
    refute second_server.psk_mode?, "server with empty ticket store must not PSK-resume"
    assert second_client.peer_authenticated?,
      "full handshake fallback should run Certificate path"
  end

  def test_full_handshake_fallback_when_binder_mismatches
    first_client, first_server = establish_connection
    first_client.receive(first_server.build_new_session_ticket)

    server_store = first_server.instance_variable_get(:@session_ticket_store)
    # Corrupt the server-side PSK so verify_psk_binder must fail
    server_entry = server_store.instance_variable_get(:@tickets).values.last
    server_entry[:psk] = ("\xFF".b) * server_entry[:psk].bytesize

    second_client, second_server = make_resumption_pair(first_client, first_server)
    drive_resumption_handshake(second_client, second_server)

    assert_equal Raiha::TLS::Client::State::CONNECTED, second_client.state
    assert_equal Raiha::TLS::Server::State::CONNECTED, second_server.state
    refute second_server.psk_mode?, "binder mismatch must reject PSK"
    assert second_client.peer_authenticated?,
      "fallback after binder mismatch should still authenticate via Certificate"
  end

  def test_psk_resumption_with_0rtt_accepted
    first_client, first_server = establish_connection
    first_client.receive(first_server.build_new_session_ticket)

    second_client, second_server = make_resumption_pair(first_client, first_server)

    client_hello_record = second_client.datagrams_to_send.join
    early_record = second_client.send_early_data("ping-0rtt")
    refute_nil early_record, "client should produce a 0-RTT record"

    second_server.receive(client_hello_record + early_record)
    assert second_server.early_data_available, "server should accept 0-RTT"
    assert_equal "ping-0rtt".b, second_server.received_early_data

    server_flight = second_server.datagrams_to_send.join
    second_client.receive(server_flight)

    client_finished = second_client.datagrams_to_send.join
    second_server.receive(client_finished)

    assert_equal Raiha::TLS::Client::State::CONNECTED, second_client.state
    assert_equal Raiha::TLS::Server::State::CONNECTED, second_server.state
    assert_equal true, second_client.early_data_accepted?
  end

  private def build_resumption_client_hello
    first_client, first_server = establish_connection
    ticket_record = first_server.build_new_session_ticket
    first_client.receive(ticket_record)

    server_ticket_store = first_server.instance_variable_get(:@session_ticket_store)
    client_ticket_store = first_client.instance_variable_get(:@session_ticket_store)

    second_client = Raiha::TLS::Client.new
    second_client.instance_variable_set(:@session_ticket_store, client_ticket_store)

    [server_ticket_store, second_client.datagrams_to_send.join]
  end

  private def build_resumption_server(ticket_store)
    server = Raiha::TLS::Server.new(config: create_server_config)
    server.instance_variable_set(:@session_ticket_store, ticket_store)
    server
  end

  # Construct a fresh client/server pair that shares the existing ticket
  # store with the previous client/server (so a PSK handshake can run).
  private def make_resumption_pair(prev_client, prev_server)
    second_client = Raiha::TLS::Client.new
    second_client.session_ticket_store = prev_client.instance_variable_get(:@session_ticket_store)

    second_server = Raiha::TLS::Server.new(config: create_server_config)
    second_server.session_ticket_store = prev_server.instance_variable_get(:@session_ticket_store)

    [second_client, second_server]
  end

  # Standard handshake drive used by the non-0RTT resumption tests.
  private def drive_resumption_handshake(client, server)
    ch_records = client.datagrams_to_send.join
    server.receive(ch_records)
    server_flight = server.datagrams_to_send.join
    client.receive(server_flight)
    client_finished = client.datagrams_to_send.join
    server.receive(client_finished)
    {
      client: client,
      server: server,
      ch_records: ch_records,
      server_flight: server_flight,
      client_finished: client_finished,
    }
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
