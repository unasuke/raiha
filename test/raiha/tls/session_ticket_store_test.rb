require "test_helper"
require_relative "../../../lib/raiha/tls/handshake"
require_relative "../../../lib/raiha/tls/session_ticket_store"

class RaihaTLSSessionTicketStoreTest < Minitest::Test
  def test_store_and_get
    store = Raiha::TLS::SessionTicketStore.new
    ticket_msg = Raiha::TLS::Handshake::NewSessionTicket.new
    ticket_msg.ticket_lifetime = 7200
    ticket_msg.ticket_age_add = 12345
    ticket_msg.ticket_nonce = "\x00".b
    ticket_msg.ticket = "ticket_data"
    ticket_msg.extensions = []

    store.store("example.com", ticket_msg, "psk_value")

    entry = store.get("example.com")
    refute_nil entry
    assert_equal "ticket_data", entry[:ticket]
    assert_equal "psk_value", entry[:psk]
    assert_equal 12345, entry[:age_add]
  end

  def test_get_nonexistent
    store = Raiha::TLS::SessionTicketStore.new
    assert_nil store.get("unknown.com")
  end

  def test_expired_ticket
    store = Raiha::TLS::SessionTicketStore.new
    ticket_msg = Raiha::TLS::Handshake::NewSessionTicket.new
    ticket_msg.ticket_lifetime = 0 # expires immediately
    ticket_msg.ticket_age_add = 0
    ticket_msg.ticket_nonce = "".b
    ticket_msg.ticket = "expired"
    ticket_msg.extensions = []

    store.store("example.com", ticket_msg, "psk")
    sleep 0.01
    assert_nil store.get("example.com")
  end

  def test_delete
    store = Raiha::TLS::SessionTicketStore.new
    ticket_msg = Raiha::TLS::Handshake::NewSessionTicket.new
    ticket_msg.ticket_lifetime = 7200
    ticket_msg.ticket_age_add = 0
    ticket_msg.ticket_nonce = "".b
    ticket_msg.ticket = "ticket"
    ticket_msg.extensions = []

    store.store("example.com", ticket_msg, "psk")
    store.delete("example.com")
    assert_nil store.get("example.com")
  end
end
