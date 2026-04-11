require "test_helper"
require_relative "../../../../../lib/raiha/tls/handshake"

class RaihaTLSHandshakeNewSessionTicketTest < Minitest::Test
  def test_roundtrip
    nst = Raiha::TLS::Handshake::NewSessionTicket.new
    nst.ticket_lifetime = 7200
    nst.ticket_age_add = 123456
    nst.ticket_nonce = "\x00\x01".b
    nst.ticket = "session_ticket_data"
    nst.extensions = []

    hs = Raiha::TLS::Handshake.new
    hs.handshake_type = Raiha::TLS::Handshake::HANDSHAKE_TYPE[:new_session_ticket]
    hs.message = nst

    serialized = hs.serialize
    deserialized = Raiha::TLS::Handshake.deserialize(serialized)

    assert_equal Raiha::TLS::Handshake::NewSessionTicket, deserialized.message.class
    assert_equal 7200, deserialized.message.ticket_lifetime
    assert_equal 123456, deserialized.message.ticket_age_add
    assert_equal "\x00\x01".b, deserialized.message.ticket_nonce
    assert_equal "session_ticket_data", deserialized.message.ticket
    assert_equal [], deserialized.message.extensions
  end

  def test_serialize_deserialize
    nst = Raiha::TLS::Handshake::NewSessionTicket.new
    nst.ticket_lifetime = 3600
    nst.ticket_age_add = 0xDEADBEEF
    nst.ticket_nonce = "\x42".b
    nst.ticket = "\x01\x02\x03\x04\x05".b
    nst.extensions = []

    serialized = nst.serialize
    deserialized = Raiha::TLS::Handshake::NewSessionTicket.deserialize(serialized)

    assert_equal 3600, deserialized.ticket_lifetime
    assert_equal 0xDEADBEEF, deserialized.ticket_age_add
    assert_equal "\x42".b, deserialized.ticket_nonce
    assert_equal "\x01\x02\x03\x04\x05".b, deserialized.ticket
  end
end
