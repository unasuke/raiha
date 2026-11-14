require "test_helper"
require "raiha/tls/test"

class RaihaTLSHandshakeNewSessionTicketTest < Minitest::Test
  TLS = Raiha::TLS
  RFC8448 = TLS::Test::RFC8448::Simple1RTT
  REGISTRY = TLS::Extension::Registry::BUILTIN

  def parse(bytes) = TLS::Handshake.parse(bytes, registry: REGISTRY)

  def test_parse_and_encode_rfc8448
    nst = parse(RFC8448::NEW_SESSION_TICKET)
    assert_instance_of TLS::Handshake::NewSessionTicket, nst
    assert_equal 4, nst.msg_type
    assert_equal 30, nst.ticket_lifetime
    assert_equal 0xfad6aac5, nst.ticket_age_add
    assert_equal "\x00\x00".b, nst.ticket_nonce
    assert_equal 178, nst.ticket.bytesize
    assert_equal TLS::Extension::EarlyData::NST.new(max_early_data_size: 1024), nst.extension(42)
    assert_equal_bin RFC8448::NEW_SESSION_TICKET, nst.encode
    assert Ractor.shareable?(nst)
  end

  def test_inspect_masks_the_ticket
    nst = parse(RFC8448::NEW_SESSION_TICKET)
    assert_includes nst.inspect, "ticket=[178 bytes]"
    refute_includes nst.inspect, nst.ticket.inspect[1..8]
  end

  def test_empty_ticket
    nst = parse(RFC8448::NEW_SESSION_TICKET).with(ticket: "".b)
    assert_raises(TLS::Codec::EncodeError) { nst.encode }
  end
end
