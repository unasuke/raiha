require "test_helper"
require "support/quic_pair"
require "raiha/http3"
require "raiha/http3/session"

# An HTTP/3 session: the QUIC session and the server's SETTINGS, as plain
# values and back.
class RaihaNextHTTP3SessionTest < Minitest::Test
  include NextQUICPair

  HTTP3 = Raiha::HTTP3

  def quic_session
    client = client_connection
    server = server_connection(tls_config: server_config(ticket_key: "\x1b".b * 32))
    now = handshake(client, server)
    3.times do
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      now += 0.001
    end
    [].tap { |all| client.each_event { all << _1 } }.grep(QUIC::Event::SessionTicket).first.session
  end

  def test_a_session_as_plain_values
    session = HTTP3::Session.new(quic: quic_session, settings: HTTP3::Settings.new(qpack_max_table_capacity: 4096, h3_datagram: true))
    assert_equal session, HTTP3::Session.from_h(session.to_h)
    assert_raises(ArgumentError) { HTTP3::Session.from_h(session.to_h.merge(settings: { h3_datagram: true })) }
    assert_raises(ArgumentError) { HTTP3::Session.from_h(session.to_h.except(:quic)) }
  end
end
