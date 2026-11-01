require "raiha/next/test_helper"
require "raiha/next/support/tcp_pair"

# 0-RTT over TCP: a client sends it through write_early_data only when
# asked, under the 0-RTT key from the start, until the server answers; a
# server that does not take it skips it and the handshake goes on.
class RaihaNextTLSTCPEarlyDataTest < Minitest::Test
  TLS = Raiha::Next::TLS
  TCPPair = NextTCPPair
  TLSPair = NextTLSPair
  NOW = TCPPair::NOW
  SEED = "\x13".b * 32

  # A session whose ticket allows 1024 bytes of 0-RTT.
  def session
    @session ||= begin
      pair = TLSPair.run(TLSPair.client, { config: TLSPair.server_config(ticket_key: SEED, max_early_data_size: 1024) })
      TLSPair.deliver(pair.server_outputs.select { |output| output.is_a?(TLS::Output::Message) && output.epoch == :application }, pair.client)
      pair.client.each_event.grep(TLS::Event::NewSessionTicket).first.session
    end
  end

  def server(**options) = TCPPair.server(config: TLSPair.server_config(ticket_key: SEED, **options))

  # The client's first records: its ClientHello, the change_cipher_spec of
  # middlebox compatibility, then 0-RTT, which only the 0-RTT key opens.
  def test_a_client_sends_0rtt_first
    client = TCPPair.client(session:, early_data: true)
    assert_equal 5, client.write_early_data("hello")
    assert_equal [22, 20, 23], TCPPair.records(TCPPair.take(client)).map(&:first)
  end

  # Only as much as the session allows.
  def test_0rtt_up_to_what_the_session_allows
    client = TCPPair.client(session:, early_data: true)
    assert_equal 1000, client.write_early_data("a" * 1000)
    assert_equal 24, client.write_early_data("b" * 100)
    assert_equal 0, client.write_early_data("c")
  end

  # Not asked for, or nothing to send it with.
  def test_no_0rtt_unless_asked
    assert_nil TCPPair.client(session:).write_early_data("hello")
    assert_nil TCPPair.client(early_data: true).write_early_data("hello")
  end

  # A server that resumes but takes no 0-RTT skips it; the client learns
  # it was not taken and sends no more, and what it writes then goes as
  # 1-RTT.
  def test_0rtt_a_server_does_not_take
    [server, server(groups: %i[secp256r1])].each do |server|
      client = TCPPair.client(session:, early_data: true)
      client.write_early_data("hello")
      pair = TCPPair.connect(client:, server:)
      assert pair.client.handshake_complete? && pair.server.handshake_complete?
      reasons = TCPPair.events(pair.client).grep(TLS::Event::EarlyDataRejected).map(&:reason)
      assert_equal 1, reasons.size
      assert_includes %i[rejected_by_server hello_retry_request], reasons.first
      assert_nil pair.client.write_early_data("more")
      assert_equal "", pair.server.read(100)
      pair.client.write("after")
      TCPPair.pump(pair.client, pair.server)
      assert_equal "after", pair.server.read(100)
    end
  end
end
