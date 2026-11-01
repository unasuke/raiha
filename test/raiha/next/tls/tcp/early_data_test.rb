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

  def zero_rtt_server(now: NOW, **options) = TCPPair.server(config: TLSPair.server_config(ticket_key: SEED, max_early_data_size: 1024, **options), now:)

  # A server that takes 0-RTT reads it by read_early_data alone, before
  # what comes as 1-RTT, and read_early_data says when it is over.
  def test_a_server_takes_0rtt
    client = TCPPair.client(session:, early_data: true)
    client.write_early_data("early")
    server = zero_rtt_server
    server.receive(TCPPair.take(client), now: NOW)
    assert_raises(TLS::UsageError) { server.read(100) }
    assert_equal "early", server.read_early_data(100)
    assert_equal "", server.read_early_data(100)
    refute server.handshake_complete?
    TCPPair.pump(client, server)
    assert server.handshake_complete?
    assert_nil server.read_early_data(100)
    assert_nil client.write_early_data("late")
    assert TCPPair.events(client).grep(TLS::Event::HandshakeComplete).first.early_data_accepted
    client.write("one-rtt")
    TCPPair.pump(client, server)
    assert_equal "one-rtt", server.read(100)
  end

  # No more than the server's max_early_data_size, whatever the client was
  # told.
  def test_0rtt_past_what_the_server_takes
    client = TCPPair.client(session: session.with(max_early_data_size: 4096), early_data: true)
    client.write_early_data("a" * 2000)
    server = zero_rtt_server
    server.receive(TCPPair.take(client), now: NOW)
    assert server.failed?
    assert_equal [:unexpected_message, :too_much_early_data],
      TCPPair.events(server).grep(TLS::Event::Failed).first.then { |f| [f.alert, f.reason] }
  end

  # A server not asked for 0-RTT, or that took none, has none to read.
  def test_no_0rtt_to_read
    pair = TCPPair.connect(client: TCPPair.client(session:), server: zero_rtt_server)
    assert pair.server.handshake_complete?
    assert_nil pair.server.read_early_data(100)
    assert_nil pair.client.read_early_data(100)
    assert TCPPair.events(pair.server).grep(TLS::Event::HandshakeComplete).first.resumed
  end

  # A server whose Config takes 0-RTT needs a record of what it took, on
  # the path that chooses the Config by the ClientHello too.
  def test_a_server_that_takes_0rtt_needs_an_anti_replay_record
    config = TLSPair.server_config(ticket_key: SEED, max_early_data_size: 1024)
    keyring = TLSPair.server_keyring(config:)
    assert_raises(TLS::UsageError) { TLS::TCP::Connection.server(config:, keyring:, now: NOW) }
    acceptor = TLS::TCP::Acceptor.new
    acceptor.receive(TCPPair.take(TCPPair.client), now: NOW)
    assert acceptor.accepted
    assert_raises(TLS::UsageError) { TLS::TCP::Connection.server(config:, keyring:, now: NOW, acceptor:) }
    plain = TLSPair.server_config
    assert TLS::TCP::Connection.server(config: plain, keyring: TLSPair.server_keyring(config: plain), now: NOW)
  end

  # Past 16 KiB, a server that skips 0-RTT closes the connection.
  def test_skipping_past_the_limit
    client = TCPPair.client(session: session.with(max_early_data_size: 32_768), early_data: true)
    client.write_early_data("a" * 17_000)
    server = server()
    server.receive(TCPPair.take(client), now: NOW)
    assert server.failed?
    assert_equal [:unexpected_message, :too_much_early_data],
      TCPPair.events(server).grep(TLS::Event::Failed).first.then { |f| [f.alert, f.reason] }
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
