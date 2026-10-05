require "raiha/next/test_helper"
require "raiha/next/support/tcp_pair"
require "stringio"

# How a TCP::Connection ends: RFC 9846 "Closure Alerts" and "Error Alerts".
class RaihaNextTLSTCPClosureTest < Minitest::Test
  TLS = Raiha::Next::TLS
  Pair = NextTCPPair
  NOW = Pair::NOW
  SUITE = TLS::CipherSuite::TLS_AES_128_GCM_SHA256

  # A connected pair, and a Protection that writes the server's records to
  # the client as its next ones would be: its first application key, used
  # by nothing yet.
  def connected_with_server_writer
    keylog = StringIO.new
    pair = Pair.connect(client: Pair.client(keylog:))
    secret = [keylog.string.lines.grep(/\ASERVER_TRAFFIC_SECRET_0/).first.split.last].pack("H*")
    [pair, TLS::Record::Protection.new(secret:, cipher_suite: SUITE)]
  end

  CLOSE_NOTIFY = "\x01\x00\x15".b

  # After the handshake: the read side closes once what came is read; the
  # write side stays open and nothing goes back; what follows is ignored.
  def test_close_notify_after_the_handshake
    pair, server = connected_with_server_writer
    pair.client.receive(server.seal("bye\x17".b) + server.seal(CLOSE_NOTIFY) + server.seal("late\x17".b), now: NOW)
    refute pair.client.failed?
    assert_empty Pair.take(pair.client)
    assert_equal "bye", pair.client.read(10)
    assert_nil pair.client.read(10)
    pair.client.receive(server.seal("later\x17".b), now: NOW)
    assert_nil pair.client.read(10)
    assert_equal 5, pair.client.write("still")
    assert_equal 1, Pair.records(Pair.take(pair.client)).size
    assert_empty Pair.events(pair.client).grep(TLS::TCP::Event::PeerAlert)
  end

  # RFC 9846 "Closure Alerts": read on after user_canceled.
  def test_user_canceled
    pair, server = connected_with_server_writer
    pair.client.receive(server.seal("\x01\x5a\x15".b) + server.seal("more\x17".b), now: NOW)
    refute pair.client.failed?
    assert_equal [TLS::TCP::Event::PeerAlert.new(level: 1, description: 90)], Pair.events(pair.client).grep(TLS::TCP::Event::PeerAlert)
    assert_equal "more", pair.client.read(10)
  end

  # Any other alert ends the connection, whatever its level.
  def test_other_alerts_are_fatal
    pair, server = connected_with_server_writer
    pair.client.receive(server.seal("\x01\x2a\x15".b) + server.seal("more\x17".b), now: NOW)
    assert pair.client.failed?
    assert_equal [TLS::TCP::Event::PeerAlert.new(level: 1, description: 42)], Pair.events(pair.client).grep(TLS::TCP::Event::PeerAlert)
    assert_empty Pair.take(pair.client)
  end

  # During the handshake the peer is not yet authenticated: a failure, and
  # no alert back.
  def test_close_notify_during_the_handshake
    client = Pair.client
    Pair.take(client)
    client.receive("\x15\x03\x03\x00\x02\x01\x00".b, now: NOW)
    assert client.failed?
    assert_empty Pair.take(client)
    assert_equal [TLS::Event::Failed.new(alert: nil, reason: :peer_closed_during_handshake)], Pair.events(client)
  end
end
