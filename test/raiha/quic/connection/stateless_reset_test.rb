require "test_helper"
require "support/quic_pair"

# RFC 9000 "Detecting a Stateless Reset", with the token of the server's
# transport parameters.
class RaihaQUICConnectionStatelessResetTest < Minitest::Test
  include QUICPair

  TOKEN = "t".b * 16

  # A client done with the handshake with a server whose transport
  # parameters carry TOKEN, and the time.
  def connected
    client = client_connection
    server = server_connection(source_connection_id: "s".b * 8, stateless_reset_token: TOKEN)
    now = handshake(client, server)
    client.each_event { nil }
    [client, now]
  end

  def reset(token) = QUIC::StatelessReset.packet(token:, length: 42, random: Random.new(5))

  # The client drains on a datagram that ends in the token, sending
  # nothing more.
  def test_the_client_drains_on_a_reset
    client, now = connected
    client.receive(reset(TOKEN), from: SERVER, now:)
    assert client.draining?
    assert_equal "stateless reset", client.close_reason.reason
    closed = [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::Closed)
    assert_equal [true], closed.map(&:by_peer)
    assert_empty client.transmits(now: now + 0.1)
  end

  def test_another_token_is_no_reset
    client, now = connected
    client.receive(reset("x".b * 16), from: SERVER, now:)
    refute client.draining?
  end

  # An Endpoint asks the connections of the address a datagram came from
  # whether it is a reset of theirs.
  def test_a_reset_of_no_packet_of_the_connection
    client, now = connected
    refute client.take_stateless_reset(reset("x".b * 16), from: SERVER, now:)
    assert client.take_stateless_reset(reset(TOKEN), from: SERVER, now:)
    assert client.draining?
    refute client.take_stateless_reset(reset(TOKEN), from: SERVER, now:)
  end
end
