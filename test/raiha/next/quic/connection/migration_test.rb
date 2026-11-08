require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Connection Migration": what a connection takes from an address
# its path does not go to.
class RaihaNextQUICConnectionMigrationTest < Minitest::Test
  include NextQUICPair

  ELSEWHERE = ["198.51.100.7", 61_000].freeze

  # Before the handshake is confirmed, a server drops what comes from an
  # address other than the client's first, and the handshake goes no
  # further until it comes from there again.
  def test_a_server_drops_a_new_address_before_confirmation
    client = client_connection
    server = server_connection
    client.transmits(now: 0.0).each { server.receive(_1.payload, from: CLIENT, now: 0.0) }
    server.transmits(now: 0.0).each { client.receive(_1.payload, from: SERVER, now: 0.0) }
    flight = client.transmits(now: 0.001)
    flight.each { server.receive(_1.payload, from: ELSEWHERE, now: 0.001) }
    refute server.handshake_complete?
    flight.each { server.receive(_1.payload, from: CLIENT, now: 0.001) }
    assert server.handshake_complete?
  end

  # A client takes nothing from a server address it did not migrate to.
  def test_a_client_drops_another_server_address
    client = client_connection
    server = server_connection
    now = handshake(client, server)
    client.each_event { nil }
    stream_id = server.open_stream(direction: :uni)
    server.stream_write(stream_id, "hello", fin: true)
    datagrams = server.transmits(now:)
    datagrams.each { client.receive(_1.payload, from: ELSEWHERE, now:) }
    assert_empty [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::StreamReadable)
    datagrams.each { client.receive(_1.payload, from: SERVER, now:) }
    refute_empty [].tap { |events| client.each_event { events << _1 } }.grep(QUIC::Event::StreamReadable)
  end
end
