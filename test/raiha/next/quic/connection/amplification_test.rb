require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# RFC 9000 "Address Validation" and RFC 9002 "Handling Anti-Amplification
# Limits": a server sends at most three times what it received until the
# client's address is validated.
class RaihaNextQUICConnectionAmplificationTest < Minitest::Test
  include NextQUICPair

  # Runs the server's timers out for ten seconds, short of the idle
  # timeout, and gives what it sent.
  def sent_over_ptos(server)
    sent = 0
    now = 0.0
    loop do
      sent += server.transmits(now:).sum { _1.payload.bytesize }
      timeout = server.next_timeout
      break if timeout.nil? || timeout > 10.0
      now = timeout
      server.handle_timeout(now:)
    end
    [sent, now]
  end

  # A server whose certificate chain makes its flight longer than three
  # datagrams.
  def long_flight_server
    identity = NextTLSPair.server_identity
    long = TLS::Keyring::Identity.new(cert_der: identity.cert_der + [NextTLSPair.ca.der] * 8, key_der: identity.key_der)
    tls_config = server_config
    keyring = TLS::Keyring.server(config: tls_config, identities: [long], random: Random.new(2))
    QUIC::Connection.server(config: QUIC::Config.new, tls_config:, keyring:, time: NOW, now: 0.0)
  end

  # A client that says nothing after its first Initial gets no more than
  # three times that, however many PTOs run out.
  def test_three_times_what_was_received
    client = client_connection
    server = long_flight_server
    first = client.transmits(now: 0.0).first.payload
    server.receive(first, from: CLIENT, now: 0.0)
    sent, = sent_over_ptos(server)
    assert_operator sent, :>, 0
    assert_operator sent, :<=, 3 * first.bytesize
  end

  # Stopped, the server sets no PTO; another datagram from the client
  # sets it again.
  def test_more_from_the_client_lets_it_go_on
    client = client_connection
    server = long_flight_server
    first = client.transmits(now: 0.0).first.payload
    server.receive(first, from: CLIENT, now: 0.0)
    server.transmits(now: 0.0)
    assert_operator server.next_timeout, :>, 10.0
    server.receive(first, from: CLIENT, now: 0.5)
    assert_operator server.next_timeout, :<, 10.0
  end

  # A Handshake packet validates the address: the handshake goes on
  # whatever was sent before.
  def test_a_handshake_packet_validates
    client = client_connection
    server = server_connection
    handshake(client, server)
    assert server.handshake_confirmed?
    server.close(now: 1.0)
    assert_equal 1, server.transmits(now: 1.0).size
  end
end
