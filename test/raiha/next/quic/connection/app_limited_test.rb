require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# Why a connection stopped sending tells its path whether the congestion
# window went unused, which keeps the congestion controller from growing it
# (RFC 9002 "Underutilizing the Congestion Window").
class RaihaNextQUICConnectionAppLimitedTest < Minitest::Test
  include NextQUICPair

  # A server whose certificate chain takes `copies` more certificates.
  def long_flight_server(copies, **options)
    identity = NextTLSPair.server_identity
    long = TLS::Keyring::Identity.new(cert_der: identity.cert_der + [NextTLSPair.ca.der] * copies, key_der: identity.key_der)
    tls_config = server_config
    keyring = TLS::Keyring.server(config: tls_config, identities: [long], random: Random.new(2))
    QUIC::Connection.server(config: QUIC::Config.new, tls_config:, keyring:, time: NOW, now: 0.0, **options)
  end

  # Nothing left to send with the window mostly free.
  def test_drained
    client = client_connection
    client.transmits(now: 0.0)
    assert client.path.app_limited?
    assert_operator client.path.bytes_in_flight, :<, client.path.congestion.window
  end

  # The server's limit before the client's address is validated, not the
  # window, stops it.
  def test_amplification
    server = long_flight_server(8)
    server.receive(client_connection.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0)
    server.transmits(now: 0.0)
    assert server.path.app_limited?
  end

  # A flight longer than the window fills it.
  def test_congestion
    server = long_flight_server(40, address_validated: true)
    server.receive(client_connection.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0)
    server.transmits(now: 0.0)
    refute server.path.app_limited?
    assert_operator server.path.bytes_in_flight + server.path.max_datagram_size, :>, server.path.congestion.window
  end
end
