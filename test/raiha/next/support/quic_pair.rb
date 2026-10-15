require "raiha/next/support/quic_tls"

# A client and a server Connection of the next release of raiha, wired to
# each other with nothing in between (250 appendix, "sans-IO, two
# connections back to back").
module NextQUICPair
  include NextQUICTLS

  CLIENT = ["192.0.2.1", 50_000].freeze
  SERVER = ["192.0.2.2", 443].freeze

  module_function

  def client_connection(config: QUIC::Config.new, tls_config: client_config, now: 0.0, time: NOW, random: Random.new(1), **options)
    keyring = TLS::Keyring.client(config: tls_config, random:)
    QUIC::Connection.client(config:, tls_config:, keyring:, server_name: "localhost", remote: SERVER, time:, now:, **options)
  end

  def server_connection(config: QUIC::Config.new, tls_config: server_config, now: 0.0, time: NOW, random: Random.new(2), **options)
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity], random:)
    QUIC::Connection.server(config:, tls_config:, keyring:, time:, now:, **options)
  end

  # Passes datagrams each way, a millisecond apart, until both have
  # completed the handshake or `rounds` have gone; gives the time then.
  def handshake(client, server, now: 0.0, rounds: 20)
    rounds.times do
      break if client.handshake_complete? && server.handshake_complete?
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      now += 0.001
    end
    now
  end
end
