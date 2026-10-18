require "raiha/next/support/quic_tls"

# A client and a server Connection of the next release of raiha, wired to
# each other with nothing in between (250 appendix, "sans-IO, two
# connections back to back").
module NextQUICPair
  include NextQUICTLS

  CLIENT = ["192.0.2.1", 50_000].freeze
  SERVER = ["192.0.2.2", 443].freeze

  # Keeps the lines TLS writes as a key log, to read the secrets back.
  class Keylog
    def initialize = @lines = []

    def write(line) = @lines << line

    def secret(label)
      _, _, hex = @lines.map(&:split).find { |fields| fields.first == label }
      hex && [hex].pack("H*")
    end
  end

  module_function

  def client_connection(config: QUIC::Config.new, tls_config: client_config, now: 0.0, time: NOW, random: Random.new(1), **options)
    keyring = TLS::Keyring.client(config: tls_config, random:)
    QUIC::Connection.client(config:, tls_config:, keyring:, server_name: "localhost", remote: SERVER, time:, now:, **options)
  end

  def server_connection(config: QUIC::Config.new, tls_config: server_config, now: 0.0, time: NOW, random: Random.new(2), **options)
    keyring = TLS::Keyring.server(config: tls_config, identities: [NextTLSPair.server_identity], random:)
    QUIC::Connection.server(config:, tls_config:, keyring:, time:, now:, **options)
  end

  # A 1-RTT packet of `payload` as the client would send it to the server
  # whose connection ID is `dcid`, sealed with the client's secret from
  # `keylog`.
  def client_one_rtt(keylog, dcid:, payload:, packet_number: 1000)
    secret = keylog.secret("CLIENT_TRAFFIC_SECRET_0") or raise "no 1-RTT secret in the key log"
    keys = QUIC::Crypto::Keys.derive(suite: TLS::CipherSuite::TLS_AES_128_GCM_SHA256, secret:, version: QUIC::Version::V1)
    QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid:, key_phase: 0), packet_number:, packet_number_length: 2,
      payload: payload.ljust(40, "\0".b), keys:)
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
