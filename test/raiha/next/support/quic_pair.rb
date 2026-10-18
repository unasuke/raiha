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

  # The 1-RTT keys of the secret `label` names in `keylog`, after `phase`
  # key updates.
  def one_rtt_keys(keylog, label, phase: 0)
    secret = keylog.secret(label) or raise "no #{label} in the key log"
    suite = TLS::CipherSuite::TLS_AES_128_GCM_SHA256
    keys = QUIC::Crypto::Keys.derive(suite:, secret:, version: QUIC::Version::V1)
    phase.times do
      secret = QUIC::Crypto::Keys.next_secret(suite:, secret:, version: QUIC::Version::V1)
      keys = keys.update(suite:, secret:, version: QUIC::Version::V1)
    end
    keys
  end

  # A 1-RTT packet of `payload` as the client would send it to the server
  # whose connection ID is `dcid`, sealed with the client's keys of `phase`
  # from `keylog`.
  def client_one_rtt(keylog, dcid:, payload:, packet_number: 1000, phase: 0)
    keys = one_rtt_keys(keylog, "CLIENT_TRAFFIC_SECRET_0", phase:)
    QUIC::Wire::Packet.seal(QUIC::Wire::ShortHeader.new(dcid:, key_phase: phase & 1), packet_number:, packet_number_length: 2,
      payload: payload.ljust(40, "\0".b), keys:)
  end

  # The Key Phase bit, packet number and frames of the server's 1-RTT
  # packet in `datagram`, opened with its keys of `phase` from `keylog`;
  # nil when it does not open with them.
  def server_one_rtt(keylog, datagram, phase:)
    keys = one_rtt_keys(keylog, "SERVER_TRAFFIC_SECRET_0", phase:)
    unmasked = QUIC::Wire::Packet.parse(datagram, dcid_length: 8).unmask(keys.header_protection, largest: nil)
    payload = unmasked.open(keys.aead) or return nil
    [unmasked.header.key_phase, unmasked.packet_number, QUIC::Wire::Frame.parse(payload, packet_type: :one_rtt, ack_delay_exponent: 3)]
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
