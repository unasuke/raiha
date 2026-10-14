# frozen_string_literal: true

module Raiha::Next::QUIC
  # The keys that protect a connection's packets, one pair for each
  # encryption level (:initial, :zero_rtt, :handshake, :one_rtt): the
  # Initial keys derived from the client's first Destination Connection ID,
  # the others from the secrets TLS gives out, until a level is discarded
  # (RFC 9001 "Packet Protection"). The 1-RTT secrets are kept as well, for
  # key updates.
  class PacketProtection
    LEVELS = %i[initial zero_rtt handshake one_rtt].freeze

    attr_reader :version

    # `role` is this end's, :client or :server.
    def initialize(role:, version:)
      @role = role
      @version = version
      @keys = LEVELS.to_h { |level| [level, {}] } #: Hash[level, Hash[direction, Crypto::Keys]]
      @one_rtt_secrets = {} #: Hash[direction, [String, Raiha::Next::TLS::CipherSuite]]
      @discarded = [] #: Array[level]
    end

    # The Initial keys from the client's first Destination Connection ID,
    # again after a Retry with the new one.
    def install_initial(dcid)
      initial = Crypto::Initial.derive(dcid:, version: @version)
      own, peer = @role == :client ? [initial.client, initial.server] : [initial.server, initial.client]
      @keys.fetch(:initial).merge!(write: own, read: peer)
    end

    # The keys of `level` in `direction` (:read or :write) from a secret of
    # TLS.
    def install(level, direction, secret:, suite:)
      raise ArgumentError, "the Initial keys come from the connection ID" if level == :initial
      raise ArgumentError, "#{level} is discarded" if @discarded.include?(level)
      @keys.fetch(level)[direction] = Crypto::Keys.derive(suite:, secret:, version: @version)
      @one_rtt_secrets[direction] = [secret, suite] if level == :one_rtt
    end

    def read_keys(level) = @keys.fetch(level)[:read]

    def write_keys(level) = @keys.fetch(level)[:write]

    def can_read?(level) = @keys.fetch(level).key?(:read)

    def can_write?(level) = @keys.fetch(level).key?(:write)

    def discarded?(level) = @discarded.include?(level)

    # Forgets the keys of `level` for good (RFC 9001 "Discarding Unused
    # Keys").
    def discard(level)
      @keys.fetch(level).clear
      @discarded << level unless @discarded.include?(level)
    end
  end
end
