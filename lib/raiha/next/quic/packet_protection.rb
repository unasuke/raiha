# frozen_string_literal: true

module Raiha::Next::QUIC
  # The keys that protect a connection's packets, one pair for each
  # encryption level (:initial, :zero_rtt, :handshake, :one_rtt): the
  # Initial keys derived from the client's first Destination Connection ID,
  # the others from the secrets TLS gives out, until a level is discarded
  # (RFC 9001 "Packet Protection").
  #
  # The 1-RTT keys change with key updates (RFC 9001 "Key Update"). The
  # read keys of the next key phase are made as soon as those of the
  # current are, so that how long a packet takes to open does not tell
  # whether its Key Phase bit changed; those of the previous phase stay
  # for the packets the network delayed.
  class PacketProtection
    LEVELS = %i[initial zero_rtt handshake one_rtt].freeze

    attr_reader :version
    # How many times the 1-RTT keys have changed.
    attr_reader :key_phase

    # `role` is this end's, :client or :server. The block is called with
    # the key phase each time the 1-RTT keys change.
    def initialize(role:, version:, &updated)
      @role = role
      @version = version
      @keys = LEVELS.to_h { |level| [level, {}] } #: Hash[level, Hash[direction, Crypto::Keys]]
      @discarded = [] #: Array[level]
      @updated = updated
      # The 1-RTT cipher suite, the secrets of the next key phase, and the
      # read keys of the next and the previous phase.
      @one_rtt_suite = nil #: Raiha::Next::TLS::CipherSuite?
      @next_secrets = {} #: Hash[direction, String]
      @next_read = nil #: Crypto::Keys?
      @previous_read = nil #: Crypto::Keys?
      @key_phase = 0
      # The lowest packet number opened with the current 1-RTT keys.
      @lowest_opened = nil #: Integer?
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
      keys = @keys.fetch(level)[direction] = Crypto::Keys.derive(suite:, secret:, version: @version)
      return unless level == :one_rtt
      @one_rtt_suite = suite
      following = @next_secrets[direction] = Crypto::Keys.next_secret(suite:, secret:, version: @version)
      @next_read = keys.update(suite:, secret: following, version: @version) if direction == :read
    end

    def read_keys(level) = @keys.fetch(level)[:read]

    def write_keys(level) = @keys.fetch(level)[:write]

    def can_read?(level) = @keys.fetch(level).key?(:read)

    def can_write?(level) = @keys.fetch(level).key?(:write)

    def discarded?(level) = @discarded.include?(level)

    # The Key Phase bit of the 1-RTT packets the current keys protect.
    def key_phase_bit = @key_phase & 1

    # The payload of a packet of `level` with header protection off, or nil
    # when it does not open. A 1-RTT packet opens with the keys its Key
    # Phase bit and packet number tell (RFC 9001 "Receiving with Different
    # Keys"): the current ones when the bit is theirs; else the previous
    # ones below the lowest packet number opened with the current, and the
    # next ones above it. A packet that opens with the next keys is the
    # peer's key update, which this end follows (RFC 9001 "Responding to a
    # Key Update").
    def open(level, unmasked)
      keys = read_keys(level) or return nil
      return unmasked.open(keys.aead) unless level == :one_rtt
      number = unmasked.packet_number
      lowest = @lowest_opened
      if unmasked.header.key_phase == key_phase_bit # steep:ignore
        payload = unmasked.open(keys.aead) or return nil
        @lowest_opened = number if lowest.nil? || number < lowest
      elsif lowest ? number < lowest : @key_phase.positive?
        previous = @previous_read or return nil
        payload = unmasked.open(previous.aead)
      else
        following = @next_read or return nil
        payload = unmasked.open(following.aead) or return nil
        update_keys
        @lowest_opened = number
      end
      payload
    end

    # Forgets the keys of `level` for good (RFC 9001 "Discarding Unused
    # Keys").
    def discard(level)
      @keys.fetch(level).clear
      @discarded << level unless @discarded.include?(level)
    end

    # The 1-RTT keys of the next key phase in place of the current, which
    # stay to read the previous phase's packets.
    private def update_keys
      suite = @one_rtt_suite or raise Error::StateError, "no 1-RTT keys to update"
      following = @next_read or raise Error::StateError, "no 1-RTT read keys of the next phase"
      keys = @keys.fetch(:one_rtt)
      @previous_read = keys.fetch(:read)
      keys[:read] = following
      keys[:write] = keys.fetch(:write).update(suite:, secret: @next_secrets.fetch(:write), version: @version)
      @next_secrets.transform_values! { |secret| Crypto::Keys.next_secret(suite:, secret:, version: @version) }
      @next_read = keys.fetch(:read).update(suite:, secret: @next_secrets.fetch(:read), version: @version)
      @key_phase += 1
      @lowest_opened = nil
      @updated&.call(@key_phase)
    end
  end
end
