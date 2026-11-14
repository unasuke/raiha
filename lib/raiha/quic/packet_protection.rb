# frozen_string_literal: true

module Raiha::QUIC
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
  # for the packets the network delayed, OLD_KEY_PTOS PTOs from the first
  # packet that opens with the new ones.
  #
  # This end updates the keys as quic-go does, so that the peer's handling
  # of an update is exercised early in a connection: after
  # FIRST_KEY_UPDATE_INTERVAL packets sent or opened with the first keys,
  # and KEY_UPDATE_INTERVAL with each later ones (quic-go's
  # `FirstKeyUpdateInterval` and `KeyUpdateInterval`).
  #
  # Packets that fail authentication are counted across all keys, and past
  # the integrity limit of the AEAD the connection closes; so does it when
  # the 1-RTT keys are about to reach the confidentiality limit and cannot
  # be updated (RFC 9001 "Limits on AEAD Usage").
  class PacketProtection
    LEVELS = %i[initial zero_rtt handshake one_rtt].freeze
    OLD_KEY_PTOS = 3
    FIRST_KEY_UPDATE_INTERVAL = 100
    KEY_UPDATE_INTERVAL = 100_000

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
      # The cipher suite TLS selected, the Initial keys' until it has.
      @suite = Crypto::Initial::SUITE
      # How many packets have failed authentication.
      @failures = 0
      # The secrets of the next key phase, the read keys of the next and the
      # previous phase, and when the latter go.
      @next_secrets = {} #: Hash[direction, String]
      @next_read = nil #: Crypto::Keys?
      @previous_read = nil #: Crypto::Keys?
      @previous_until = nil #: Float?
      @key_phase = 0
      @confirmed = false
      # The largest 1-RTT packet number the peer has acknowledged, opened,
      # and opened with keys older than the current.
      @largest_acked = nil #: Integer?
      @largest_opened = nil #: Integer?
      @largest_older = nil #: Integer?
      # Of the packets of the current key phase: the first number sent, the
      # lowest opened, how many were sent and opened, and the largest an
      # ACK frame sent with them acknowledged.
      @first_sent = nil #: Integer?
      @lowest_opened = nil #: Integer?
      @sent_count = 0
      @opened_count = 0
      @largest_ack_sent = nil #: Integer?
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
      @suite = suite
      return unless level == :one_rtt
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
    # Key Update"). `pto` is the PTO period at `now`.
    #
    # A Violation of KEY_UPDATE_ERROR when the peer updates again before
    # this end has acknowledged, with the current keys, a packet of the
    # peer's current keys (MAY), or when a packet opens with keys older than
    # those of a packet with a lower number (MUST, RFC 9001 "Sending with
    # Updated Keys"); of AEAD_LIMIT_REACHED when more packets have failed
    # authentication than the integrity limit.
    def open(level, unmasked, now:, pto:)
      keys = read_keys(level) or return nil
      return open_with(keys, unmasked) unless level == :one_rtt
      discard_previous_keys(now)
      number = unmasked.packet_number
      lowest = @lowest_opened
      if unmasked.header.key_phase == key_phase_bit # steep:ignore
        payload = open_with(keys, unmasked) or return nil
      elsif lowest ? number < lowest : @key_phase.positive?
        previous = @previous_read or return nil
        payload = open_with(previous, unmasked) or return nil
        @largest_older = number if @largest_older.nil? || number > @largest_older # steep:ignore
        @largest_opened = number if @largest_opened.nil? || number > @largest_opened # steep:ignore
        return payload
      else
        following = @next_read or return nil
        payload = open_with(following, unmasked) or return nil
        if @key_phase.positive? && !(lowest && (ack = @largest_ack_sent) && ack >= lowest)
          key_update_error("the peer updated its keys again before an ACK of its packets with the current ones")
        end
        update_keys
        lowest = nil
      end
      older = @largest_older
      key_update_error("packet #{number} opened with keys newer than packet #{older}") if older && number < older
      @previous_until = now + OLD_KEY_PTOS * pto if lowest.nil? && @previous_read
      @lowest_opened = number if lowest.nil? || number < lowest
      @largest_opened = number if @largest_opened.nil? || number > @largest_opened # steep:ignore
      @opened_count += 1
      payload
    end

    # A 1-RTT packet numbered `packet_number` went out with the current
    # keys, with an ACK frame of the packets up to `acknowledging` when not
    # nil.
    #
    # Keys that have protected as many packets as the confidentiality limit
    # are not used again.
    def sent(packet_number, acknowledging: nil)
      @first_sent ||= packet_number
      @sent_count += 1
      if acknowledging && (@largest_ack_sent.nil? || acknowledging > @largest_ack_sent) # steep:ignore
        @largest_ack_sent = acknowledging
      end
      limit = @suite.confidentiality_limit(:quic)
      @keys.fetch(:one_rtt).delete(:write) if limit && @sent_count >= limit
    end

    # The peer acknowledged the 1-RTT packets up to `largest`. An ACK of a
    # packet sent with the current keys before any packet of the peer opened
    # with them came with older keys: the peer did not follow the update, a
    # Violation of KEY_UPDATE_ERROR (MAY, RFC 9001 "Responding to a Key
    # Update", as quic-go checks it).
    def acknowledged(largest)
      if (first = @first_sent) && largest >= first && @opened_count.zero?
        key_update_error("an ACK of packet #{largest}, sent with the current keys, came with older keys")
      end
      @largest_acked = largest if @largest_acked.nil? || largest > @largest_acked # steep:ignore
    end

    def handshake_confirmed! = @confirmed = true

    # Moves to the keys of the next key phase when an update is due: as
    # many packets gone with the current keys as the interval, or all but
    # one the confidentiality limit allows. An update needs the handshake
    # confirmed and a packet sent with the current keys acknowledged (RFC
    # 9001 "Initiating a Key Update"); without them at the limit, a
    # Violation of AEAD_LIMIT_REACHED, whose CONNECTION_CLOSE is the last
    # packet the keys protect.
    def update_keys_if_due
      limit = @suite.confidentiality_limit(:quic)
      exhausted = limit && @sent_count >= limit - 1
      return unless exhausted || [@sent_count, @opened_count].max >= (@key_phase.zero? ? FIRST_KEY_UPDATE_INTERVAL : KEY_UPDATE_INTERVAL)
      return update_keys if update_allowed?
      return unless exhausted
      raise Violation.new("#{@sent_count} packets sent with the 1-RTT keys, which cannot be updated, near the limit of #{limit}",
        code: ErrorCode::AEAD_LIMIT_REACHED)
    end

    # When the previous 1-RTT read keys go, nil when none are to go.
    def next_timeout = @previous_until

    def handle_timeout(now:) = discard_previous_keys(now)

    # Forgets the keys of `level` for good (RFC 9001 "Discarding Unused
    # Keys").
    def discard(level)
      @keys.fetch(level).clear
      @discarded << level unless @discarded.include?(level)
    end

    # The 1-RTT keys of the next key phase in place of the current, which
    # stay to read the previous phase's packets.
    private def update_keys
      suite = @suite
      following = @next_read or raise Error::StateError, "no 1-RTT read keys of the next phase"
      keys = @keys.fetch(:one_rtt)
      @previous_read = keys.fetch(:read)
      @previous_until = nil
      keys[:read] = following
      keys[:write] = keys.fetch(:write).update(suite:, secret: @next_secrets.fetch(:write), version: @version)
      @next_secrets.transform_values! { |secret| Crypto::Keys.next_secret(suite:, secret:, version: @version) }
      @next_read = keys.fetch(:read).update(suite:, secret: @next_secrets.fetch(:read), version: @version)
      @key_phase += 1
      @largest_older = @largest_opened
      @first_sent = nil
      @lowest_opened = nil
      @sent_count = 0
      @opened_count = 0
      @largest_ack_sent = nil
      @updated&.call(@key_phase)
    end

    private def update_allowed?
      return false unless @confirmed && @next_read
      first = @first_sent or return false
      acked = @largest_acked or return false
      acked >= first
    end

    private def key_update_error(message) = raise Violation.new(message, code: ErrorCode::KEY_UPDATE_ERROR)

    private def open_with(keys, unmasked) = unmasked.open(keys.aead) || authentication_failed

    # RFC 9001 "Limits on AEAD Usage": once more packets have failed
    # authentication, across all keys, than the integrity limit of the AEAD
    # TLS selected, the connection closes with AEAD_LIMIT_REACHED and
    # processes no more.
    private def authentication_failed
      @failures += 1
      limit = @suite.integrity_limit(:quic)
      return nil unless limit && @failures > limit
      raise Violation.new("#{@failures} packets failed authentication, over the limit of #{limit}", code: ErrorCode::AEAD_LIMIT_REACHED)
    end

    # RFC 9001 "Receiving with Different Keys": an endpoint keeps the old
    # read keys no more than three PTOs after a packet opens with the new.
    private def discard_previous_keys(now)
      deadline = @previous_until or return
      return if now < deadline
      @previous_read = nil
      @previous_until = nil
    end
  end
end
