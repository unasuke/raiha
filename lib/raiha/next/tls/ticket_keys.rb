# frozen_string_literal: true

require_relative "key_schedule"
require_relative "masked_inspect"

module Raiha::Next::TLS
  # The keys a server seals its session tickets with. Each comes from a
  # 32-byte seed through HKDF-Expand-Label with a prefix of this
  # implementation's own in place of "tls13 ", so that no label of TLS can
  # give the same key: an AES-256-GCM key, a key for making nonces, and an
  # 8-byte ID that names the key in a ticket. The ID is derived rather than
  # random, so every worker given the same seed names it the same way.
  #
  # TicketKeys.static seals with `current` and opens with it and each of
  # `previous`; the application turns the keys over by building a new
  # Config with new ones.
  class TicketKeys
    # The keys of one seed. `epoch` is nil for keys that are not of a
    # ratchet.
    class Entry < Data.define(:key_id, :aead_key, :nonce_key, :epoch)
      include MaskedInspect

      def masked_members = %i[aead_key nonce_key]
    end

    PREFIX = "raiha "
    SEED_LENGTH = 32
    KEY_LENGTH = 32
    KEY_ID_LENGTH = 8
    HASH = :sha256

    def self.static(current:, previous: [])
      raise ArgumentError, "previous must be an Array of ticket keys" unless previous.is_a?(Array)
      new([current, *previous].map { |seed| derive(seed, nil) })
    end

    # The Entry of `seed`.
    def self.derive(seed, epoch)
      raise ArgumentError, "a ticket key is #{SEED_LENGTH} bytes" unless seed.is_a?(String) && seed.bytesize == SEED_LENGTH
      Entry.new(key_id: expand(seed, "ticket id", KEY_ID_LENGTH), aead_key: expand(seed, "ticket key", KEY_LENGTH),
        nonce_key: expand(seed, "ticket nonce", KEY_LENGTH), epoch:)
    end

    def self.expand(seed, label, length)
      KeySchedule.expand_label(secret: seed.b, label:, length:, hash: HASH, prefix: PREFIX)
    end
    private_class_method :expand

    # `entries`, the first of which seals.
    def initialize(entries)
      ids = entries.map(&:key_id)
      raise ArgumentError, "two ticket keys have the same key ID" unless ids.uniq.size == ids.size
      @entries = entries.dup.freeze
      @by_id = entries.to_h { |entry| [entry.key_id, entry] }.freeze
      Ractor.make_shareable(self)
    end

    # The Entry to seal a ticket with at `now`, nil when there is none.
    def sealing(now) = @entries.first

    # The Entry named `key_id` that may open a ticket at `now`, nil when none
    # may.
    def opening(key_id, now) = @by_id[key_id]

    def inspect = "#<#{self.class.name} key_ids=#{@entries.map { |entry| entry.key_id.unpack1("H*") }.inspect}>"
  end
end
