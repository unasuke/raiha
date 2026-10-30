# frozen_string_literal: true

require_relative "key_schedule"
require_relative "masked_inspect"
require_relative "error"

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
  # Config with new ones. TicketKeys.ratchet gives each epoch of the wall
  # clock keys of its own, every worker computing the same ones without
  # talking to the others (Ratchet).
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

    def self.ratchet(base:, base_epoch:, origin:, now:, epoch: 3600, retain: nil, horizon: 24)
      Ratchet.new(base:, base_epoch:, origin:, epoch:, retain:, horizon:, now:)
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

    # The keys as a Config whose tickets live `ticket_lifetime` seconds holds
    # them.
    def for_ticket_lifetime(ticket_lifetime) = self

    # When these keys stop sealing, nil for never.
    def issuing_until = nil

    # When to `advance`, nil for never.
    def next_advance_at = nil

    # The keys to hold from `now` on.
    def advance(now:) = self

    def inspect = "#<#{self.class.name} key_ids=#{@entries.map { |entry| entry.key_id.unpack1("H*") }.inspect}>"

    # Keys for each epoch of `epoch` seconds of the wall clock from `origin`,
    # the seed of each epoch derived from the one before:
    #
    #   seed(base_epoch) = base
    #   seed(e + 1)      = HKDF-Expand-Label(seed(e), "ticket ratchet", "", 32)
    #
    # Workers given the same base, base_epoch, origin and epoch compute the
    # same keys at the same time, and keep only the epochs from `retain`
    # before the one they were built in to `horizon` after it. They seal with
    # the key of the current epoch, none once past the horizon, and open a
    # ticket of a key `retain` epochs old to one epoch ahead, for clocks that
    # differ. `advance` builds them again from a later epoch; a seed is never
    # derived backwards, so keys stolen from memory open no ticket sealed
    # before the earliest epoch kept, though they give every later one.
    #
    # Without `retain`, it is the ticket lifetime in epochs plus one, set by
    # the Config the keys are given to (`for_ticket_lifetime`).
    class Ratchet < TicketKeys
      MAX_STEPS = 4096

      attr_reader :origin, :epoch, :retain, :horizon, :base, :base_epoch

      def initialize(base:, base_epoch:, origin:, epoch:, retain:, horizon:, now:)
        raise ArgumentError, "a ticket key is #{SEED_LENGTH} bytes" unless base.is_a?(String) && base.bytesize == SEED_LENGTH
        raise ArgumentError, "base_epoch must be an Integer" unless base_epoch.is_a?(Integer)
        raise ArgumentError, "origin and now must be Times" unless origin.is_a?(Time) && now.is_a?(Time)
        raise ArgumentError, "epoch must be a positive Integer of seconds" unless epoch.is_a?(Integer) && epoch.positive?
        raise ArgumentError, "retain must be nil or an Integer of 0 or more" unless retain.nil? || (retain.is_a?(Integer) && !retain.negative?)
        raise ArgumentError, "horizon must be an Integer of 1 or more" unless horizon.is_a?(Integer) && horizon.positive?
        @origin = origin.dup.freeze
        @epoch = epoch
        @retain = retain
        @horizon = horizon
        @built_at = now.dup.freeze
        @built_epoch = epoch_at(now)
        @base = base.b
        @base_epoch = base_epoch
        @by_epoch = {} #: Hash[Integer, Entry]
        return super([]) unless retain
        super(chain(retain))
      end

      def sealing(now)
        resolved!
        @by_epoch[epoch_at(now)]
      end

      def opening(key_id, now)
        resolved!
        entry = @by_id[key_id] or return nil
        current = epoch_at(now)
        entry if entry.epoch&.between?(current - retain!, current + 1)
      end

      def for_ticket_lifetime(ticket_lifetime)
        least = (ticket_lifetime.to_r / epoch).ceil
        return rebuild(retain: least + 1, now: @built_at) unless @retain
        # steep narrows no instance variable by the return above.
        raise ArgumentError, "retain #{@retain} keeps fewer epochs than a ticket lives (#{least})" if @retain < least # steep:ignore
        self
      end

      def issuing_until = resolved! && (origin + (@built_epoch + horizon + 1) * epoch)

      def next_advance_at = resolved! && (origin + (@built_epoch + 1) * epoch)

      def advance(now:) = rebuild(retain: retain!, now:)

      def inspect = "#<#{self.class.name} base_epoch=#{base_epoch} epochs=#{@by_epoch.keys.minmax.inspect}>"

      private def rebuild(retain:, now:)
        Ratchet.new(base:, base_epoch:, origin:, epoch:, retain:, horizon:, now:)
      end

      # The Entries from `retain` epochs before the current to `horizon`
      # after; `base` becomes the seed of the first.
      private def chain(retain)
        first = @built_epoch - retain
        last = @built_epoch + horizon
        raise ArgumentError, "base_epoch #{base_epoch} is after the first epoch kept, #{first}" if base_epoch > first
        if last - base_epoch > MAX_STEPS
          raise ArgumentError, "the base is #{last - base_epoch} epochs behind; hand out the base of the keys advance(now:) gives instead"
        end
        seed = @base
        (first - base_epoch).times { seed = step(seed) }
        @base = seed
        @base_epoch = first
        (first..last).map do |e|
          entry = TicketKeys.derive(seed, e)
          seed = step(seed)
          @by_epoch[e] = entry
        end
      end

      private def step(seed)
        KeySchedule.expand_label(secret: seed, label: "ticket ratchet", length: SEED_LENGTH, hash: HASH, prefix: PREFIX)
      end

      private def epoch_at(time) = ((time.to_r - origin.to_r) / epoch).floor

      private def retain! = @retain || raise(UsageError, "the ratchet keeps no epochs until a Config gives it its ticket lifetime")

      private def resolved! = retain! && true
    end
  end
end
