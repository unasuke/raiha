# frozen_string_literal: true

require_relative "../error"
require_relative "protection"

module Raiha::Next::TLS
  module Record
    CONTENT_TYPES = { change_cipher_spec: 20, alert: 21, handshake: 22, application_data: 23 }.freeze #: Hash[Symbol, Integer]
    CONTENT_TYPE_NAMES = CONTENT_TYPES.invert.freeze #: Hash[Integer, Symbol]

    HEADER_LENGTH = 5
    MAX_PLAINTEXT = 1 << 14
    # TLSCiphertext.length may exceed the plaintext by up to 256 bytes.
    MAX_EXPANSION = 256
    # RFC 8449 counts the content type byte, so the default limit is one more
    # than MAX_PLAINTEXT.
    DEFAULT_SIZE_LIMIT = MAX_PLAINTEXT + 1

    # One record's content, opened. `content_type` is a Symbol of
    # CONTENT_TYPES. A change_cipher_spec record is only ever unprotected.
    class Plaintext < Data.define(:content_type, :payload)
    end

    # Why the record layer gave up on the peer's bytes, as the alert to send
    # and a reason for Event::Failed. A value, not an exception: over TCP a
    # record that does not open ends the connection (bad_record_mac), which
    # the caller decides, unlike QUIC, which drops such packets.
    class Failure < Data.define(:alert, :reason)
    end

    # The TLS record layer for Profile::TCP (RFC 9846 "Record Protocol").
    # Independent of the handshake: it holds a key table per epoch and
    # direction, filled from Output::Secret in queue order, and frames,
    # protects, opens and fragments records. Each record is read under the
    # epoch the caller names, so the caller can move the read epoch between
    # two records of one segment.
    class Layer
      def initialize(profile:)
        raise ArgumentError, "a record layer needs a profile with one, as Profile::TCP" unless profile.record_layer
        @buffer = "".b
        @read = {} #: Hash[epoch, Protection]
        @write = {} #: Hash[epoch, Protection]
        @send_size_limit = DEFAULT_SIZE_LIMIT
        @receive_size_limit = DEFAULT_SIZE_LIMIT
      end

      # Puts a key in the table, replacing the one of the same epoch and
      # direction: a KeyUpdate's next generation goes in the same way.
      def install(direction:, epoch:, secret:, cipher_suite:)
        raise UsageError, ":initial records are not protected" if epoch == :initial
        table = direction == :read ? @read : @write
        table[epoch]&.discard!
        table[epoch] = Protection.new(secret:, cipher_suite:)
        nil
      end

      # The record_size_limit values in force (RFC 8449): `send` is the
      # peer's, `receive` our own once the peer has agreed to it. Both count
      # the content type byte of a protected record.
      def limit_sizes(send: DEFAULT_SIZE_LIMIT, receive: DEFAULT_SIZE_LIMIT)
        @send_size_limit = send.clamp(..DEFAULT_SIZE_LIMIT)
        @receive_size_limit = receive.clamp(..DEFAULT_SIZE_LIMIT)
        nil
      end

      def <<(bytes)
        @buffer << bytes
        self
      end

      def pending_bytes = @buffer.bytesize

      # The next whole record, opened with `epoch`'s key: a Plaintext, a
      # Failure, or nil until a whole record is buffered.
      def read(epoch:)
        return nil if @buffer.bytesize < HEADER_LENGTH
        # The version field is ignored, as RFC 9846 asks.
        type, length = @buffer.unpack("Cx2n").map(&:to_i)
        return Failure.new(alert: :record_overflow, reason: :record_too_large) if length > MAX_PLAINTEXT + MAX_EXPANSION
        return nil if @buffer.bytesize < HEADER_LENGTH + length
        header = @buffer.byteslice(0, HEADER_LENGTH).to_s
        fragment = @buffer.byteslice(HEADER_LENGTH, length).to_s
        @buffer = @buffer.byteslice((HEADER_LENGTH + length)..).to_s
        epoch == :initial ? unprotected(type, fragment) : protected(epoch, type, header, fragment)
      end

      # The records carrying `payload`, split to fit the peer's limit and
      # protected with `epoch`'s key unless it is :initial.
      def write(content_type:, payload:, epoch:)
        type = CONTENT_TYPES.fetch(content_type) { raise ArgumentError, "unknown content type #{content_type.inspect}" }
        if epoch == :initial
          fragments(payload, MAX_PLAINTEXT).map { |fragment| [type, Protection::LEGACY_RECORD_VERSION, fragment.bytesize].pack("Cnn") + fragment }.join
        else
          protection = @write.fetch(epoch) { raise UsageError, "no write key for #{epoch.inspect}" }
          fragments(payload, @send_size_limit - 1).map { |fragment| protection.seal(fragment + type.chr) }.join
        end
      end

      # Records written under `epoch`'s current key.
      def records_written(epoch) = @write[epoch]&.sequence_number || 0

      # Whether `epoch`'s write key has room for only one more record within
      # its cipher suite's confidentiality limit over TCP: the KeyUpdate that
      # replaces it must go out now (RFC 9846 "Limits on Key Usage").
      def key_update_due?(epoch)
        protection = @write[epoch] or return false
        limit = protection.cipher_suite.confidentiality_limit(:tcp) or return false
        protection.sequence_number + 1 >= limit
      end

      def discard!
        (@read.values + @write.values).each(&:discard!)
        @read.clear
        @write.clear
        @buffer.clear
        nil
      end

      # An empty payload is one empty record: zero-length application data is
      # allowed, and the caller never writes an empty handshake message.
      private def fragments(payload, size)
        return ["".b] if payload.empty?
        (0...payload.bytesize).step(size).map { |offset| payload.byteslice(offset, size).to_s }
      end

      # Before any key: handshake, alert and change_cipher_spec records in
      # the clear. Application data cannot come yet.
      private def unprotected(type, fragment)
        name = CONTENT_TYPE_NAMES[type]
        return Failure.new(alert: :unexpected_message, reason: :unexpected_record) if name.nil? || name == :application_data
        return Failure.new(alert: :record_overflow, reason: :record_too_large) if fragment.bytesize > MAX_PLAINTEXT
        return Failure.new(alert: :unexpected_message, reason: :empty_handshake_record) if name == :handshake && fragment.empty?
        return change_cipher_spec(:initial, fragment) if name == :change_cipher_spec
        Plaintext.new(content_type: name, payload: fragment)
      end

      # Once keys are in place every record is protected, but for the
      # change_cipher_spec of middlebox compatibility and an alert from a
      # peer that failed before it had the handshake keys.
      private def protected(epoch, type, header, fragment)
        case CONTENT_TYPE_NAMES[type]
        when :application_data then open(epoch, header, fragment)
        when :change_cipher_spec then change_cipher_spec(epoch, fragment)
        when :alert then epoch == :handshake ? unprotected(type, fragment) : Failure.new(alert: :unexpected_message, reason: :unprotected_record)
        else Failure.new(alert: :unexpected_message, reason: :unprotected_record)
        end
      end

      # The single byte 0x01 a middlebox-compatible peer sends, which only
      # comes before the peer's Finished, that is, before the :application
      # read keys (RFC 9846 "Record Protocol"). Anything else is an
      # unexpected record. Whether one may come before the first ClientHello
      # is the caller's to judge.
      private def change_cipher_spec(epoch, fragment)
        return Failure.new(alert: :unexpected_message, reason: :unexpected_change_cipher_spec) if epoch == :application || fragment != "\x01".b
        Plaintext.new(content_type: :change_cipher_spec, payload: fragment)
      end

      private def open(epoch, header, fragment)
        protection = @read.fetch(epoch) { raise UsageError, "no read key for #{epoch.inspect}" }
        if fragment.bytesize > @receive_size_limit + MAX_EXPANSION - 1
          return Failure.new(alert: :record_overflow, reason: :record_too_large)
        end
        inner = protection.open(header, fragment) or return Failure.new(alert: :bad_record_mac, reason: :bad_record_mac)
        return Failure.new(alert: :record_overflow, reason: :record_too_large) if inner.bytesize > @receive_size_limit
        # TLSInnerPlaintext: the content, its type, then zeros.
        last = inner.bytesize - 1
        last -= 1 while last >= 0 && inner.getbyte(last) == 0
        return Failure.new(alert: :unexpected_message, reason: :no_content_type) if last < 0
        name = CONTENT_TYPE_NAMES[inner.getbyte(last).to_i]
        return Failure.new(alert: :unexpected_message, reason: :unexpected_record) if name.nil? || name == :change_cipher_spec
        content = inner.byteslice(0, last).to_s
        return Failure.new(alert: :unexpected_message, reason: :empty_handshake_record) if name == :handshake && content.empty?
        Plaintext.new(content_type: name, payload: content)
      end
    end
  end
end
