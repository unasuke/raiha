# frozen_string_literal: true

require_relative "../error"
require_relative "protection"

module Raiha::TLS
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

    BAD_RECORD_MAC = Failure.new(alert: :bad_record_mac, reason: :bad_record_mac)

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
        # The client's 0-RTT skipped so far, and whether skipping has ended.
        @early_data_skipped = 0
        @skipping_ended = false
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
      # Failure, or nil until a whole record is buffered. A server that did
      # not take the client's 0-RTT gives `skip_early_data`, the most of it
      # to skip in bytes (Machine#skip_early_data_limit).
      def read(epoch:, skip_early_data: nil)
        loop do
          return nil if @buffer.bytesize < HEADER_LENGTH
          # The version field is ignored, as RFC 9846 asks. Only a record of
          # application_data is ever protected, so any other is held to the
          # plaintext limit as soon as its header is in.
          type, length = @buffer.unpack("Cx2n").map(&:to_i)
          # A type no record has is unexpected_message as soon as the header
          # is in, so that what is no TLS record, an SSL 2.0 ClientHello say,
          # is not waited on for a length it does not have.
          return Failure.new(alert: :unexpected_message, reason: :unexpected_record) unless CONTENT_TYPE_NAMES.key?(type)
          limit = type == CONTENT_TYPES.fetch(:application_data) ? MAX_PLAINTEXT + MAX_EXPANSION : MAX_PLAINTEXT
          return Failure.new(alert: :record_overflow, reason: :record_too_large) if length > limit # steep:ignore
          return nil if @buffer.bytesize < HEADER_LENGTH + length # steep:ignore
          header = @buffer.byteslice(0, HEADER_LENGTH).to_s
          fragment = @buffer.byteslice(HEADER_LENGTH, length).to_s # steep:ignore
          @buffer = @buffer.byteslice((HEADER_LENGTH + length)..).to_s # steep:ignore
          result = epoch == :initial ? unprotected(type, fragment) : protected(epoch, type, header, fragment) # steep:ignore
          return result unless skip_early_data && skipped?(epoch, type, result) # steep:ignore
          # Too short for a tag and a content type, it was never 0-RTT.
          return BAD_RECORD_MAC if fragment.bytesize <= Crypto::AEAD::TAG_LENGTH
          # The plaintext the record carried, at most, as its tag and content
          # type are not 0-RTT; an empty one counts once, so that the records
          # tried under the handshake key are bounded too.
          @early_data_skipped += (fragment.bytesize - Crypto::AEAD::TAG_LENGTH - 1).clamp(1, MAX_PLAINTEXT)
          return Failure.new(alert: :unexpected_message, reason: :too_much_early_data) if @early_data_skipped > skip_early_data
        end
      end

      # The records carrying `payload`, split to fit the peer's limit and
      # protected with `epoch`'s key unless it is :initial.
      def write(content_type:, payload:, epoch:)
        type = CONTENT_TYPES.fetch(content_type) { raise ArgumentError, "unknown content type #{content_type.inspect}" }
        if epoch == :initial
          fragments(payload, fragment_size(epoch)).map { |fragment| [type, Protection::LEGACY_RECORD_VERSION, fragment.bytesize].pack("Cnn") + fragment }.join
        else
          protection = @write.fetch(epoch) { raise UsageError, "no write key for #{epoch.inspect}" }
          fragments(payload, fragment_size(epoch)).map { |fragment| protection.seal(fragment + type.chr) }.join
        end
      end

      # The most content one record of `epoch` carries: a protected record
      # keeps to the peer's limit, less its content type byte.
      def fragment_size(epoch) = epoch == :initial ? MAX_PLAINTEXT : @send_size_limit - 1

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

      # RFC 9846 "Early Data Indication": the client's 0-RTT that was not
      # taken comes until its next flight, and is skipped. While the server
      # reads in the clear, after a HelloRetryRequest, that is each record of
      # application_data; under the handshake key, each record that does not
      # open. Any other record ends the skipping for good, but for the
      # change_cipher_spec of middlebox compatibility, which a client sends
      # before its 0-RTT.
      private def skipped?(epoch, type, result)
        return false if @skipping_ended
        rejected = case epoch
          when :initial then type == CONTENT_TYPES.fetch(:application_data)
          when :handshake then result == BAD_RECORD_MAC
          else false
          end
        @skipping_ended = true unless rejected || type == CONTENT_TYPES.fetch(:change_cipher_spec)
        rejected
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
        return Failure.new(alert: :unexpected_message, reason: :empty_alert_record) if name == :alert && fragment.empty?
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
        inner = protection.open(header, fragment) or return BAD_RECORD_MAC
        return Failure.new(alert: :record_overflow, reason: :record_too_large) if inner.bytesize > @receive_size_limit
        # TLSInnerPlaintext: the content, its type, then zeros.
        last = inner.bytesize - 1
        last -= 1 while last >= 0 && inner.getbyte(last) == 0
        return Failure.new(alert: :unexpected_message, reason: :no_content_type) if last < 0
        name = CONTENT_TYPE_NAMES[inner.getbyte(last).to_i]
        return Failure.new(alert: :unexpected_message, reason: :unexpected_record) if name.nil? || name == :change_cipher_spec
        content = inner.byteslice(0, last).to_s
        # RFC 8446 "Record Layer": a Handshake or Alert record of no content
        # is unexpected_message.
        return Failure.new(alert: :unexpected_message, reason: :empty_handshake_record) if name == :handshake && content.empty?
        return Failure.new(alert: :unexpected_message, reason: :empty_alert_record) if name == :alert && content.empty?
        Plaintext.new(content_type: name, payload: content)
      end
    end
  end
end
