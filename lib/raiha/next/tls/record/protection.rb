# frozen_string_literal: true

require_relative "../crypto"
require_relative "../key_schedule"

module Raiha::Next::TLS
  module Record
    # One direction's protection under one traffic secret (RFC 9846 "Record
    # Payload Protection" and "Per-Record Nonce"): the AEAD keyed from the
    # secret, the nonce from the IV and the record sequence number, and the
    # count of records it has protected or opened.
    class Protection
      CONTENT_TYPE_APPLICATION_DATA = 23
      LEGACY_RECORD_VERSION = 0x0303

      attr_reader :cipher_suite, :sequence_number

      def initialize(secret:, cipher_suite:)
        @cipher_suite = cipher_suite
        hash = cipher_suite.hash_algorithm
        key = KeySchedule.expand_label(secret:, label: KeySchedule::LABELS.fetch(:key), length: cipher_suite.key_length, hash:)
        @iv = KeySchedule.expand_label(secret:, label: KeySchedule::LABELS.fetch(:iv), length: cipher_suite.iv_length, hash:)
        @aead = Crypto::AEAD.new(cipher_suite.aead, key)
        key.clear
        @sequence_number = 0
      end

      # The whole record that protects `inner_plaintext` (TLSInnerPlaintext:
      # content, its type, and any zero padding).
      def seal(inner_plaintext)
        header = [CONTENT_TYPE_APPLICATION_DATA, LEGACY_RECORD_VERSION, inner_plaintext.bytesize + Crypto::AEAD::TAG_LENGTH].pack("Cnn")
        header + @aead.seal(nonce: next_nonce, aad: header, plaintext: inner_plaintext)
      end

      # The TLSInnerPlaintext of the record with `header` and
      # `encrypted_record`, or nil when it does not authenticate. Only a
      # record that opens is counted: a server that did not take the
      # client's 0-RTT tries its records under the handshake key and skips
      # those that do not open (Layer#read).
      def open(header, encrypted_record)
        inner = @aead.open(nonce: nonce(@sequence_number), aad: header, ciphertext: encrypted_record)
        @sequence_number += 1 if inner
        inner
      end

      def discard!
        @iv.clear
        @aead.discard!
      end

      private def instance_variables_to_inspect = %i[@cipher_suite @sequence_number]

      private def next_nonce
        sequence = @sequence_number
        @sequence_number += 1
        nonce(sequence)
      end

      # The IV XORed with `sequence`, the number of records protected or
      # opened under this key before. Every suite here has a 12-byte IV.
      private def nonce(sequence)
        high, middle, low = @iv.unpack("N3")
        [high.to_i, middle.to_i ^ (sequence >> 32), low.to_i ^ (sequence & 0xffff_ffff)].pack("N3")
      end
    end
  end
end
