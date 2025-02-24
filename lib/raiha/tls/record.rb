# frozen_string_literal: true

require "stringio"
require_relative "record/tls_plaintext"
require_relative "record/tls_ciphertext"

module Raiha
  module TLS
    class Record
      CONTENT_TYPE = {
        invalid: 0,
        change_cipher_spec: 20,
        alert: 21,
        handshake: 22,
        application_data: 23,
      }.freeze

      LEGACY_RECORD_VERSION = [0x03, 0x03].pack("C*") # TLS v1.2

      def self.deserialize(buf)
        deserialized = []
        fragments = unwrap_fragments(buf)

        fragments.each do |fragment|
          case fragment[:content_type]
          when CONTENT_TYPE[:invalid]
            # TODO:
          when CONTENT_TYPE[:change_cipher_spec]
            deserialized << TLSPlaintext.new.tap do |record|
              record.content_type = fragment[:content_type]
              record.length = fragment[:length]
              record.fragment = ChangeCipherSpec.deserialize(fragment[:fragment])
              record.legacy_record_version = fragment[:legacy_record_version]
            end
          when CONTENT_TYPE[:alert]
            # TODO: deserialized << Alert.deserialize(fragment[:fragment])
          when CONTENT_TYPE[:handshake]
            deserialized << TLSPlaintext.new.tap do |record|
              record.content_type = fragment[:content_type]
              record.length = fragment[:length]
              record.fragment = Handshake.deserialize(fragment[:fragment])
              record.legacy_record_version = fragment[:legacy_record_version]
            end
          when CONTENT_TYPE[:application_data]
            deserialized << TLSCiphertext.new.tap do |record|
              record.length = fragment[:length]
              record.encrypted_record = fragment[:fragment]
            end
          else
            puts "unknown content type: #{fragment[:content_type]}"
          end
        end

        deserialized
      end

      def self.unwrap_fragments(serialized_records)
        fragments = []
        buf = StringIO.new(serialized_records)
        loop do
          content_type = buf.read(1).unpack1("C")
          legacy_record_version = buf.read(2) # [MUST] Ignore legacy_record_version field

          length = buf.read(2).unpack1("n")
          fragment = buf.read(length)
          raise if fragment.bytesize != length

          fragments << { content_type: content_type, length: length, fragment: fragment, legacy_record_version: legacy_record_version }
          break if buf.eof?
        end

        fragments
      end
    end
  end
end

