# frozen_string_literal: true

require "stringio"
require_relative "record/tls_plaintext"
require_relative "record/tls_ciphertext"
require_relative "../util/io_reader"

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
        deserialized = [] #: Array[TLSPlaintext | TLSCiphertext]
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
            parsed = Handshake.deserialize_with_bytes(fragment[:fragment])
            next if parsed.nil?
            handshake, raw_bytes = parsed
            deserialized << TLSPlaintext.new.tap do |record|
              record.content_type = fragment[:content_type]
              record.length = fragment[:length]
              record.fragment = handshake
              record.handshake_raw_bytes = raw_bytes
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
        # @type var fragments: Array[{content_type: Integer, length: Integer, fragment: String, legacy_record_version: String}]
        fragments = []
        buf = StringIO.new(serialized_records)
        loop do
          content_type = Raiha::Util::IOReader.read_exact(buf, 1).unpack1("C")
          legacy_record_version = Raiha::Util::IOReader.read_exact(buf, 2) # [MUST] Ignore legacy_record_version field

          length = Raiha::Util::IOReader.read_exact(buf, 2).unpack1("n")
          fragment = Raiha::Util::IOReader.read_exact(buf, length)
          raise if fragment.bytesize != length

          fragments << { content_type: content_type, length: length, fragment: fragment, legacy_record_version: legacy_record_version }
          break if buf.eof?
        end

        fragments
      end
    end
  end
end

