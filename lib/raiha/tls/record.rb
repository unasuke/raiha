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
            deserialized << ChangeCipherSpec.deserialize(fragment[:fragment])
          when CONTENT_TYPE[:alert]
            # TODO: deserialized << Alert.deserialize(fragment[:fragment])
          when CONTENT_TYPE[:handshake]
            deserialized << Handshake.deserialize(fragment[:fragment])
          when CONTENT_TYPE[:application_data]
            deserialized << ApplicationData.deserialize(fragment[:fragment])
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
          legacy_record_version = buf.read(2)
          raise "unknown legacy record version: #{legacy_record_version}" unless legacy_record_version == LEGACY_RECORD_VERSION

          length = buf.read(2).unpack1("n")
          fragment = buf.read(length)
          raise if fragment.bytesize != length

          fragments << { content_type: content_type, length: length, fragment: fragment }
          break if buf.eof?
        end

        fragments
      end
    end
  end
end

