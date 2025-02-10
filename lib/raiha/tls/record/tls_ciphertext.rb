require "stringio"
require_relative "../record"

module Raiha
  module TLS
    class Record
      # TLSCiphertext class represents the +TLSCiphertext+ struct object.
      #
      #     enum {
      #         invalid(0),
      #         change_cipher_spec(20),
      #         alert(21),
      #         handshake(22),
      #         application_data(23),
      #         (255)
      #     } ContentType;
      #
      #     struct {
      #         ContentType type;
      #         ProtocolVersion legacy_record_version;
      #         uint16 length;
      #         opaque fragment[TLSPlaintext.length];
      #     } TLSPlaintext;
      #
      #     struct {
      #         opaque content[TLSPlaintext.length];
      #         ContentType type;
      #         uint8 zeros[length_of_padding];
      #     } TLSInnerPlaintext;
      #
      #     struct {
      #         ContentType opaque_type = application_data; /* 23 */
      #         ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
      #         uint16 length;
      #         opaque encrypted_record[TLSCiphertext.length];
      #     } TLSCiphertext;
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
      class TLSCiphertext
        attr_reader :content_type
        attr_accessor :length
        attr_accessor :encrypted_record
        attr_accessor :tls_inner_plaintext

        def initialize
          @content_type = CONTENT_TYPE[:application_data]
          @protocol_version = [0x03, 0x03].pack("C*") # TLS v1.2
          @tls_inner_plaintext = nil
        end

        def serialize
          [@content_type].pack("C") + @protocol_version + [@encrypted_record.bytesize].pack("n") + @encrypted_record
        end

        def auth_tag
          # TODO: 16
          @encrypted_record[-16..-1]
        end

        def encrypted_record_without_auth_tag
          # TODO: 16
          @encrypted_record[0...-16]
        end

        def additional_data
          [@content_type].pack("C") + @protocol_version + [@length].pack("n")
        end
      end

      class TLSInnerPlaintext
        attr_accessor :content
        attr_accessor :content_type
        attr_accessor :zeros

        PROTOCOL_VERSION = [0x03, 0x03].pack("C*") # TLS v1.2

        def self.deserialize(data)
          tls_inner_plaintext = self.new
          pads = 0
          loop { pads -= 1; break if data[pads] != "\x00" }
          tls_inner_plaintext.content = data[0..(pads - 1)]
          tls_inner_plaintext.content_type = data[pads].unpack1("C")
          tls_inner_plaintext
        end

        def serialize
          content + [content_type].pack("C") # TODO: no zeros
        end

        def additional_data
          # TODO: hardcoded values
          [23].pack("C") + PROTOCOL_VERSION + [serialize.bytesize + 16].pack("n")
        end
      end
    end
  end
end
