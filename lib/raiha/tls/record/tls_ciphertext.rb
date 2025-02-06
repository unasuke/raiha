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
        end
      end

      class TLSInnerPlaintext
        attr_accessor :content
        attr_accessor :content_type
        attr_accessor :zeros
      end
    end
  end
end
