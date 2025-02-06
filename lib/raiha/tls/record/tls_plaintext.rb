require "stringio"
require_relative "../record"
require_relative "../change_cipher_spec"
require_relative "../application_data"
require_relative "../handshake"

module Raiha
  module TLS
    class Record
      # TLSPlaintext class represents the +TLSPlaintext+ struct object.
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
      # @see https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
      class TLSPlaintext
        FRAGMENT_SIZE_LIMIT = 2**14
        attr_accessor :content_type
        attr_accessor :length
        attr_accessor :fragment

        def self.serialize(content)
          bufs = []
          data = content.serialize
          count = 0

          while (fragment = data[(FRAGMENT_SIZE_LIMIT * count)..(FRAGMENT_SIZE_LIMIT * (count + 1) - 1)])
            buf = String.new(encoding: "BINARY")
            case content
            when Handshake
              buf << [CONTENT_TYPE[:handshake]].pack("C")
            else
              raise "TODO #{content.class}"
            end
            buf << LEGACY_RECORD_VERSION
            buf << [fragment.bytesize].pack("n")
            buf << fragment
            bufs << buf
            count += 1
          end
          bufs
        end
      end
    end
  end
end
