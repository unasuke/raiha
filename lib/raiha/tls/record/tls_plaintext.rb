require "stringio"
require_relative "../record"
require_relative "../change_cipher_spec"
require_relative "../application_data"
require_relative "../handshake"
require_relative "../alert"

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
        attr_accessor :legacy_record_version

        def self.serialize(content)
          bufs = []
          data = content.serialize
          count = 0

          while (fragment = data[(FRAGMENT_SIZE_LIMIT * count)..(FRAGMENT_SIZE_LIMIT * (count + 1) - 1)])
            buf = String.new(encoding: "BINARY")
            case content
            when Handshake
              buf << [CONTENT_TYPE[:handshake]].pack("C")
            when Alert::ErrorAlert, Alert::ClosureAlert
              buf << [CONTENT_TYPE[:alert]].pack("C")
            else
              raise "TODO #{content.class}"
            end
            buf << (@legacy_record_version || LEGACY_RECORD_VERSION)
            buf << [fragment.bytesize].pack("n")
            buf << fragment
            bufs << buf
            count += 1
          end
          bufs
        end

        def serialize
          buf = String.new(encoding: "BINARY")
          serialized = @fragment.serialize

          case @fragment
          when Handshake
            buf << [CONTENT_TYPE[:handshake]].pack("C")
          else
            raise "TODO #{@fragment.class}"
          end
          buf << (@legacy_record_version || LEGACY_RECORD_VERSION)
          buf << [serialized.bytesize].pack("n")
          buf << serialized
          buf
        end

        def invalid?
          @content_type == CONTENT_TYPE[:invalid]
        end

        def change_cipher_spec?
          @content_type == CONTENT_TYPE[:change_cipher_spec]
        end

        def handshake?
          @content_type == CONTENT_TYPE[:handshake]
        end

        def alert?
          @content_type == CONTENT_TYPE[:alert]
        end

        def application_data?
          @content_type == CONTENT_TYPE[:application_data]
        end

        def plaintext?
          true
        end

        def ciphertext?
          false
        end
      end
    end
  end
end
