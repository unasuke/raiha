require "stringio"
require_relative "../record"

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

        def self.deserialize(bufs)
          cursor = 0
          deserialized = []
          loop do
            target = bufs[cursor]
            fragment = unwrap_fragment(target)

            case fragment[:content_type]
            when CONTENT_TYPE[:handshake]
              fragment_hs = fragment[:fragment]
              loop do
                hs = Handshake.deserialize(fragment_hs)
                if hs.nil?
                  cursor += 1
                  target = bufs[cursor]
                  fragment = unwrap_fragment(target)
                  if fragment[:content_type] == CONTENT_TYPE[:handshake]
                    fragment_hs += fragment[:fragment]
                  else
                    raise "unexpected content type: #{fragment[:content_type]}"
                  end
                else
                  deserialized << hs
                  break
                end
              end
            end

            cursor += 1
            break if bufs.length <= cursor
          end

          deserialized
        end

        def self.unwrap_fragment(serialized_tlsplaintext)
          buf = StringIO.new(serialized_tlsplaintext)
          content_type = buf.read(1).unpack1("C")
          legacy_record_version = buf.read(2)
          raise "unknown legacy record version: #{legacy_record_version}" unless legacy_record_version == LEGACY_RECORD_VERSION

          length = buf.read(2).unpack1("n")
          fragment = buf.read(length)
          if !buf.eof? || fragment.bytesize != length
            raise "incorrect fragment size: #{fragment.bytesize}, given length: #{length}"
          end

          { content_type: content_type, fragment: fragment }
        end
      end
    end
  end
end
