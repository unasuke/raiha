# frozen_string_literal: true

require_relative "../../quic/wire/buffer"
require_relative "static_table"
require_relative "integer"

module Raiha
  module HTTP3
    module QPACK
      class DecodingError < StandardError; end

      # RFC 9204: QPACK Decoder (static-table only, no Huffman, no dynamic table)
      class Decoder
        def initialize
        end

        # Decode an Encoded Field Section into a list of [name, value] pairs.
        def decode(encoded)
          buf = Quic::Wire::Buffer.new(encoded)

          # RFC 9204 Section 4.5.1: Field Section Prefix
          required_insert_count = Integer.decode(buf, 8)
          # Delta Base: 1 bit S + 7 bit Base value
          _delta_base = Integer.decode(buf, 7)

          raise DecodingError, "Dynamic table references not supported" if required_insert_count != 0

          headers = []
          until buf.eof?
            headers << decode_field_line(buf)
          end
          headers
        end

        private def decode_field_line(buf)
          first_byte = peek_uint8(buf)

          if (first_byte & 0x80) != 0
            decode_indexed_field_line(buf)
          elsif (first_byte & 0x40) != 0
            decode_literal_field_line_with_name_reference(buf)
          elsif (first_byte & 0x20) != 0
            decode_literal_field_line_with_literal_name(buf)
          elsif (first_byte & 0x10) != 0
            raise DecodingError, "Indexed Field Line With Post-Base Index not supported"
          else
            raise DecodingError, "Literal Field Line With Post-Base Name Reference not supported"
          end
        end

        # RFC 9204 Section 4.5.2
        # Pattern: 1 T xxxxxx
        private def decode_indexed_field_line(buf)
          first_byte = peek_uint8(buf)
          static = (first_byte & 0x40) != 0
          index = Integer.decode(buf, 6)

          raise DecodingError, "Dynamic table references not supported" unless static

          entry = StaticTable[index]
          raise DecodingError, "Invalid static table index #{index}" unless entry
          entry
        end

        # RFC 9204 Section 4.5.4
        # Pattern: 0 1 N T xxxx
        private def decode_literal_field_line_with_name_reference(buf)
          first_byte = peek_uint8(buf)
          static = (first_byte & 0x10) != 0
          index = Integer.decode(buf, 4)

          raise DecodingError, "Dynamic table references not supported" unless static

          entry = StaticTable[index]
          raise DecodingError, "Invalid static table index #{index}" unless entry
          name = entry[0]
          value = read_string(buf)
          [name, value]
        end

        # RFC 9204 Section 4.5.6
        # Pattern: 0 0 1 N H xxx
        private def decode_literal_field_line_with_literal_name(buf)
          first_byte = peek_uint8(buf)
          huffman = (first_byte & 0x08) != 0
          raise DecodingError, "Huffman decoding not supported" if huffman

          name_length = Integer.decode(buf, 3)
          name = buf.read(name_length)
          value = read_string(buf)
          [name, value]
        end

        private def peek_uint8(buf)
          byte = buf.read_uint8
          buf.seek(buf.pos - 1)
          byte
        end

        # RFC 7541 Section 5.2 / used in QPACK: H | 7-bit length prefix
        private def read_string(buf)
          first_byte = peek_uint8(buf)
          huffman = (first_byte & 0x80) != 0
          raise DecodingError, "Huffman decoding not supported" if huffman

          length = Integer.decode(buf, 7)
          buf.read(length)
        end
      end
    end
  end
end
