# frozen_string_literal: true

require_relative "../../quic/wire/buffer"
require_relative "static_table"
require_relative "integer"

module Raiha
  module HTTP3
    module QPACK
      # RFC 9204: QPACK Encoder (static-table only, no Huffman, no dynamic table)
      class Encoder
        def initialize
        end

        # Encode a list of [name, value] header pairs into an Encoded Field Section.
        # RFC 9204 Section 4.5
        def encode(headers)
          buf = Quic::Wire::Buffer.new

          # Required Insert Count = 0 (no dynamic table entries required)
          buf.write(Integer.encode(0, 8, 0))
          # Delta Base: S=0, Base=0
          buf.write(Integer.encode(0, 7, 0))

          headers.each do |name, value|
            encode_field_line(buf, name.downcase, value)
          end

          buf.to_s
        end

        private def encode_field_line(buf, name, value)
          idx = StaticTable.find(name, value)
          if idx
            # RFC 9204 Section 4.5.2: Indexed Field Line, T=1 (static)
            # Pattern: 1 T xxxxxx  → flags 0xc0, 6-bit prefix for index
            buf.write(Integer.encode(idx, 6, 0xc0))
            return
          end

          name_idx = StaticTable.find_name(name)
          if name_idx
            # RFC 9204 Section 4.5.4: Literal Field Line with Name Reference, T=1 (static)
            # Pattern: 0 1 N T xxxx  → with N=0, T=1 → flags 0x50, 4-bit prefix for index
            buf.write(Integer.encode(name_idx, 4, 0x50))
            write_string(buf, value, huffman: false)
            return
          end

          # RFC 9204 Section 4.5.6: Literal Field Line with Literal Name
          # Pattern: 0 0 1 N H xxx (3-bit name length prefix, H=0 for non-Huffman, N=0)
          # → flags 0x20, 3-bit prefix for name length
          name_bytes = name.b
          buf.write(Integer.encode(name_bytes.bytesize, 3, 0x20))
          buf.write(name_bytes)
          write_string(buf, value, huffman: false)
        end

        # Write a length-prefixed string. RFC 9204 Section 4.5 / RFC 7541 Section 5.2.
        # First byte: H | 7-bit length prefix. H=0 for non-Huffman.
        private def write_string(buf, str, huffman:)
          raise NotImplementedError, "Huffman encoding not supported" if huffman

          bytes = str.b
          buf.write(Integer.encode(bytes.bytesize, 7, 0x00))
          buf.write(bytes)
        end
      end
    end
  end
end
