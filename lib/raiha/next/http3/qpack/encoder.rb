# frozen_string_literal: true

require_relative "field"
require_relative "static_table"
require_relative "writer"

module Raiha::Next::HTTP3::QPACK
  # The encoder of one connection. It refers to the static table and sends
  # the rest as literals: it inserts nothing into the dynamic table, so a
  # field section never waits on the encoder stream and no entry is held
  # by a reference the decoder has yet to acknowledge.
  class Encoder
    # The representations of RFC 9204 "Field Line Representations", as the
    # bits above their prefixes.
    INDEXED_STATIC = 0b1100_0000 # Indexed Field Line, T = 1
    NAME_REFERENCE_STATIC = 0b0101_0000 # Literal Field Line with Name Reference, T = 1
    NAME_REFERENCE_NEVER_INDEXED = 0b0010_0000
    LITERAL_NAME = 0b0010_0000 # Literal Field Line with Literal Name
    LITERAL_NAME_NEVER_INDEXED = 0b0001_0000

    # The field section of `fields` for the stream `stream_id`. Its
    # Required Insert Count and Base are both 0. A field in the static
    # table goes as its index, one whose name is there as a reference to
    # the name, and the rest as literals; a never-indexed one is always a
    # literal.
    def encode(stream_id, fields)
      writer = Writer.new.integer(0, 8).integer(0, 7)
      fields.each { |field| represent(writer, field) }
      writer.to_s
    end

    private def represent(writer, field)
      never_indexed = field.never_indexed
      if !never_indexed && (index = StaticTable.find(field.name, field.value))
        writer.integer(index, 6, INDEXED_STATIC)
      elsif (index = StaticTable.find_name(field.name))
        writer.integer(index, 4, NAME_REFERENCE_STATIC | (never_indexed ? NAME_REFERENCE_NEVER_INDEXED : 0)).string(field.value, 8)
      else
        writer.string(field.name, 4, LITERAL_NAME | (never_indexed ? LITERAL_NAME_NEVER_INDEXED : 0)).string(field.value, 8)
      end
    end
  end
end
