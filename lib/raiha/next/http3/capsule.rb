# frozen_string_literal: true

require_relative "varint"

module Raiha::Next::HTTP3
  # A Capsule of the Capsule Protocol (RFC 9297 "The Capsule Protocol"): a
  # type and a value, which the request's data stream carries in place of
  # content. This layer reads and writes any type; what a type means is
  # for the layers above, except DATAGRAM, which is an HTTP Datagram. The
  # value is frozen and binary, copied first when the caller's is not.
  class Capsule < Data.define(:type, :value)
    DATAGRAM = 0x00

    def initialize(type:, value:)
      raise ArgumentError, "a Capsule Type is 0..2^62-1, not #{type.inspect}" unless type.is_a?(Integer) && type.between?(0, Varint::MAX)
      value = value.frozen? && value.encoding == Encoding::BINARY ? value : value.b.freeze
      super
    end

    # The bytes of `capsule` on a data stream.
    def self.encode(capsule) = Varint.encode(capsule.type) << Varint.encode(capsule.value.bytesize) << capsule.value
  end

  # Reads the Capsules of one data stream from its bytes as they come.
  # One whose value is longer than `max_value` is passed over without its
  # bytes held, as RFC 9297 asks of one too long to use.
  class CapsuleReader
    # The longest a type and a length take together.
    MAX_HEADER = 16

    def initialize(max_value:)
      @max_value = max_value
      @header = "".b
      @type = nil #: Integer?
      @left = 0
      @value = nil #: String?
    end

    # Whether the bytes so far end inside a Capsule, which makes the
    # message malformed if the stream ends there (RFC 9297 "Error
    # Handling").
    def mid_capsule? = !@header.empty? || !@type.nil?

    # Reads `bytes`, yielding each Capsule whole.
    def feed(bytes, &)
      offset = 0
      while offset < bytes.bytesize
        offset = @type ? read_value(bytes, offset, &) : read_header(bytes, offset, &)
      end
    end

    private def read_header(bytes, offset, &)
      held = @header.bytesize
      source = held.zero? ? bytes : @header << bytes.byteslice(offset, MAX_HEADER - held) # steep:ignore
      start = held.zero? ? offset : 0
      type, after = Varint.decode(source, start)
      length, after = Varint.decode(source, after) if type && after
      unless length && after
        @header = source.byteslice(start..) if held.zero? # steep:ignore
        return bytes.bytesize
      end
      @header = "".b
      @type = type
      @left = length
      @value = length <= @max_value ? "".b : nil
      finish(&) if length.zero?
      held.zero? ? after : offset + after - held
    end

    private def read_value(bytes, offset, &)
      taken = [@left, bytes.bytesize - offset].min
      @value&.<<(bytes.byteslice(offset, taken)) # steep:ignore
      @left -= taken
      finish(&) if @left.zero?
      offset + taken
    end

    private def finish
      type = @type or return
      value = @value
      @type = nil
      @value = nil
      yield Capsule.new(type:, value: value.freeze) if value
    end
  end
end
