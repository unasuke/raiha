# frozen_string_literal: true

module Raiha::Next::QUIC
  module Wire
    # The frames of RFC 9000 "Frame Types and Formats", as values. Each knows
    # its frame types, reads its fields after the type, and writes itself.
    # ACK Delay is in seconds as a Float; `ack_delay_exponent` converts it,
    # the peer's when reading and our own when writing.
    module Frame
      # A run of PADDING frames, one zero byte each, read as one value.
      class Padding < Data.define(:length)
        TYPES = [0x00].freeze

        def initialize(length:)
          raise ArgumentError, "padding is 1 byte at least, not #{length}" unless length.positive?
          super
        end

        def self.read(reader, type:, ack_delay_exponent:) = new(length: 1 + reader.zero_run)

        def write(writer, ack_delay_exponent:) = writer.bytes("\0".b * length)
      end

      class Ping < Data.define
        TYPES = [0x01].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new

        def write(writer, ack_delay_exponent:) = writer.u8(0x01)
      end

      class HandshakeDone < Data.define
        TYPES = [0x1e].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new

        def write(writer, ack_delay_exponent:) = writer.u8(0x1e)
      end

      KINDS = [Padding, Ping, HandshakeDone].freeze
      BY_TYPE = KINDS.flat_map { |kind| kind::TYPES.map { |type| [type, kind] } }.to_h.freeze # steep:ignore

      # The frames of a packet's payload. A payload without frames, a frame
      # type of an unknown frame or not in its shortest encoding, and fields
      # that do not decode raise Malformed with the frame type and the error
      # to close the connection with (RFC 9000 "Frames and Frame Types").
      def self.parse(payload, ack_delay_exponent:)
        reader = Reader.new(payload)
        raise Malformed.new("a packet without frames", code: ErrorCode::PROTOCOL_VIOLATION) if reader.eof?
        frames = [] #: Array[t]
        frames << read(reader, ack_delay_exponent:) until reader.eof?
        frames
      end

      # The bytes of `frames`, one after another.
      def self.encode(frames, ack_delay_exponent:)
        writer = Writer.new
        frames.each { |frame| frame.write(writer, ack_delay_exponent:) }
        writer.to_s
      end

      private_class_method def self.read(reader, ack_delay_exponent:)
        type, size = reader.varint_with_size
        unless size == Varint.size(type)
          raise Malformed.new("frame type 0x#{type.to_s(16)} in #{size} bytes", code: ErrorCode::PROTOCOL_VIOLATION, frame_type: type)
        end
        kind = BY_TYPE.fetch(type) { raise Malformed.new("unknown frame type 0x#{type.to_s(16)}", frame_type: type) }
        begin
          kind.read(reader, type:, ack_delay_exponent:)
        rescue Malformed => error
          raise Malformed.new(error.message, code: error.code, frame_type: type)
        end
      end
    end
  end
end
