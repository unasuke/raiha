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

      # ACK, and ACK with ECN counts (RFC 9000 "ACK Frames"). `ranges` are
      # the packet numbers acknowledged, as inclusive Ranges from the
      # largest down with a gap between each two; `delay` is the ACK Delay in
      # seconds; `ecn` the ECN counts, or nil.
      class Ack < Data.define(:ranges, :delay, :ecn)
        TYPES = [0x02, 0x03].freeze

        # The packets received with ECT(0), ECT(1) and CE.
        class ECNCounts < Data.define(:ect0, :ect1, :ce); end

        def initialize(ranges:, delay:, ecn: nil)
          raise ArgumentError, "an ACK acknowledges one packet at least" if ranges.empty?
          raise ArgumentError, "packet numbers are not negative: #{ranges.last}" if ranges.last.begin.negative?
          ranges.each { |range| raise ArgumentError, "an empty range #{range}" if range.begin > range.end }
          ranges.inject do |above, below|
            raise ArgumentError, "#{below} is not below #{above} with a gap" unless below.end < above.begin - 1
            below
          end
          raise ArgumentError, "a negative ACK Delay" if delay.negative?
          super
        end

        def largest = ranges.first.end

        # The Range Count field is not trusted to allocate anything: each
        # range takes two fields, so the bytes run out first when it lies.
        # A range below packet 0 is FRAME_ENCODING_ERROR.
        def self.read(reader, type:, ack_delay_exponent:)
          largest = reader.varint
          delay = reader.varint * (1 << ack_delay_exponent) / 1_000_000.0
          count = reader.varint
          smallest = largest - reader.varint
          raise Malformed, "the first ACK range goes below packet 0" if smallest.negative?
          ranges = [smallest..largest]
          count.times do
            range_largest = smallest - reader.varint - 2
            smallest = range_largest - reader.varint
            raise Malformed, "an ACK range goes below packet 0" if smallest.negative?
            ranges << (smallest..range_largest)
          end
          ecn = type == 0x03 ? ECNCounts.new(ect0: reader.varint, ect1: reader.varint, ce: reader.varint) : nil
          new(ranges:, delay:, ecn:)
        end

        # The delay goes in whole microseconds, divided by 2 to the power of
        # `ack_delay_exponent` (RFC 9000 "ACK Frames").
        def write(writer, ack_delay_exponent:)
          writer.u8(ecn ? 0x03 : 0x02).varint(largest).varint((delay * 1_000_000).round >> ack_delay_exponent)
          writer.varint(ranges.size - 1).varint(largest - ranges.first.begin)
          ranges.inject do |above, below|
            writer.varint(above.begin - below.end - 2).varint(below.end - below.begin)
            below
          end
          writer.varint(ecn.ect0).varint(ecn.ect1).varint(ecn.ce) if ecn
          writer
        end
      end

      KINDS = [Padding, Ping, HandshakeDone, Ack].freeze
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
