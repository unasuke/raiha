# frozen_string_literal: true

module Raiha::Next::QUIC
  module Wire
    # The frames of RFC 9000 "Frame Types and Formats" and the DATAGRAM frame
    # of RFC 9221, as values. Each knows its frame types, reads its fields
    # after the type, writes itself, and tells what RFC 9000 Table 3 says of
    # it. ACK Delay is in seconds as a Float; `ack_delay_exponent` converts
    # it, the peer's when reading and our own when writing.
    module Frame
      # The packet types of RFC 9000 Table 3, "Pkts": Initial, Handshake,
      # 0-RTT and 1-RTT.
      ALL_PACKETS = %i[initial handshake zero_rtt one_rtt].freeze
      NOT_ZERO_RTT = %i[initial handshake one_rtt].freeze
      APPLICATION_PACKETS = %i[zero_rtt one_rtt].freeze
      ONE_RTT = %i[one_rtt].freeze

      # What RFC 9000 Table 3 says of most frames: they travel in 0-RTT and
      # 1-RTT packets, elicit an ACK, and are no probe. Frames for which it
      # says otherwise override these.
      module Defaults
        def permitted_in?(packet_type) = APPLICATION_PACKETS.include?(packet_type)

        def ack_eliciting? = true

        # Whether the frame may go in a packet that probes a new path.
        def probing? = false
      end

      # A run of PADDING frames, one zero byte each, read as one value.
      class Padding < Data.define(:length)
        include Defaults

        TYPES = [0x00].freeze

        def permitted_in?(packet_type) = ALL_PACKETS.include?(packet_type)

        def ack_eliciting? = false

        def probing? = true

        def initialize(length:)
          raise ArgumentError, "padding is 1 byte at least, not #{length}" unless length.positive?
          super
        end

        def self.read(reader, type:, ack_delay_exponent:) = new(length: 1 + reader.zero_run)

        def write(writer, ack_delay_exponent:) = writer.bytes("\0".b * length)
      end

      class Ping < Data.define
        include Defaults

        TYPES = [0x01].freeze

        def permitted_in?(packet_type) = ALL_PACKETS.include?(packet_type)

        def self.read(reader, type:, ack_delay_exponent:) = new

        def write(writer, ack_delay_exponent:) = writer.u8(0x01)
      end

      class HandshakeDone < Data.define
        include Defaults

        TYPES = [0x1e].freeze

        def permitted_in?(packet_type) = ONE_RTT.include?(packet_type)

        def self.read(reader, type:, ack_delay_exponent:) = new

        def write(writer, ack_delay_exponent:) = writer.u8(0x1e)
      end

      # ACK, and ACK with ECN counts (RFC 9000 "ACK Frames"). `ranges` are
      # the packet numbers acknowledged, as inclusive Ranges from the
      # largest down with a gap between each two; `delay` is the ACK Delay in
      # seconds; `ecn` the ECN counts, or nil.
      class Ack < Data.define(:ranges, :delay, :ecn)
        include Defaults

        TYPES = [0x02, 0x03].freeze

        def permitted_in?(packet_type) = NOT_ZERO_RTT.include?(packet_type)

        def ack_eliciting? = false

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

      # Bytes of the TLS handshake at `offset` in the crypto stream of the
      # packet's encryption level (RFC 9000 "CRYPTO Frames").
      class Crypto < Data.define(:offset, :data)
        include Defaults

        TYPES = [0x06].freeze

        def permitted_in?(packet_type) = NOT_ZERO_RTT.include?(packet_type)

        def initialize(offset:, data:)
          raise ArgumentError, "CRYPTO data ends past 2^62 - 1" unless offset >= 0 && offset + data.bytesize <= Varint::MAX
          super
        end

        # Data that would end past 2^62 - 1 is FRAME_ENCODING_ERROR.
        def self.read(reader, type:, ack_delay_exponent:)
          offset = reader.varint
          length = reader.varint
          raise Malformed, "CRYPTO data ends past 2^62 - 1" if offset + length > Varint::MAX
          new(offset:, data: reader.bytes(length))
        end

        def write(writer, ack_delay_exponent:) = writer.u8(0x06).varint(offset).varint(data.bytesize).bytes(data)
      end

      # A token for the address validation of a later connection (RFC 9000
      # "NEW_TOKEN Frames"). An empty one is FRAME_ENCODING_ERROR.
      class NewToken < Data.define(:token)
        include Defaults

        TYPES = [0x07].freeze

        def permitted_in?(packet_type) = ONE_RTT.include?(packet_type)

        def initialize(token:)
          raise ArgumentError, "a NEW_TOKEN frame carries a token" if token.empty?
          super
        end

        def self.read(reader, type:, ack_delay_exponent:)
          token = reader.bytes(reader.varint)
          raise Malformed, "an empty NEW_TOKEN" if token.empty?
          new(token:)
        end

        def write(writer, ack_delay_exponent:) = writer.u8(0x07).varint(token.bytesize).bytes(token)
      end

      # Bytes of a stream at `offset`, and whether they end it (RFC 9000
      # "STREAM Frames"). The low three bits of the frame type say whether
      # an Offset and a Length field follow and whether FIN is set; without
      # a Length the data runs to the end of the packet. Written, the frame
      # always has a Length, and an Offset unless it is 0.
      class Stream < Data.define(:stream_id, :offset, :data, :fin)
        include Defaults

        TYPES = (0x08..0x0f).to_a.freeze
        OFF = 0x04
        LEN = 0x02
        FIN = 0x01

        def initialize(stream_id:, offset:, data:, fin: false)
          raise ArgumentError, "stream data ends past 2^62 - 1" unless offset >= 0 && offset + data.bytesize <= Varint::MAX
          super
        end

        # Data that would end past 2^62 - 1 is FRAME_ENCODING_ERROR.
        def self.read(reader, type:, ack_delay_exponent:)
          stream_id = reader.varint
          offset = type & OFF == 0 ? 0 : reader.varint
          length = type & LEN == 0 ? reader.remaining : reader.varint
          raise Malformed, "stream data ends past 2^62 - 1" if offset + length > Varint::MAX
          new(stream_id:, offset:, data: reader.bytes(length), fin: type & FIN != 0)
        end

        def write(writer, ack_delay_exponent:)
          type = 0x08 | LEN | (offset.zero? ? 0 : OFF) | (fin ? FIN : 0)
          writer.u8(type).varint(stream_id)
          writer.varint(offset) unless offset.zero?
          writer.varint(data.bytesize).bytes(data)
        end
      end

      # The sender abandons the sending part of a stream (RFC 9000
      # "RESET_STREAM Frames"); `final_size` is how far it got.
      class ResetStream < Data.define(:stream_id, :error_code, :final_size)
        include Defaults

        TYPES = [0x04].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(stream_id: reader.varint, error_code: reader.varint, final_size: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x04).varint(stream_id).varint(error_code).varint(final_size)
      end

      # The receiver asks the sender to stop sending on a stream (RFC 9000
      # "STOP_SENDING Frames").
      class StopSending < Data.define(:stream_id, :error_code)
        include Defaults

        TYPES = [0x05].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(stream_id: reader.varint, error_code: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x05).varint(stream_id).varint(error_code)
      end

      # The most data the peer may send on the connection (RFC 9000
      # "MAX_DATA Frames").
      class MaxData < Data.define(:maximum)
        include Defaults

        TYPES = [0x10].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(maximum: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x10).varint(maximum)
      end

      # The most data the peer may send on a stream (RFC 9000
      # "MAX_STREAM_DATA Frames").
      class MaxStreamData < Data.define(:stream_id, :maximum)
        include Defaults

        TYPES = [0x11].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(stream_id: reader.varint, maximum: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x11).varint(stream_id).varint(maximum)
      end

      # A count of streams of one direction no stream ID can go past: 2^60.
      MAX_STREAM_COUNT = 1 << 60

      # The most streams of one kind the peer may open (RFC 9000
      # "MAX_STREAMS Frames"). A count past 2^60 is FRAME_ENCODING_ERROR.
      class MaxStreams < Data.define(:bidirectional, :maximum)
        include Defaults

        TYPES = [0x12, 0x13].freeze

        def initialize(bidirectional:, maximum:)
          raise ArgumentError, "#{maximum} streams is past 2^60" if maximum > MAX_STREAM_COUNT
          super
        end

        def self.read(reader, type:, ack_delay_exponent:)
          maximum = reader.varint
          raise Malformed, "#{maximum} streams is past 2^60" if maximum > MAX_STREAM_COUNT
          new(bidirectional: type == 0x12, maximum:)
        end

        def write(writer, ack_delay_exponent:) = writer.u8(bidirectional ? 0x12 : 0x13).varint(maximum)
      end

      # The sender has data to send but the connection's limit, `maximum`,
      # stops it (RFC 9000 "DATA_BLOCKED Frames").
      class DataBlocked < Data.define(:maximum)
        include Defaults

        TYPES = [0x14].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(maximum: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x14).varint(maximum)
      end

      # The same for a stream (RFC 9000 "STREAM_DATA_BLOCKED Frames").
      class StreamDataBlocked < Data.define(:stream_id, :maximum)
        include Defaults

        TYPES = [0x15].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(stream_id: reader.varint, maximum: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x15).varint(stream_id).varint(maximum)
      end

      # The sender would open a stream but the count `maximum` stops it (RFC
      # 9000 "STREAMS_BLOCKED Frames"). A count past 2^60 is
      # FRAME_ENCODING_ERROR.
      class StreamsBlocked < Data.define(:bidirectional, :maximum)
        include Defaults

        TYPES = [0x16, 0x17].freeze

        def initialize(bidirectional:, maximum:)
          raise ArgumentError, "#{maximum} streams is past 2^60" if maximum > MAX_STREAM_COUNT
          super
        end

        def self.read(reader, type:, ack_delay_exponent:)
          maximum = reader.varint
          raise Malformed, "#{maximum} streams is past 2^60" if maximum > MAX_STREAM_COUNT
          new(bidirectional: type == 0x16, maximum:)
        end

        def write(writer, ack_delay_exponent:) = writer.u8(bidirectional ? 0x16 : 0x17).varint(maximum)
      end

      # A connection ID the peer may use, with its sequence number and the
      # token of a stateless reset for it (RFC 9000 "NEW_CONNECTION_ID
      # Frames"). A length outside 1 to 20 and Retire Prior To past the
      # sequence number are FRAME_ENCODING_ERROR.
      class NewConnectionID < Data.define(:sequence_number, :retire_prior_to, :connection_id, :stateless_reset_token)
        include Defaults

        TYPES = [0x18].freeze

        def probing? = true
        STATELESS_RESET_TOKEN_LENGTH = 16

        def initialize(sequence_number:, retire_prior_to:, connection_id:, stateless_reset_token:)
          raise ArgumentError, "Retire Prior To #{retire_prior_to} is past #{sequence_number}" if retire_prior_to > sequence_number
          raise ArgumentError, "a connection ID of #{connection_id.bytesize} bytes" unless connection_id.bytesize.between?(1, CONNECTION_ID_MAX_LENGTH)
          raise ArgumentError, "a stateless reset token has 16 bytes" unless stateless_reset_token.bytesize == STATELESS_RESET_TOKEN_LENGTH
          super
        end

        def self.read(reader, type:, ack_delay_exponent:)
          sequence_number = reader.varint
          retire_prior_to = reader.varint
          raise Malformed, "Retire Prior To #{retire_prior_to} is past #{sequence_number}" if retire_prior_to > sequence_number
          length = reader.u8
          raise Malformed, "a connection ID of #{length} bytes" unless length.between?(1, CONNECTION_ID_MAX_LENGTH)
          new(sequence_number:, retire_prior_to:, connection_id: reader.bytes(length), stateless_reset_token: reader.bytes(STATELESS_RESET_TOKEN_LENGTH))
        end

        def write(writer, ack_delay_exponent:)
          writer.u8(0x18).varint(sequence_number).varint(retire_prior_to)
            .u8(connection_id.bytesize).bytes(connection_id).bytes(stateless_reset_token)
        end
      end

      # The connection ID of `sequence_number` is no longer used (RFC 9000
      # "RETIRE_CONNECTION_ID Frames").
      class RetireConnectionID < Data.define(:sequence_number)
        include Defaults

        TYPES = [0x19].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(sequence_number: reader.varint)

        def write(writer, ack_delay_exponent:) = writer.u8(0x19).varint(sequence_number)
      end

      PATH_DATA_LENGTH = 8

      # Eight bytes for the peer to echo, to validate a path (RFC 9000
      # "PATH_CHALLENGE Frames").
      class PathChallenge < Data.define(:data)
        include Defaults

        TYPES = [0x1a].freeze

        def probing? = true

        def initialize(data:)
          raise ArgumentError, "PATH_CHALLENGE data has 8 bytes" unless data.bytesize == PATH_DATA_LENGTH
          super
        end

        def self.read(reader, type:, ack_delay_exponent:) = new(data: reader.bytes(PATH_DATA_LENGTH))

        def write(writer, ack_delay_exponent:) = writer.u8(0x1a).bytes(data)
      end

      # The echo of a PATH_CHALLENGE (RFC 9000 "PATH_RESPONSE Frames").
      class PathResponse < Data.define(:data)
        include Defaults

        TYPES = [0x1b].freeze

        def permitted_in?(packet_type) = ONE_RTT.include?(packet_type)

        def probing? = true

        def initialize(data:)
          raise ArgumentError, "PATH_RESPONSE data has 8 bytes" unless data.bytesize == PATH_DATA_LENGTH
          super
        end

        def self.read(reader, type:, ack_delay_exponent:) = new(data: reader.bytes(PATH_DATA_LENGTH))

        def write(writer, ack_delay_exponent:) = writer.u8(0x1b).bytes(data)
      end

      # The end of the connection (RFC 9000 "CONNECTION_CLOSE Frames"), with
      # the fields of ConnectionError. A transport error (type 0x1c) names
      # the frame type that caused it, 0 when none did; an application error
      # (type 0x1d) has no frame type. `reason` is the bytes as they came.
      class ConnectionClose < Data.define(:code, :frame_type, :reason, :application)
        include Defaults

        TYPES = [0x1c, 0x1d].freeze

        # Only a transport error may close a connection in Initial and Handshake
        # packets.
        def permitted_in?(packet_type) = (application ? APPLICATION_PACKETS : ALL_PACKETS).include?(packet_type)

        def ack_eliciting? = false

        def initialize(code:, frame_type:, reason:, application:)
          raise ArgumentError, "an application error names no frame type" if application && frame_type
          raise ArgumentError, "a transport error names a frame type, 0 for none" unless application || frame_type
          super
        end

        def self.read(reader, type:, ack_delay_exponent:)
          application = type == 0x1d
          code = reader.varint
          frame_type = application ? nil : reader.varint
          new(code:, frame_type:, reason: reader.bytes(reader.varint), application:)
        end

        def write(writer, ack_delay_exponent:)
          writer.u8(application ? 0x1d : 0x1c).varint(code)
          writer.varint(frame_type) if frame_type
          writer.varint(reason.bytesize).bytes(reason)
        end
      end

      # Application data outside any stream (RFC 9221 "Datagram Frame
      # Types"). Type 0x30 runs to the end of the packet, 0x31 has a Length;
      # written, it always has the Length.
      class Datagram < Data.define(:data)
        include Defaults

        TYPES = [0x30, 0x31].freeze

        def self.read(reader, type:, ack_delay_exponent:) = new(data: type == 0x31 ? reader.bytes(reader.varint) : reader.rest)

        def write(writer, ack_delay_exponent:) = writer.u8(0x31).varint(data.bytesize).bytes(data)
      end

      KINDS = [
        Padding, Ping, HandshakeDone, Ack, Crypto, NewToken, Stream, ResetStream, StopSending,
        MaxData, MaxStreamData, MaxStreams, DataBlocked, StreamDataBlocked, StreamsBlocked,
        NewConnectionID, RetireConnectionID, PathChallenge, PathResponse, ConnectionClose, Datagram
      ].freeze
      BY_TYPE = KINDS.flat_map { |kind| kind::TYPES.map { |type| [type, kind] } }.to_h.freeze # steep:ignore

      # The frames of the payload of a packet of `packet_type` (:initial,
      # :handshake, :zero_rtt or :one_rtt, as the header's `type` says). A
      # payload without frames, a frame type of an unknown frame or not in its
      # shortest encoding, fields that do not decode, and a frame the packet
      # type may not carry raise Malformed with the frame type and the error
      # to close the connection with (RFC 9000 "Frames and Frame Types").
      def self.parse(payload, packet_type:, ack_delay_exponent:)
        reader = Reader.new(payload)
        raise Malformed.new("a packet without frames", code: ErrorCode::PROTOCOL_VIOLATION) if reader.eof?
        frames = [] #: Array[t]
        frames << read(reader, packet_type:, ack_delay_exponent:) until reader.eof?
        frames
      end

      # The bytes of `frames`, one after another.
      def self.encode(frames, ack_delay_exponent:)
        writer = Writer.new
        frames.each { |frame| frame.write(writer, ack_delay_exponent:) }
        writer.to_s
      end

      private_class_method def self.read(reader, packet_type:, ack_delay_exponent:)
        type, size = reader.varint_with_size
        unless size == Varint.size(type)
          raise Malformed.new("frame type 0x#{type.to_s(16)} in #{size} bytes", code: ErrorCode::PROTOCOL_VIOLATION, frame_type: type)
        end
        kind = BY_TYPE.fetch(type) { raise Malformed.new("unknown frame type 0x#{type.to_s(16)}", frame_type: type) }
        frame = begin
          kind.read(reader, type:, ack_delay_exponent:)
        rescue Malformed => error
          raise Malformed.new(error.message, code: error.code, frame_type: type)
        end
        unless frame.permitted_in?(packet_type)
          raise Malformed.new("frame type 0x#{type.to_s(16)} in a #{packet_type} packet", code: ErrorCode::PROTOCOL_VIOLATION, frame_type: type)
        end
        frame
      end
    end
  end
end
