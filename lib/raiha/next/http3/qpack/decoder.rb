# frozen_string_literal: true

require_relative "dynamic_table"
require_relative "error_code"
require_relative "field"
require_relative "reader"
require_relative "result"
require_relative "static_table"

module Raiha::Next::HTTP3::QPACK
  # The decoder of one connection: it follows the encoder stream into its
  # dynamic table and decodes field sections against it. What the peer
  # sends never raises; it comes back as a Failure.
  class Decoder
    DEFAULT_MAX_FIELD_SECTION_SIZE = 65_536

    # `max_table_capacity` and `max_blocked_streams` are what this end
    # sends as SETTINGS_QPACK_MAX_TABLE_CAPACITY and
    # SETTINGS_QPACK_BLOCKED_STREAMS; both default to 0, as in RFC 9204
    # "Configuration".
    def initialize(max_table_capacity: 0, max_blocked_streams: 0, max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE)
      @table = DynamicTable.new(max_table_capacity)
      @max_blocked_streams = max_blocked_streams
      @max_field_section_size = max_field_section_size
      # The encoder stream's bytes of an instruction yet to arrive whole, and
      # how many of them it needs at least before it is worth reading again.
      @pending = String.new(encoding: Encoding::BINARY)
      @needed = 0
      @failure = nil
    end

    # Follows the instructions in `bytes` from the encoder stream (RFC 9204
    # "Encoder Instructions"), keeping an instruction cut short for the
    # bytes after it. A string that would not fit the dynamic table is
    # refused as soon as its length shows it, before its bytes come.
    def receive_encoder_stream(bytes)
      return @failure if @failure # steep:ignore
      @pending.append_as_bytes(bytes)
      return [] if @pending.bytesize < @needed
      reader = Reader.new(@pending)
      until reader.eof?
        start = reader.offset
        begin
          follow(reader)
        rescue Truncated => truncated
          if start.positive?
            @pending = @pending.byteslice(start..) #: String
          end
          @needed = truncated.needed - start
          return []
        end
      end
      @pending = String.new(encoding: Encoding::BINARY)
      @needed = 0
      []
    rescue Malformed, TooLong => error
      @failure = Failure.new(code: ErrorCode::ENCODER_STREAM_ERROR, reason: error.message)
    end

    # The field section `bytes` from the stream `stream_id` (RFC 9204
    # "Field Line Representations"). Bytes that do not decode are a
    # Failure of the connection, but an integer past 62 bits only of the
    # stream (RFC 9204 "Implementation Limits").
    def decode(stream_id, bytes)
      return @failure if @failure # steep:ignore
      reader = Reader.new(bytes)
      required = required_insert_count(reader.integer(8))
      negative = reader.peek[7] == 1
      delta = reader.integer(7)
      raise Malformed, "a Base below 0" if negative && delta >= required
      base = negative ? required - delta - 1 : required + delta
      if required > @table.insert_count
        raise Malformed, "a field section refers to entry #{required - 1}, which is yet to come"
      end
      fields = [] #: Array[Field]
      size = 0
      until reader.eof?
        field = represent(reader, required, base)
        fields << field
        size += field.name.bytesize + field.value.bytesize + DynamicTable::ENTRY_OVERHEAD
      end
      Decoded.new(stream_id:, fields: fields.freeze, size:)
    rescue IntegerOverflow => error
      Failure.new(code: ErrorCode::DECOMPRESSION_FAILED, reason: error.message, stream_id:)
    rescue Malformed => error
      @failure = Failure.new(code: ErrorCode::DECOMPRESSION_FAILED, reason: error.message)
    end

    # RFC 9204 "Required Insert Count": the encoded value is the count
    # modulo twice the most entries the table can hold, plus 1.
    private def required_insert_count(encoded)
      return 0 if encoded.zero?
      max_entries = @table.max_entries
      full_range = 2 * max_entries
      raise Malformed, "an encoded Required Insert Count of #{encoded} past #{full_range}" if encoded > full_range
      max_value = @table.insert_count + max_entries
      required = (max_value / full_range * full_range) + encoded - 1
      if required > max_value
        raise Malformed, "an encoded Required Insert Count of #{encoded} no encoder could send" if required <= full_range
        required -= full_range
      end
      raise Malformed, "a Required Insert Count of 0 encoded as #{encoded}" if required.zero?
      required
    end

    # One field line, its representation told by the first byte. A
    # reference to the dynamic table must be below the Required Insert
    # Count (RFC 9204 "Invalid References").
    private def represent(reader, required, base)
      first = reader.peek
      if first >= 0b1000_0000 # Indexed Field Line
        static = first[6] == 1
        index = reader.integer(6)
        name, value = static ? static_entry(index) : field_entry(base - 1 - index, required)
        Field.new(name:, value:)
      elsif first >= 0b0100_0000 # Literal Field Line with Name Reference
        never_indexed = first[5] == 1
        static = first[4] == 1
        index = reader.integer(4)
        name = (static ? static_entry(index) : field_entry(base - 1 - index, required)).first
        Field.new(name:, value: reader.string(8), never_indexed:)
      elsif first >= 0b0010_0000 # Literal Field Line with Literal Name
        never_indexed = first[4] == 1
        Field.new(name: reader.string(4), value: reader.string(8), never_indexed:)
      elsif first >= 0b0001_0000 # Indexed Field Line with Post-Base Index
        name, value = field_entry(base + reader.integer(4), required)
        Field.new(name:, value:)
      else # Literal Field Line with Post-Base Name Reference
        never_indexed = first[3] == 1
        name = field_entry(base + reader.integer(3), required).first
        Field.new(name:, value: reader.string(8), never_indexed:)
      end
    end

    private def field_entry(absolute, required)
      if absolute.negative? || absolute >= required
        raise Malformed, "a reference to dynamic entry #{absolute}, not below the Required Insert Count of #{required}"
      end
      @table.entry(absolute) or raise Malformed, "a reference to dynamic entry #{absolute}, which was evicted"
    end

    private def follow(reader)
      first = reader.peek
      if first >= 0b1000_0000 # Insert with Name Reference
        static = first[6] == 1
        name = (static ? static_entry(reader.integer(6)) : relative_entry(reader.integer(6))).first
        @table.insert(name, reader.string(8, room - name.bytesize))
      elsif first >= 0b0100_0000 # Insert with Literal Name
        name = reader.string(6, room)
        @table.insert(name, reader.string(8, room - name.bytesize))
      elsif first >= 0b0010_0000 # Set Dynamic Table Capacity
        @table.resize(reader.integer(5))
      else # Duplicate
        name, value = relative_entry(reader.integer(5))
        @table.insert(name, value)
      end
    end

    # The octets of name and value an entry may have and still fit.
    private def room = @table.capacity - DynamicTable::ENTRY_OVERHEAD

    private def static_entry(index)
      StaticTable.entry(index) or raise Malformed, "no static entry #{index}"
    end

    # RFC 9204 "Relative Indexing": on the encoder stream, 0 is the entry
    # inserted last.
    private def relative_entry(index)
      absolute = @table.insert_count - 1 - index
      @table.entry(absolute) or raise Malformed, "no dynamic entry at relative index #{index}"
    end
  end
end
