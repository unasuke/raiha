require "raiha/next/http3/qpack"

# The QPACK Offline Interop of the qifs corpus (github.com/qpackers/qifs):
# header lists in QIF files, and what encoders made of them, a sequence of
# blocks, each a stream ID (8 octets), a length (4 octets) and that many
# octets, where stream 0 is the encoder stream and the others carry one
# field section each.
module NextQPACKOfflineInterop
  QPACK = Raiha::Next::HTTP3::QPACK
  QIFS_DIR = ENV.fetch("QIFS_DIR") { File.expand_path("../../../../tmp/qifs", __dir__) }

  # The header lists of a QIF file, in order: "name\tvalue" lines, a blank
  # line between lists, "#" for comments.
  private def qif(path)
    File.binread(path).split(/\n\n+/).map do |chunk|
      chunk.lines.grep_v(/\A#/).map(&:chomp).reject(&:empty?).map do |line|
        name, value = line.split("\t", 2)
        QPACK::Field.new(name: name.to_s.b, value: value.to_s.b)
      end
    end.reject(&:empty?)
  end

  # [stream ID, octets] of each block of an encoded file.
  private def blocks(bytes)
    offset = 0
    result = []
    while offset < bytes.bytesize
      stream_id, length = bytes.unpack("Q>N", offset:)
      result << [stream_id, bytes.byteslice(offset + 12, length)]
      offset += 12 + length
    end
    result
  end

  private def block(stream_id, octets) = [stream_id, octets.bytesize].pack("Q>N") + octets

  # The header lists an encoded file decodes to, by stream ID, or the
  # first result that is not Decoded. The files came before RFC 9204 made
  # the dynamic table's first capacity 0, and many insert without setting
  # one: the decoder is given the capacity first, as their encoders took
  # it to be.
  private def decode_file(bytes, table:, blocked:)
    decoder = QPACK::Decoder.new(max_table_capacity: table, max_blocked_streams: blocked)
    decoder.receive_encoder_stream(QPACK::Writer.new.integer(table, 5, 0x20).to_s)
    lists = {}
    blocks(bytes).each do |stream_id, octets|
      results = stream_id.zero? ? decoder.receive_encoder_stream(octets) : [decoder.decode(stream_id, octets)]
      return results if results.is_a?(QPACK::Failure)
      results.each do |result|
        case result
        when QPACK::Decoded then lists[result.stream_id] = result.fields
        when QPACK::Blocked then next
        else return result
        end
      end
    end
    lists
  end
end
