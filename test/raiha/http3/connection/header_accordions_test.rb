require "test_helper"
require "support/http3_pair"
require "raiha/quic"
require "stringio"

# Header Accordions (FoxIO, 2026) sent as HTTP/3 requests: a server
# expands no more of a request's field sections than its budget, the
# header section and the trailers together, and refuses past it, 431 for
# a request it has not given the application, H3_EXCESSIVE_LOAD for one it
# has. Each runs again with the qlog written, which stays small.
class RaihaNextHTTP3HeaderAccordionsTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK
  KIB = 1024
  POST = [[":method", "POST"], [":scheme", "https"], [":authority", "example.com"], [":path", "/upload"]].freeze
  # A 4 KiB entry for the dynamic table, as the client's encoder stream
  # carries it, and a field section that refers to it `count` times, a
  # byte each: 4,064 octets against the budget for every byte.
  LARGE_ENTRY = ("\x02".b + QPACK::Writer.new.integer(4096, 5, 0x20).string("a".b, 6, 0x40).string("x".b * 4031, 8).to_s).freeze

  def references(count) = "\x02\x00".b + ("\x80".b * count)

  def headers(section) = Frame.encode(Frame::Headers.new(field_section: section))

  def literal(fields) = QPACK::Encoder.new.encode(0, fields.map { QPACK::Field.new(name: _1, value: _2) })

  # About 29,000 fields of unique names in 200 KiB, under the longest
  # HEADERS frame a server holds, each 7 octets on the wire and 37 against
  # the budget: the server stops near 1,800 of them and answers 431.
  def test_unique_names_packed_into_a_request
    section = "\x00\x00".b + (0...(200 * KIB / 7)).map { |index| [0x25].pack("C") + format("%05d", index) + "\x00" }.join.b
    each_server do |server, qlog|
      allocated = allocations { server.stream_data(0, headers(section), fin: true) }
      assert_refused server
      assert_operator allocated, :<, 20_000, "the server stopped near 1,800 fields instead of expanding 29,000"
      assert_operator qlog.bytesize, :<, 2 * KIB if qlog
    end
  end

  # 1 MiB of them, as FoxIO sent: past four times the budget, the HEADERS
  # frame is refused as it begins, its payload passed over unheld.
  def test_a_megabyte_of_unique_names
    section = "\x00\x00".b + (0...((1 << 20) / 7)).map { |index| [0x25].pack("C") + format("%06d", index)[1..] + "\x00" }.join.b
    pieces = headers(section).bytes.each_slice(16 * KIB).map { _1.pack("C*") }
    each_server do |server, qlog|
      allocated = allocations { pieces.each { server.stream_data(0, _1) } }
      assert_refused server
      assert_operator allocated, :<, 1_000, "the server held the frame"
      assert_operator qlog.bytesize, :<, 2 * KIB if qlog
    end
  end

  # An entry of about 4 KiB referred to by each of 200 KiB of bytes: the
  # server stops after 17 references.
  def test_one_large_entry_referred_to_by_every_byte
    each_server(qpack_max_table_capacity: 4096) do |server, qlog|
      server.stream_data(6, LARGE_ENTRY)
      allocated = allocations { server.stream_data(0, headers(references(200 * KIB)), fin: true) }
      assert_refused server
      assert_operator allocated, :<, 1_000, "the server stopped after 17 references"
      assert_operator qlog.bytesize, :<, 2 * KIB if qlog
    end
  end

  # The trailers take what the header section left of the budget: two
  # references to the large entry fit after a small header section, not
  # after one of 60 KiB, and an accordion of them stops there too.
  def test_trailers_from_what_the_header_section_left
    [[POST, references(2), HTTP3::Event::Trailers], [POST + [["x-fill", "y" * (60 * KIB)]], references(2), HTTP3::Event::Reset],
     [POST, references(200 * KIB), HTTP3::Event::Reset]].each do |fields, trailers, last|
      each_server(qpack_max_table_capacity: 4096) do |server, qlog|
        server.stream_data(6, LARGE_ENTRY)
        server.stream_data(0, headers(literal(fields)) + Frame.encode(Frame::Data.new(data: "abc")))
        allocated = allocations { server.stream_data(0, headers(trailers), fin: true) }
        events = [].tap { |all| server.each_event { all << _1 } }
        assert_kind_of last, events.last
        if last == HTTP3::Event::Reset
          assert_equal HTTP3::ErrorCode::EXCESSIVE_LOAD, events.last.error_code
          assert_operator allocated, :<, 1_000
        end
        assert_operator qlog.bytesize, :<, 4 * KIB if qlog
      end
    end
  end

  # Runs the block with a server of `settings`, then with one that writes
  # its qlog, given as the String written.
  private def each_server(**settings)
    [false, true].each do |traced|
      io = StringIO.new if traced
      quic = Raiha::QUIC::Qlog::Tracer.new(io, vantage_point: :server, event_schemas: [HTTP3::Qlog::EVENT_SCHEMA]) if io
      server = HTTP3::Connection.server(settings: HTTP3::Settings.new(**settings), tracer: quic && HTTP3::Qlog::Tracer.new(quic))
      server.start(**SERVER_STREAMS)
      sent(server)
      yield server, io&.string
    end
  end

  # The server answered 431 and asked the client to stop sending.
  private def assert_refused(server)
    frames = []
    HTTP3::FrameReader.new(max_payload: KIB).feed(sent(server).fetch(0).first) { frames << _1 }
    fields = QPACK::Decoder.new.decode(0, frames.grep(Frame::Headers).first.field_section).fields
    assert_equal [[":status", "431"]], fields.map { [_1.name, _1.value] }
    assert_includes actions(server), HTTP3::Action::StopSending.new(stream_id: 0, error_code: HTTP3::ErrorCode::NO_ERROR)
  end

  private def allocations
    before = GC.stat(:total_allocated_objects)
    yield
    GC.stat(:total_allocated_objects) - before
  end
end
