require "raiha/next/test_helper"
require "raiha/next/support/http3_pair"

# What the peer sends never raises out of the HTTP/3 layer: the frame
# reader gives frames or Frame::Malformed, the same however the bytes are
# cut, and a Connection takes anything on any stream, and any datagram,
# closing at most once and sending nothing after. The inputs are random
# bytes, frames of every kind with random values, and real requests and
# responses with a byte changed, cut short or lengthened.
# RAIHA_FUZZ_ITERATIONS (default 300) and RAIHA_FUZZ_SEED change the
# number of inputs to each target and the seed.
class RaihaNextHTTP3FuzzTest < Minitest::Test
  include NextHTTP3Pair

  Frame = HTTP3::Frame
  QPACK = HTTP3::QPACK

  ITERATIONS = Integer(ENV.fetch("RAIHA_FUZZ_ITERATIONS", "300"))
  SEED = Integer(ENV.fetch("RAIHA_FUZZ_SEED", "9114"))
  GET = [[":method", "GET"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  CONNECT = [[":method", "CONNECT"], [":protocol", "echo"], [":scheme", "https"], [":authority", "example.com"], [":path", "/"]].freeze
  # Encoder instructions that insert two entries in a table of 4096
  # octets, and a field section that refers to them, blocked until they
  # come.
  INSTRUCTIONS = (QPACK::Writer.new.integer(4096, 5, 0x20).to_s + QPACK::Writer.new.string("x-key".b, 6, 0x40).string("v".b, 8).to_s * 2).freeze
  BLOCKED = QPACK::Writer.new.integer(3, 8).integer(0, 7).integer(0, 6, 0x80).integer(1, 6, 0x80).to_s.freeze
  # Types besides those of Frame: reserved, of HTTP/2, unknown.
  OTHER_TYPES = [0x21, 0x21 + 0x1f * 7, *Frame::HTTP2_TYPES, 0x0e, 0x4242].freeze

  def test_reading_frames_however_cut
    run_fuzz("FrameReader") do |rng|
      bytes = rng.rand(3).zero? ? rng.bytes(rng.rand(0..80)) : mutate(rng, frames(rng))
      max_payload = rng.rand(0..64)
      whole = read(bytes, [bytes.bytesize], max_payload)
      cuts = Array.new(rng.rand(1..6)) { rng.rand(0..bytes.bytesize) }
      assert_equal whole, read(bytes, cuts, max_payload)
    end
  end

  def test_a_server_takes_anything
    run_fuzz("server") do |rng|
      settings = HTTP3::Settings.new(enable_connect_protocol: true, qpack_max_table_capacity: [0, 4096].sample(random: rng), qpack_blocked_streams: rng.rand(0..2))
      server = HTTP3::Connection.server(settings:)
      server.start(**SERVER_STREAMS)
      closes = 0
      rng.rand(1..6).times do
        case rng.rand(6)
        when 0 then server.stream_data(2, "\x00".b + mutate(rng, Frame.encode(HTTP3::Settings.new.to_frame) + frames(rng)), fin: rng.rand(8).zero?)
        when 1 then server.stream_data(rng.rand(0..3) * 4, mutate(rng, request(rng)), fin: rng.rand(2).zero?)
        when 2 then server.stream_data([6, 10, 14, 18].sample(random: rng), [rng.rand(0..4)].pack("C") + mutate(rng, INSTRUCTIONS), fin: rng.rand(4).zero?)
        when 3 then server.datagram_received([rng.rand(0..3)].pack("C") + rng.bytes(rng.rand(0..20)))
        when 4 then server.stream_reset(rng.rand(0..15), error_code: rng.rand(0..0x200))
        else server.stream_stopped(rng.rand(0..3) * 4, error_code: rng.rand(0..0x200))
        end
        closes += drain(server)
      end
      assert_operator closes, :<=, 1
    end
  end

  def test_a_client_takes_anything
    run_fuzz("client") do |rng|
      client = HTTP3::Connection.client
      client.start(**CLIENT_STREAMS)
      client.send_request(0, GET, fin: true)
      closes = 0
      rng.rand(1..6).times do
        case rng.rand(4)
        when 0 then client.stream_data(3, "\x00".b + mutate(rng, Frame.encode(HTTP3::Settings.new.to_frame) + frames(rng)), fin: rng.rand(8).zero?)
        when 1 then client.stream_data(0, mutate(rng, response(rng)), fin: rng.rand(2).zero?)
        when 2 then client.stream_data([1, 7, 11, 15].sample(random: rng), [rng.rand(0..4)].pack("C") + rng.bytes(rng.rand(0..30)), fin: rng.rand(4).zero?)
        else client.datagram_received(rng.bytes(rng.rand(0..20)))
        end
        closes += drain(client)
      end
      assert_operator closes, :<=, 1
    end
  end

  # What a reader with `max_payload` gives of `bytes` fed cut at `cuts`:
  # the pieces of DATA joined, and whether it ended in Frame::Malformed.
  private def read(bytes, cuts, max_payload)
    reader = HTTP3::FrameReader.new(max_payload:)
    items = []
    take = lambda do |item|
      if item.is_a?(Frame::Data) && items.last.is_a?(Frame::Data)
        items[-1] = Frame::Data.new(data: items.last.data + item.data)
      else
        items << item
      end
    end
    offset = 0
    [*cuts.sort, bytes.bytesize].each do |cut|
      reader.feed(bytes.byteslice(offset...cut) || "".b, &take) if cut > offset
      offset = [offset, cut].max
    end
    items
  rescue Frame::Malformed
    items << :malformed
  end

  # Takes all a connection gives, as a transport and an application
  # would: how many times it asked to close. Once closed, it sends nothing.
  private def drain(connection)
    closes = actions(connection, priorities: true).grep(HTTP3::Action::Close).size
    connection.each_event { nil }
    sending = sent(connection)
    connection.each_datagram_send { nil }
    assert_empty sending if connection.closed?
    closes
  end

  # One to four frames of random kinds and values.
  private def frames(rng)
    Array.new(rng.rand(1..4)) do
      case rng.rand(9)
      when 0 then Frame.encode(Frame::Data.new(data: rng.bytes(rng.rand(0..20))))
      when 1 then Frame.encode(Frame::Headers.new(field_section: rng.rand(2).zero? ? section(rng) : rng.bytes(rng.rand(0..20))))
      when 2 then Frame.encode(Frame::Settings.new(settings: Array.new(rng.rand(0..3)) { [rng.rand(0..0x40), rng.rand(0..70_000)] }))
      when 3 then Frame.encode(Frame::GoAway.new(id: rng.rand(0..64)))
      when 4 then Frame.encode(Frame::MaxPushId.new(push_id: rng.rand(0..64)))
      when 5 then Frame.encode(Frame::CancelPush.new(push_id: rng.rand(0..64)))
      when 6 then Frame.encode(Frame::PriorityUpdate.new(element_id: rng.rand(0..64), priority: ["u=1", "i", "u=9, i=?0", rng.bytes(4)].sample(random: rng), push: rng.rand(2).zero?))
      else Frame.header(OTHER_TYPES.sample(random: rng), (payload = rng.bytes(rng.rand(0..20))).bytesize) << payload
      end
    end.join
  end

  private def section(rng, fields = GET)
    QPACK::Encoder.new.encode(0, (fields + Array.new(rng.rand(0..2)) { [rng.bytes(rng.rand(1..6)), rng.bytes(rng.rand(0..10))] }).map { QPACK::Field.new(name: _1, value: _2) })
  end

  # A request, which may be Extended CONNECT or wait on the encoder
  # stream, its content, and trailers or random frames.
  private def request(rng)
    field_section = rng.rand(4).zero? ? BLOCKED : section(rng, [GET, CONNECT].sample(random: rng))
    after = [frames(rng), Frame.encode(Frame::Headers.new(field_section: section(rng, [["x-checksum", "1"]]))), "".b].sample(random: rng)
    Frame.encode(Frame::Headers.new(field_section:)) + Frame.encode(Frame::Data.new(data: rng.bytes(rng.rand(0..20)))) + after
  end

  private def response(rng)
    Frame.encode(Frame::Headers.new(field_section: section(rng, [[":status", ["103", "200", "204"].sample(random: rng)]]))) +
      Frame.encode(Frame::Data.new(data: rng.bytes(rng.rand(0..20))))
  end

  private def mutate(rng, bytes)
    bytes = bytes.b
    case rng.rand(4)
    when 0
      bytes.setbyte(rng.rand(bytes.bytesize), rng.rand(256)) unless bytes.empty?
      bytes
    when 1 then bytes.byteslice(0, rng.rand(0..bytes.bytesize)).to_s
    when 2 then bytes + rng.bytes(rng.rand(1..10))
    else bytes
    end
  end

  # Runs the block ITERATIONS times; an exception from it fails with the
  # iteration to rerun.
  private def run_fuzz(label)
    rng = Random.new(SEED)
    ITERATIONS.times do |iteration|
      yield rng
    rescue Minitest::Assertion
      raise
    rescue => error
      flunk "#{label} seed=#{SEED} iteration=#{iteration}: #{error.class}: #{error.message}\n#{error.backtrace&.first(8)&.join("\n")}"
    end
  end
end
