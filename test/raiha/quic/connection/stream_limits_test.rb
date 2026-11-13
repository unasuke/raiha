require "test_helper"
require "support/quic_pair"
require "stringio"
require "json"

# The peer's limits on what a Connection sends: a write cut short by them
# tells the peer with a BLOCKED frame, and goes on once MAX_DATA or
# MAX_STREAM_DATA comes.
class RaihaNextQUICConnectionStreamLimitsTest < Minitest::Test
  include NextQUICPair

  # A client and a server done with the handshake and confirmed on both
  # ends, and the time then.
  def connected(server_config: QUIC::Config.new)
    @keylog = Keylog.new
    client = client_connection(keylog: @keylog)
    server = server_connection(config: server_config)
    now = exchange(client, server, now: handshake(client, server), rounds: 3)
    [client, server].each { |connection| connection.each_event { nil } }
    [client, server, now]
  end

  def exchange(client, server, now:, rounds: 10)
    rounds.times do
      client.transmits(now:).each { |transmit| server.receive(transmit.payload, from: CLIENT, now:) }
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now:) }
      now += 0.01
    end
    now
  end

  # The frames of the client's 1-RTT packets now, which go nowhere.
  def client_frames(client, now:)
    keys = one_rtt_keys(@keylog, "CLIENT_TRAFFIC_SECRET_0")
    client.transmits(now:).flat_map do |transmit|
      unmasked = QUIC::Wire::Packet.parse(transmit.payload, dcid_length: 8).unmask(keys.header_protection, largest: nil)
      QUIC::Wire::Frame.parse(unmasked.open(keys.aead).to_s, packet_type: :one_rtt, ack_delay_exponent: 3)
    end
  end

  def events(connection) = [].tap { |all| connection.each_event { all << _1 } }

  def read_all(connection, stream_id)
    data = "".b
    while (chunk = connection.stream_read(stream_id, 100_000)) && !chunk.empty?
      data << chunk
    end
    data
  end

  # The stream's credit cuts the write short: STREAM_DATA_BLOCKED goes
  # with the limit, once; the peer reads, MAX_STREAM_DATA comes, and the
  # stream can take more.
  def test_the_stream_limit
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_stream_data_bidi_remote: 1000))
    stream_id = client.open_stream
    assert_equal 1000, client.stream_write(stream_id, "x" * 5000)
    assert_equal 0, client.stream_write(stream_id, "x" * 5000)
    blocked = client_frames(client, now:).grep(QUIC::Wire::Frame::StreamDataBlocked)
    assert_equal [QUIC::Wire::Frame::StreamDataBlocked.new(stream_id:, maximum: 1000)], blocked
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_stream_data_bidi_remote: 1000))
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 5000)
    now = exchange(client, server, now:)
    assert_equal 1000, read_all(server, stream_id).bytesize
    exchange(client, server, now:)
    assert_equal [QUIC::Event::StreamWritable.new(stream_id:)], events(client)
    assert_equal 1000, client.stream_writable_bytes(stream_id)
  end

  # The connection's credit cuts a write short: DATA_BLOCKED, then MAX_DATA.
  def test_the_connection_limit
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_data: 2000))
    first = client.open_stream
    second = client.open_stream
    assert_equal 1500, client.stream_write(first, "a" * 1500)
    assert_equal 500, client.stream_write(second, "b" * 1500)
    assert_includes client_frames(client, now:), QUIC::Wire::Frame::DataBlocked.new(maximum: 2000)
    client, server, now = connected(server_config: QUIC::Config.new(initial_max_data: 2000))
    first = client.open_stream
    second = client.open_stream
    client.stream_write(first, "a" * 1500)
    client.stream_write(second, "b" * 1500)
    now = exchange(client, server, now:)
    assert_equal [1500, 500], [read_all(server, first).bytesize, read_all(server, second).bytesize]
    exchange(client, server, now:)
    assert_includes events(client), QUIC::Event::StreamWritable.new(stream_id: second)
  end

  # This end's own send buffer is no peer's limit: no BLOCKED frame.
  def test_no_blocked_frame_for_the_send_buffer
    @keylog = Keylog.new
    client = client_connection(keylog: @keylog, config: QUIC::Config.new(max_send_buffer: 1000))
    server = server_connection
    now = exchange(client, server, now: handshake(client, server), rounds: 3)
    stream_id = client.open_stream
    assert_equal 1000, client.stream_write(stream_id, "x" * 5000)
    assert_empty client_frames(client, now:).grep(QUIC::Wire::Frame::DataBlocked) + client_frames(client, now:).grep(QUIC::Wire::Frame::StreamDataBlocked)
  end

  # The peer allows two streams: the third does not open, and
  # STREAMS_BLOCKED tells it so, once.
  def test_the_stream_count
    client, _, now = connected(server_config: QUIC::Config.new(initial_max_streams_bidi: 2))
    2.times { refute_nil client.open_stream }
    assert_nil client.open_stream
    assert_nil client.open_stream
    assert_equal [QUIC::Wire::Frame::StreamsBlocked.new(bidirectional: true, maximum: 2)],
      client_frames(client, now:).grep(QUIC::Wire::Frame::StreamsBlocked)
  end

  # Keeps what it hears of flow control blocking.
  class BlockedTracer
    include Raiha::QUIC::Tracer

    attr_reader :log

    def initialize = @log = []

    def connection_data_blocked_updated(old:, new:, reason:, now:) = @log << [:connection, new, reason]

    def stream_data_blocked_updated(stream_id:, old:, new:, reason:, now:) = @log << [stream_id, new, reason]
  end

  # The tracer hears when the peer's credit blocks the connection or a
  # stream, and when the limit grows past it; a qlog writes both.
  def test_the_tracer_hears_of_blocking
    tracer = BlockedTracer.new
    @keylog = Keylog.new
    client = client_connection(keylog: @keylog, tracer:)
    server = server_connection(config: QUIC::Config.new(initial_max_stream_data_bidi_remote: 1000, initial_max_data: 1500))
    now = exchange(client, server, now: handshake(client, server), rounds: 3)
    first = client.open_stream
    second = client.open_stream
    client.stream_write(first, "a" * 2000)
    client.stream_write(second, "b" * 2000)
    assert_equal [[first, :blocked, :stream_flow_control], [:connection, :blocked, :connection_flow_control]], tracer.log
    now = exchange(client, server, now:)
    read_all(server, first)
    read_all(server, second)
    exchange(client, server, now:)
    assert_includes tracer.log, [first, :unblocked, :stream_flow_control]
    assert_includes tracer.log, [:connection, :unblocked, :connection_flow_control]
    io = StringIO.new
    qlog = QUIC::Qlog::Tracer.new(io, vantage_point: :client)
    qlog.stream_data_blocked_updated(stream_id: 0, old: :unblocked, new: :blocked, reason: :stream_flow_control, now: 1.0)
    record = JSON.parse(io.string.split("\x1e").last)
    assert_equal ["quic:stream_data_blocked_updated", { "old" => "unblocked", "new" => "blocked", "stream_id" => 0, "reason" => "stream_flow_control" }],
      record.values_at("name", "data")
  end
end
