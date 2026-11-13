require "test_helper"
require "support/quic_transfer"
require "support/quic_recovery"
require "digest"

# Flow control in transfers on a Test::Network, on virtual time: the
# window grows to keep a long fat path full, a slow reader stops the
# sender within the windows and the send buffer, credit lost on the way
# does not stall a transfer, and the peer's room for streams comes back
# as streams end. The rejection of 0-RTT comes with 0-RTT.
class RaihaNextQUICTestFlowControlScenariosTest < Minitest::Test
  include NextQUICTransfer

  # The server sends `body` on the stream the client opens with a request,
  # while the client's `reader` takes what it reads; gives the network, the
  # client and the server.
  def serve(body, model:, reader:, server_config: QUIC::Config.new, wake: nil)
    request = nil
    sent = 0
    client_step = lambda do |client, now|
      if client.handshake_confirmed? && request.nil?
        request = client.open_stream
        client.stream_write(request, "GET", fin: true)
      end
      reader.call(client, request, now) if request
    end
    server_step = lambda do |server, _now|
      server.connections.each do |connection|
        next unless connection.handshake_complete? && !connection.closing? && !connection.draining? && !connection.closed?
        @asked ||= connection.readable_streams.include?(0) && drain(connection, 0)
        next unless @asked
        while sent < body.bytesize
          taken = connection.stream_write(0, body.byteslice(sent, 65_536), fin: sent + 65_536 >= body.bytesize)
          sent += taken
          break if taken < 65_536
        end
      end
    end
    transfer_network(model:, server_config:, client_wake: wake, client_step:, server_step:)
  end

  # 100 Mbps and 100 ms, a bandwidth-delay product of 1.25 MB: the
  # stream's window doubles as it is read faster than a quarter of it a
  # round trip, up to its maximum of 6 MiB, and the second half of 8 MB
  # goes near the path's rate.
  def test_a_long_fat_path
    body = "x".b * 8_000_000
    received = []
    widest = 0
    reader = lambda do |client, stream_id, now|
      data, = drain(client, stream_id)
      received << [now, (received.last&.last || 0) + data.bytesize] unless data.empty?
      receiver = client.instance_variable_get(:@streams).instance_variable_get(:@receivers)[stream_id]
      widest = [widest, receiver.window.size].max if receiver
    end
    path = Test::Bottleneck.new(bandwidth: 100_000_000, delay: 0.05, queue: 2_000_000)
    net, client, = serve(body, model: path, reader:)
    assert net.run_until(within: 10.0) { received.last&.last == body.bytesize }
    assert_equal 6 * 1024 * 1024, widest
    assert_operator client.stats.receive_window, :>=, widest * 1.5
    half = received.find { |_, bytes| bytes >= body.bytesize / 2 } || flunk
    rate = (body.bytesize - half.last) * 8 / (received.last.first - half.first)
    assert_operator rate, :>, 70_000_000
  end

  # The client reads 50 KB every 100 ms: the server stops at the stream's
  # credit, sending STREAM_DATA_BLOCKED, and neither end holds more than
  # its window or send buffer.
  def test_a_slow_reader
    body = "y".b * 1_000_000
    total = 0
    next_read = nil
    held = []
    reader = lambda do |client, stream_id, now|
      next_read ||= now
      receiver = client.instance_variable_get(:@streams).instance_variable_get(:@receivers)[stream_id]
      held << [receiver.window.received - receiver.window.consumed, receiver.window.size] if receiver
      next if now < next_read
      next_read = now + 0.1
      chunk = client.stream_read(stream_id, 50_000)
      total += chunk.bytesize if chunk
    end
    path = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 200_000)
    net, client, server = serve(body, model: path, reader:, server_config: QUIC::Config.new(max_send_buffer: 256 * 1024),
      wake: -> { next_read })
    buffers = []
    assert net.run_until(within: 30.0) {
      buffers << server.connections.first&.stats&.send_buffer_bytes.to_i
      total == body.bytesize
    }
    assert_operator server.connections.first.stats.blocked_sent, :>, 0
    assert_operator client.stats.blocked_received, :>, 0
    assert_operator buffers.max, :<=, 256 * 1024
    held.each { |bytes, window| assert_operator bytes, :<=, window }
  end

  # 3 % of datagrams lost and 10 % reordered: credit lost on the way goes
  # again, and the transfer ends whole. The holes in what the client has
  # received stay far from their limit.
  def test_credit_lost_on_the_way
    body = Random.new(5).bytes(1_000_000)
    got = "".b
    holes = 0
    reader = lambda do |client, stream_id, _now|
      holes = [holes, client.instance_variable_get(:@streams).instance_variable_get(:@gaps)].max
      got << drain(client, stream_id).first
    end
    path = [Test::RandomLoss.new(rate: 0.03), Test::Reorder.new(rate: 0.1), Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 200_000)]
    net, client, = serve(body, model: path, reader:, server_config: QUIC::Config.new(initial_max_stream_data_bidi_remote: 64 * 1024,
      initial_max_data: 96 * 1024))
    assert net.run_until(within: 60.0) { got.bytesize == body.bytesize }
    assert_equal Digest::SHA256.digest(body), Digest::SHA256.digest(got)
    assert_operator holes, :>, 0
    assert_operator holes, :<, client.instance_variable_get(:@streams).max_gaps
  end

  # A thousand requests with a hundred streams open at once, answered one
  # a millisecond: the server gives room for more as they end,
  # MAX_STREAMS every twelve or thirteen.
  def test_a_thousand_requests
    tracer = NextQUICRecovery::RecordingTracer.new
    opened = 0
    answered = 0
    client_step = lambda do |client, _now|
      next unless client.handshake_confirmed?
      while opened < 1000 && (stream_id = client.open_stream)
        opened += 1
        client.stream_write(stream_id, "q", fin: true)
      end
      client.readable_streams.to_a.each do |stream_id|
        _, ended = drain(client, stream_id)
        answered += 1 if ended
      end
    end
    asked = []
    next_answer = 0.0
    server_step = lambda do |server, now|
      server.connections.each do |connection|
        connection.readable_streams.to_a.each do |stream_id|
          _, ended = drain(connection, stream_id)
          asked << [connection, stream_id] if ended
        end
      end
      next if asked.empty? || now < next_answer
      connection, stream_id = asked.shift
      connection.stream_write(stream_id, "a", fin: true)
      next_answer = now + 0.001
    end
    wake = -> { asked.empty? ? nil : next_answer }
    net, = transfer_network(client_step:, server_step:, server_tracer: tracer, server_wake: wake)
    assert net.run_until(within: 30.0) { answered == 1000 }
    limits = tracer.of(:packet_sent).flat_map { _1[:frames] || [] }.grep(QUIC::Wire::Frame::MaxStreams).map(&:maximum).uniq
    assert_operator limits.size, :>, 60
    assert limits.each_cons(2).all? { |a, b| (12..13).cover?(b - a) }, limits.inspect
  end
end
