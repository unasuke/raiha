require "test_helper"
require "support/quic_transfer"
require "support/quic_recovery"

# Congestion control in transfers through a Test::Bottleneck, on virtual
# time: each controller fills the path and shrinks its window by its own
# factor, CE marks shrink it as losses do and no more than once a round
# trip, and CUBIC's window does not jump after the sender has been idle.
# The client's windows are wide enough that flow control never holds the
# server back.
class RaihaQUICTestCongestionScenariosTest < Minitest::Test
  include QUICTransfer

  RecordingTracer = QUICRecovery::RecordingTracer

  WIDE = QUIC::Config.new(initial_max_data: 16 << 20, initial_max_stream_data_bidi_local: 16 << 20,
    max_stream_receive_window: 16 << 20, max_receive_window: 24 << 20)

  # The congestion window each time it changed, as [time, bytes].
  def windows(tracer) = tracer.of(:metrics_updated).filter_map { |metrics| metrics.values_at(:now, :congestion_window) if metrics[:congestion_window] }

  # The times the window shrank, and by what factor.
  def cuts(tracer)
    windows(tracer).each_cons(2).filter_map { |(_, before), (time, after)| [time, after.fdiv(before)] if after < before }
  end

  # Bits a second from the first read to the last.
  def rate(reads) = reads.last.last * 8 / (reads.last.first - reads.first.first)

  # 10 Mbps and 20 ms each way, with a queue of a little more than the
  # bandwidth-delay product that drops what overflows it: each controller
  # loses packets, shrinks its window by its factor, and goes at more than
  # 90 % of the bandwidth.
  def test_a_bulk_transfer
    { cubic: 0.7, new_reno: 0.5 }.each do |name, beta|
      tracer = RecordingTracer.new(frames: false)
      path = QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 60_000)
      net, _, server, reads = download(4_000_000, model: path, client_config: WIDE,
        server_config: QUIC::Config.new(congestion_control: name), server_tracer: tracer)
      assert net.run_until(within: 10.0) { reads.last&.last == 4_000_000 }, name
      assert_operator server.connections.first.stats.packets_lost, :>, 0, name
      assert_in_delta beta, cuts(tracer).first&.last, 0.001, name
      assert_operator rate(reads), :>, 9_000_000, name
    end
  end

  # A queue that marks CE past 30 KB never fills: nothing is lost, and the
  # window shrinks by CUBIC's factor at most once a round trip, as CE on
  # what went before the recovery period began shrinks it no more.
  def test_ce_marks
    tracer = RecordingTracer.new(frames: false)
    path = QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 200_000, ce_threshold: 30_000)
    net, _, server, reads = download(4_000_000, model: path, client_config: WIDE, server_tracer: tracer)
    assert net.run_until(within: 10.0) { reads.last&.last == 4_000_000 }
    connection = server.connections.first
    assert_equal [0, :capable], [connection.stats.packets_lost, connection.path.ecn_state]
    cuts = cuts(tracer)
    assert_operator cuts.size, :>, 1
    cuts.each { |_, factor| assert_in_delta 0.7, factor, 0.001 }
    assert cuts.each_cons(2).all? { |(earlier, _), (later, _)| later - earlier >= connection.stats.min_rtt }
    assert_operator rate(reads), :>, 9_000_000
  end

  # The client asks for 2.5 MB, then, 10 seconds after it has all of it,
  # for 1 MB more. CUBIC was in congestion avoidance when the server ran out
  # of data; as its clock stood still while nothing went, its window a
  # tenth of a second after the second request is within 5 % of where it
  # stood.
  def test_idle_for_seconds
    tracer = RecordingTracer.new(frames: false)
    sizes = [2_500_000, 1_000_000]
    requests = []
    ended = []
    ask_at = nil
    client_step = lambda do |client, now|
      next unless client.handshake_confirmed?
      if requests.empty? || (requests.size == 1 && ask_at && now >= ask_at)
        requests << client.open_stream
        client.stream_write(requests.last || flunk, sizes.fetch(requests.size - 1).to_s, fin: true)
      end
      requests.each do |stream_id|
        next if ended.include?(stream_id) || !drain(client, stream_id).last
        ended << stream_id
        ask_at ||= now + 10.0
      end
    end
    left = {}
    server_step = lambda do |server, _now|
      server.connections.each do |connection|
        next unless connection.handshake_complete? && !connection.closing? && !connection.draining? && !connection.closed?
        connection.readable_streams.to_a.each do |stream_id|
          asked, done = drain(connection, stream_id)
          left[stream_id] = Integer(asked) if done
        end
        left.each do |stream_id, bytes|
          while bytes.positive?
            chunk = [bytes, 65_536].min
            taken = connection.stream_write(stream_id, "x".b * chunk, fin: chunk == bytes)
            bytes -= taken
            break if taken < chunk
          end
          left[stream_id] = bytes
        end
      end
    end
    path = QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 150_000)
    net, = transfer_network(model: path, client_config: WIDE, server_tracer: tracer, client_wake: -> { ask_at if requests.size == 1 },
      client_step:, server_step:)
    assert net.run_until(within: 30.0) { ended.size == 2 }
    resumed = ask_at || flunk
    idle_from = resumed - 10.0
    states = tracer.of(:congestion_state_updated).select { _1[:now] <= idle_from && _1[:new] != :application_limited }
    assert_includes %i[reno_friendly concave convex], states.last&.fetch(:new)
    windows = windows(tracer)
    before = windows.select { |time, _| time <= idle_from }.last&.last || flunk
    after = windows.select { |time, _| time > resumed && time <= resumed + 0.1 }.last&.last || flunk
    assert_operator after, :<=, before * 1.05
  end
end
