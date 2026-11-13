require "test_helper"
require "raiha/quic"

# Flow control's invariants over random runs of what a peer and an
# application do: data received on the client's streams, reads, STOP_SENDING,
# RESET_STREAM, and time passing as credit goes out. After every step: no
# limit told goes down; what is consumed is at most what is received, and
# that at most the limit, on each stream and on the connection; the
# connection has received the sum of what each stream has; no window
# shrinks or grows past its maximum; and the holes are within their limit. The
# frames are ones the peer may send, as the rules broken are tried
# elsewhere. A run that breaks one is kept as a case of its own, with its
# seed. RAIHA_FLOW_SEEDS (default 30) and RAIHA_FLOW_STEPS (default 300)
# change how many runs and how long.
class RaihaNextQUICStreamsInvariantsTest < Minitest::Test
  QUIC = Raiha::Next::QUIC
  SEEDS = Integer(ENV.fetch("RAIHA_FLOW_SEEDS", "30"))
  STEPS = Integer(ENV.fetch("RAIHA_FLOW_STEPS", "300"))
  CONFIG = QUIC::Config.new(initial_max_data: 8000, initial_max_stream_data_bidi_local: 3000, initial_max_stream_data_bidi_remote: 3000,
    initial_max_stream_data_uni: 3000, max_stream_receive_window: 12_000, max_receive_window: 18_000, initial_max_streams_bidi: 4,
    initial_max_streams_uni: 4)
  # The client's bidirectional streams, which stay as the server never ends
  # its sending part, and its unidirectional ones, let go once over.
  STREAMS = [0, 4, 8, 12, 2, 6, 10, 14].freeze

  def test_random_runs
    SEEDS.times { |seed| run_steps(seed) }
  end

  def run_steps(seed)
    rng = Random.new(seed)
    streams = QUIC::Streams.new(role: :server, config: CONFIG, events: [], now: 0.0)
    # How far each stream has been received, and its final size, as the
    # peer knows them; the limits last seen.
    received = Hash.new(0)
    finals = {}
    limits = {}
    sizes = {}
    now = 0.0
    seen = []
    STEPS.times do |step|
      receivers = streams.instance_variable_get(:@receivers)
      seen |= receivers.keys
      stream_id = STREAMS.sample(random: rng)
      receiver = receivers[stream_id]
      # A stream let go hears nothing more that counts.
      next if receiver.nil? && seen.include?(stream_id)
      case rng.rand(10)
      when 0..4 then receive(streams, receiver, stream_id, rng, received, finals, now)
      when 5..6 then streams.read(stream_id, rng.rand(1..2000)) if receiver
      when 7 then streams.stop_sending(stream_id, 0) if receiver && rng.rand(4).zero?
      when 8 then reset(streams, receiver, stream_id, rng, received, finals, now) if rng.rand(4).zero?
      else
        now += rng.rand * 0.05
        while streams.next_credit(100, now:, rtt: 0.01)
        end
      end
      check(streams, received, limits, sizes, "seed #{seed}, step #{step}")
    end
  end

  # Data on `stream_id` that keeps to its limit, the connection's and its
  # final size.
  def receive(streams, receiver, stream_id, rng, received, finals, now)
    limit = receiver&.window&.limit || CONFIG.initial_max_stream_data_uni
    room = streams.window.limit - streams.window.received
    final = finals[stream_id]
    finish = [final || limit, received[stream_id] + room].min
    start = [rng.rand(0..finish), (receiver&.read_offset || 0)].max
    return if start > finish
    finish = [finish, start + rng.rand(0..1500)].min
    fin = final ? finish == final : rng.rand(20).zero? && finish >= received[stream_id]
    streams.receive_stream(QUIC::Wire::Frame::Stream.new(stream_id:, offset: start, data: "x".b * (finish - start), fin:), now:)
    received[stream_id] = [received[stream_id], finish].max
    finals[stream_id] = finish if fin
  end

  # The peer resets `stream_id` with a final size that keeps to the limits.
  def reset(streams, receiver, stream_id, rng, received, finals, now)
    return unless receiver
    limit = receiver.window.limit
    final = finals[stream_id] || [received[stream_id] + rng.rand(0..200), limit, received[stream_id] + streams.window.limit - streams.window.received].min
    streams.receive_reset_stream(QUIC::Wire::Frame::ResetStream.new(stream_id:, error_code: 0, final_size: final), now:)
    received[stream_id] = [received[stream_id], final].max
    finals[stream_id] = final
  end

  def check(streams, received, limits, sizes, where)
    windows = streams.instance_variable_get(:@receivers).to_h { |stream_id, receiver| [stream_id, receiver.window] }
    windows[:connection] = streams.window
    windows.each do |key, window|
      assert_operator window.limit, :>=, limits.fetch(key, 0), "#{where}: the limit of #{key} went down"
      assert_operator window.consumed, :<=, window.received, "#{where}: #{key} consumed more than it received"
      assert_operator window.received, :<=, window.limit, "#{where}: #{key} received past its limit"
      assert_operator window.size, :>=, sizes.fetch(key, 0), "#{where}: the window of #{key} shrank"
      maximum = key == :connection ? CONFIG.max_receive_window : CONFIG.max_stream_receive_window
      assert_operator window.size, :<=, maximum, "#{where}: the window of #{key} grew past its maximum"
      limits[key] = window.limit
      sizes[key] = window.size
    end
    assert_equal received.values.sum, streams.window.received, "#{where}: the connection's count is not the streams' sum"
    assert_operator streams.instance_variable_get(:@gaps), :<=, streams.max_gaps, where
  end
end
