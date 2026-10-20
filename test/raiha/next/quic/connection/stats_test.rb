require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

# What `Connection#stats` gives: the path's RTT and window, the packets and
# bytes each way, the handshake's time, and flow control's numbers.
class RaihaNextQUICConnectionStatsTest < Minitest::Test
  include NextQUICPair

  def exchange(client, server, now:, rounds: 10)
    rounds.times do
      client.transmits(now:).each do |transmit|
        @client_bytes += transmit.payload.bytesize
        server.receive(transmit.payload, from: CLIENT, now:)
      end
      server.transmits(now:).each { |transmit| client.receive(transmit.payload, from: SERVER, now: now + 0.005) }
      now += 0.01
    end
    now
  end

  def test_before_the_handshake
    stats = client_connection.stats
    assert_nil stats.handshake_duration
    assert_nil stats.min_rtt
    assert_equal [0, 0, 0.333, 12_000, 1200], [stats.packets_sent, stats.packets_received, stats.rtt, stats.congestion_window, stats.path_mtu]
    assert_equal 768 * 1024, stats.receive_window
  end

  def test_after_a_transfer
    @client_bytes = 0
    client = client_connection
    server = server_connection(config: QUIC::Config.new(initial_max_stream_data_bidi_remote: 1000))
    now = exchange(client, server, now: 0.0, rounds: 5)
    stream_id = client.open_stream
    client.stream_write(stream_id, "x" * 5000)
    assert_equal 1000, client.stats.send_buffer_bytes
    exchange(client, server, now:)
    stats = client.stats
    assert_in_delta 0.005, stats.handshake_duration, 1e-9
    refute_nil stats.min_rtt
    assert_equal @client_bytes, stats.bytes_sent
    assert_equal server.stats.bytes_received, stats.bytes_sent
    assert_equal server.stats.packets_received, stats.packets_sent
    assert_equal [0, 1], [stats.send_buffer_bytes, stats.blocked_sent]
    assert_equal 1, server.stats.blocked_received
    assert_equal 0, stats.packets_lost
  end
end
