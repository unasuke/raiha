require "raiha/next/test_helper"
require "raiha/next/support/quic_transfer"

# Pacing over a bottleneck (the congestion control design's "Tests"): the
# granularity the pacer wakes at changes how often it sends, not how much
# goes or how fast the transfer ends.
class RaihaNextQUICTestPacingScenariosTest < Minitest::Test
  include NextQUICTransfer

  SIZE = 1_000_000

  # A window of a hundred datagrams, far above what RFC 9002 lets go in a
  # burst, so that the pacer, not the window, holds the server back.
  WIDE = Ractor.shareable_lambda { |max_datagram_size| 100 * max_datagram_size }

  # A download of SIZE over 1 Gbps with 50 ms each way and room in the queue
  # for all of it: when it ended and the bytes the server sent.
  def download_with(granularity)
    path = Test::Bottleneck.new(bandwidth: 1_000_000_000, delay: 0.05, queue: 10_000_000)
    config = QUIC::Config.new(initial_window: WIDE, pacing_granularity: granularity)
    net, _client, server, reads = download(SIZE, model: path, server_config: config)
    assert net.run_until(within: 30.0) { reads.last&.last == SIZE }
    [reads.last.first, server.connections.first.stats.bytes_sent]
  end

  def test_the_granularity_changes_neither_how_much_nor_how_fast
    fine_time, fine_bytes = download_with(0.001)
    [0.004, 0.02].each do |granularity|
      time, bytes = download_with(granularity)
      assert_in_delta fine_time, time, fine_time * 0.1
      assert_in_delta fine_bytes, bytes, fine_bytes * 0.05
    end
  end
end
