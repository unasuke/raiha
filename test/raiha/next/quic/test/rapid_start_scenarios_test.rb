require "raiha/next/test_helper"
require "raiha/next/support/quic_transfer"

# Rapid Start over a bottleneck (the congestion control design's "Tests"):
# a download ends sooner than with CUBIC's own slow start, and once the
# first recovery period is over the path goes on with CUBIC.
class RaihaNextQUICTestRapidStartScenariosTest < Minitest::Test
  include NextQUICTransfer

  RapidStart = QUIC::Congestion::Startup::RapidStart

  # A download of `size` over 50 Mbps with 25 ms each way and a queue of
  # 300 KB: when it ended, and the server's connection.
  def download_with(size, **config)
    path = Test::Bottleneck.new(bandwidth: 50_000_000, delay: 0.025, queue: 300_000)
    net, _client, server, reads = download(size, model: path, server_config: QUIC::Config.new(**config))
    assert net.run_until(within: 30.0) { reads.last&.last == size }
    [reads.last.first, server.connections.first, net]
  end

  # 1 MB goes before the queue overflows: growing three times a round trip
  # while no queue builds up, Rapid Start ends it in 0.44 s, where CUBIC's
  # own slow start takes 0.51.
  def test_sooner_than_slow_start
    slow_start, = download_with(1_000_000)
    rapid_start, = download_with(1_000_000, startup: RapidStart)
    assert_operator rapid_start, :<, slow_start * 0.9
  end

  # 5 MB overflows the queue: the first recovery period ends, and the path
  # takes CUBIC back.
  def test_cubic_after_the_first_recovery
    _time, connection, net = download_with(5_000_000, startup: RapidStart)
    net.run_until(within: 1.0) { false }
    assert_operator connection.stats.packets_lost, :>, 0
    assert_kind_of QUIC::Congestion::Cubic, connection.path.congestion
  end
end
