require "test_helper"
require "support/quic_transfer"
require "support/quic_recovery"

# The delivery rate a server's path reports in qlog while it sends over a
# bottleneck, held back by its window: about the bottleneck's bandwidth.
class RaihaNextQUICTestDeliveryRateScenariosTest < Minitest::Test
  include NextQUICTransfer

  # A download of 2 MB over 10 Mbps with 10 ms each way: the delivery rates
  # the server reported, bits a second.
  def test_about_the_bottleneck
    tracer = NextQUICRecovery::RecordingTracer.new
    path = Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.01, queue: 100_000)
    net, _client, _server, reads = download(2_000_000, model: path, server_tracer: tracer)
    assert net.run_until(within: 30.0) { reads.last&.last == 2_000_000 }
    rates = tracer.of(:metrics_updated).filter_map { _1[:delivery_rate] }
    refute_empty rates
    assert_in_delta 10_000_000, rates.last, 1_000_000
  end
end
