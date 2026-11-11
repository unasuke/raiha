require "raiha/next/test_helper"
require "raiha/next/support/quic_transfer"

# DPLPMTUD on virtual time (RFC 8899): through a path that drops what is
# larger than its MTU, each end searches its path once the handshake is
# confirmed, and sends as large as it found from then on.
class RaihaNextQUICTestPMTUDScenariosTest < Minitest::Test
  include NextQUICTransfer

  SIZE = 1_000_000

  # Drops each datagram larger than `mtu` bytes, and passes the rest on at
  # once.
  class MTU < Data.define(:mtu)
    def start(random:) = State.new(mtu)

    class State
      def initialize(mtu)
        @mtu = mtu
        @queue = []
      end

      def submit(datagram, now:) = (@queue << datagram if datagram.payload.bytesize <= @mtu)

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { |datagram| yield datagram }
      end

      def next_timeout = nil
    end
  end

  # 10 Mbps and 20 ms each way, dropping what is larger than `mtu`.
  def path(mtu) = [MTU.new(mtu), QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 200_000)]

  # The largest, 1472, is lost three times; then halfway between, 1336
  # gets through, 1404 is lost three times, 1370 and 1387 get through, 17
  # bytes short of what did not: each end sends 1387 bytes from then on,
  # the client, which sends little but ACKs, once its PTOs have told it of
  # its probes lost.
  def test_each_end_finds_the_mtu
    net, client, server, reads = download(SIZE, model: path(1400))
    assert net.run_until(within: 20.0) { reads.last&.last == SIZE }
    sizes = -> { [client.path.max_datagram_size, server.connections.first.path.max_datagram_size] }
    assert net.run_until(within: 10.0) { sizes.call == [1387, 1387] }, sizes.call.inspect
  end

  # With enable_pmtud false, nothing is searched.
  def test_no_search
    config = QUIC::Config.new(enable_pmtud: false)
    net, client, server, reads = download(SIZE, model: path(1500), client_config: config, server_config: config)
    assert net.run_until(within: 20.0) { reads.last&.last == SIZE }
    assert_equal [1200, 1200], [client.path.max_datagram_size, server.connections.first.path.max_datagram_size]
  end
end
