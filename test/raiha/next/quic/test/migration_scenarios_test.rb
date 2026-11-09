require "raiha/next/test_helper"
require "raiha/next/support/quic_transfer"

# Loss recovery's design, "the scenarios on virtual time": a NAT binds the
# client's address anew in the middle of a download, and drops what comes
# to the address before. Each path counts its own bytes in flight and has
# its own congestion controller, so what the server had in flight to the
# old address does not hold the new path back, and its loss does not
# shrink the new path's window (RFC 9000 "Loss Detection and Congestion
# Control"). The client's windows are wide enough that flow control never
# holds the server back.
class RaihaNextQUICTestMigrationScenariosTest < Minitest::Test
  include NextQUICTransfer

  WIDE = QUIC::Config.new(initial_max_data: 16 << 20, initial_max_stream_data_bidi_local: 16 << 20,
    max_stream_receive_window: 16 << 20, max_receive_window: 24 << 20)

  SIZE = 2_000_000

  # Keeps each datagram that passes, with the time, and passes it on at
  # once.
  class Tap < Data.define(:log)
    def start(random:) = State.new(log)

    class State
      def initialize(log)
        @log = log
        @queue = []
      end

      def submit(datagram, now:)
        @log << [now, datagram]
        @queue << datagram
      end

      def each_delivery(now:)
        queue = @queue
        @queue = []
        queue.each { |datagram| yield datagram }
      end

      def next_timeout = nil
    end
  end

  # Downloads SIZE bytes through 10 Mbps and 20 ms each way, keeping what
  # the server sends. Once the client has read 1 MB, the NAT binds its
  # address to `outside`, and the client writes on a stream of its own so
  # that something leaves from there; it runs until the server has moved to
  # the new path and validated it. Gives the network, the server's
  # connection, its path before, the client's reads and what the server
  # sent, as [time, datagram].
  def move(outside)
    path = QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 200_000)
    sent = []
    net, client, server, reads = download(SIZE, forward: path, reverse: [Tap.new(sent), path], client_config: WIDE)
    assert net.run_until { reads.last&.last.to_i >= 1_000_000 }
    connection = server.connections.first
    old = connection.path
    net.rebind(CLIENT, to: outside)
    client.stream_write(client.open_stream || flunk, "here", fin: true)
    assert net.run_until { !connection.path.equal?(old) && connection.path.validated? }
    [net, connection, old, reads, sent]
  end

  # The port alone, or the address too: when the new path is validated,
  # the old one still has more in flight than is left of the new path's
  # window, yet the server sends ten datagrams on the new path at once, as
  # many as its window lets go. The old path's packets lost, the old
  # path's controller goes into recovery and the new path's window stays;
  # the download ends.
  def test_a_new_binding_mid_download
    { port: ["192.0.2.1", 61_000], address: ["203.0.113.7", 61_000] }.each do |name, outside|
      net, connection, old, reads, sent = move(outside)
      new = connection.path
      assert_operator old.bytes_in_flight, :>, new.window - new.bytes_in_flight, name
      assert_operator sent.count { |time, datagram| time == net.now && datagram.destination == outside }, :>=, 10, name
      window = new.window
      assert net.run_until { old.congestion.state == :recovery }, name
      assert_operator new.window, :>=, window, name
      assert net.run_until(within: 20.0) { reads.last.last == SIZE }, name
    end
  end
end
