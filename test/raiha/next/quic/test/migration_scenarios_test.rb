require "raiha/next/test_helper"
require "raiha/next/support/quic_transfer"
require "raiha/next/support/quic_recovery"

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

  PREFERRED = ["192.0.2.2", 4434].freeze

  PROBING = [QUIC::Wire::Frame::PathChallenge, QUIC::Wire::Frame::PathResponse, QUIC::Wire::Frame::Padding].freeze

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

  # Downloads SIZE bytes through 10 Mbps and 20 ms each way from a server
  # that offers PREFERRED as its preferred address, at `addresses` besides
  # SERVER, to a client that issues connection IDs, keeping what the client
  # sends and its tracer's events. Gives the network, the client, the
  # server, the client's reads, what it sent as [time, datagram], its
  # tracer, and when the handshake was confirmed.
  def offered(addresses, client_config: WIDE)
    path = QUIC::Test::Bottleneck.new(bandwidth: 10_000_000, delay: 0.02, queue: 200_000)
    sent = []
    tracer = NextQUICRecovery::RecordingTracer.new
    random = Random.new(9)
    issuer = QUIC::Endpoint::Issuer.new(->(_connection) { [random.bytes(8), random.bytes(16)] }, ->(_connection_id) {})
    net, client, server, reads = download(SIZE, forward: [Tap.new(sent), path], reverse: path, client_config:, client_tracer: tracer,
      client_issuer: issuer, server_config: QUIC::Config.new(preferred_address: { ipv4: PREFERRED }), server_addresses: addresses)
    assert net.run_until { client.handshake_confirmed? }
    [net, client, server, reads, sent, tracer, net.now]
  end

  # The ID of the preferred address the server's transport parameters gave.
  def preferred_id(tracer) = tracer.of(:parameters_set).find { _1[:owner] == :remote }[:parameters].preferred_address.connection_id

  # The frames of the packets the client sent with `dcid` before `time`.
  def frames_with(tracer, dcid, before:)
    tracer.of(:packet_sent).select { _1[:header].dcid == dcid && _1[:now] < before }.flat_map { _1[:frames] }
  end

  # RFC 9000 "Migration to a Preferred Address": once the handshake is
  # confirmed and one of its IDs acknowledged, a round trip on, the client
  # validates a path to the preferred address with the ID that came with
  # it, sending nothing but probes there, and moves to it once validated;
  # the server follows, and the download ends.
  def test_a_move_to_the_preferred_address
    net, client, server, reads, sent, tracer, confirmed_at = offered([PREFERRED])
    assert net.run_until { client.path.remote == PREFERRED }
    moved_at = net.now
    first_at, first = sent.find { |_, datagram| datagram.destination == PREFERRED }
    assert_operator first_at - confirmed_at, :>=, 0.04
    assert_equal preferred_id(tracer), QUIC::Wire::Packet.parse(first.payload, dcid_length: 8).header.dcid
    probes = frames_with(tracer, preferred_id(tracer), before: moved_at)
    refute_empty probes
    assert probes.all? { |frame| PROBING.any? { frame.is_a?(_1) } }
    assert net.run_until(within: 20.0) { reads.last&.last == SIZE }
    assert_equal PREFERRED, server.connections.first.path.local
  end

  # A client with zero-length connection IDs issues none to wait for: the
  # server answers on any path with none, and the client moves as soon as
  # the handshake is confirmed.
  def test_a_move_with_zero_length_connection_ids
    net, client, _, reads, sent, _, confirmed_at = offered([PREFERRED], client_config: WIDE.with(connection_id_length: 0))
    assert net.run_until { client.path.remote == PREFERRED }
    assert_equal confirmed_at, sent.find { |_, datagram| datagram.destination == PREFERRED }.first
    assert net.run_until(within: 20.0) { reads.last&.last == SIZE }
  end

  # A preferred address that nothing answers at: the download ends where
  # it began, and the client, having sent nothing but probes there,
  # retires the ID it sent with once the validation fails.
  def test_a_preferred_address_that_fails
    net, client, _, reads, _, tracer, = offered([])
    retired = -> { tracer.of(:packet_sent).flat_map { _1[:frames] }.grep(QUIC::Wire::Frame::RetireConnectionID).map(&:sequence_number) }
    assert net.run_until(within: 20.0) { reads.last&.last == SIZE && retired.call.any? }
    assert_equal [[1], SERVER], [retired.call, client.path.remote]
    probes = frames_with(tracer, preferred_id(tracer), before: net.now)
    refute_empty probes
    assert probes.all? { |frame| PROBING.any? { frame.is_a?(_1) } }
  end
end
