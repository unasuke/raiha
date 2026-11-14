require "test_helper"
require "support/quic_pair"
require "support/quic_recovery"

# The tracer hears how the paths stand (qlog `migration_state_updated`): a
# path besides the one in use as it is validated, and one the server moves
# to.
class RaihaQUICConnectionMigrationTraceTest < Minitest::Test
  include QUICPair

  NEW = ["198.51.100.7", 61_000].freeze

  # A server done with the handshake and given three more IDs of the
  # client's, its tracer, the client's key log, and the time.
  def connected
    tracer = QUICRecovery::RecordingTracer.new
    keylog = Keylog.new
    client = client_connection(keylog:)
    server = server_connection(source_connection_id: "s".b * 8, tracer:)
    now = handshake(client, server)
    issued = (1..3).map do |sequence_number|
      QUIC::Wire::Frame::NewConnectionID.new(sequence_number:, retire_prior_to: 0, connection_id: format("c%07d", sequence_number).b,
        stateless_reset_token: format("%016d", sequence_number).b)
    end
    server.receive(packet(keylog, *issued, number: 900), from: CLIENT, now:)
    server.transmits(now:)
    [server, tracer, keylog, now]
  end

  def packet(keylog, *frames, number:)
    client_one_rtt(keylog, dcid: "s".b * 8, payload: QUIC::Wire::Frame.encode(frames, ack_delay_exponent: 3), packet_number: number)
  end

  # The data of the PATH_CHALLENGE the server sent to `to` at `now`.
  def challenge(server, keylog, now, to:)
    server.transmits(now:).filter_map do |transmit|
      next unless transmit.destination == to
      server_one_rtt(keylog, transmit.payload, phase: 0)&.last&.grep(QUIC::Wire::Frame::PathChallenge)&.first&.data
    end.first
  end

  def states(tracer) = tracer.of(:migration_state_updated).map { _1.values_at(:state, :remote) }

  # A probe from a new address starts the path's validation, and the
  # answer to the server's full-size challenge ends it.
  def test_a_path_probed
    server, tracer, keylog, now = connected
    probe = [QUIC::Wire::Frame::PathChallenge.new(data: "abcdefgh".b), QUIC::Wire::Frame::Padding.new(length: 1200)]
    server.receive(packet(keylog, *probe, number: 1000), from: NEW, now:)
    data = challenge(server, keylog, now, to: NEW)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data:), number: 1001), from: NEW, now:)
    assert_equal [[:probing_started, NEW], [:probing_successful, NEW]], states(tracer)
  end

  # A packet that is no probe from a new address moves the server there,
  # and the path left is validated again; the answer to the new path's
  # challenge completes the move. The path left, its challenge
  # unanswered, is abandoned.
  def test_a_move
    server, tracer, keylog, now = connected
    server.receive(packet(keylog, QUIC::Wire::Frame::Ping.new, number: 1000), from: NEW, now:)
    data = challenge(server, keylog, now, to: NEW)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data:), number: 1001), from: NEW, now:)
    data = challenge(server, keylog, now, to: NEW)
    server.receive(packet(keylog, QUIC::Wire::Frame::PathResponse.new(data:), number: 1002), from: NEW, now:)
    assert_equal [[:migration_started, NEW], [:probing_started, CLIENT], [:migration_complete, NEW]], states(tracer)
    server.handle_timeout(now: now += 10.0)
    assert_equal [:probing_abandoned, CLIENT], states(tracer).last
  end
end
