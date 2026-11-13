require "test_helper"
require "support/quic_pair"
require "support/quic_recovery"

# The tracer hears each change of the connection IDs in use (qlog
# `connection_id_updated`): the peer's this end sends with, and this end's
# the peer sends with.
class RaihaQUICConnectionConnectionIDTraceTest < Minitest::Test
  include QUICPair

  def updates(tracer) = tracer.of(:connection_id_updated).map { _1.values_at(:owner, :old, :new) }

  # The client takes the server's ID from its first Initial; the server
  # takes the client's next one when Retire Prior To retires the first, and
  # hears the client send with another of the server's IDs.
  def test_the_ids_in_use
    client_tracer = QUICRecovery::RecordingTracer.new(frames: false)
    server_tracer = QUICRecovery::RecordingTracer.new(frames: false)
    keylog = Keylog.new
    client = client_connection(keylog:, tracer: client_tracer, source_connection_id: "c".b * 8)
    server = server_connection(source_connection_id: "s".b * 8, tracer: server_tracer)
    now = handshake(client, server)
    assert_equal [[:remote, "s".b * 8]], updates(client_tracer).map { [_1, _3] }
    assert_empty updates(server_tracer)
    issued = QUIC::Wire::Frame::NewConnectionID.new(sequence_number: 1, retire_prior_to: 1, connection_id: "d".b * 8,
      stateless_reset_token: "t".b * 16)
    server.receive(client_one_rtt(keylog, dcid: "s".b * 8, payload: QUIC::Wire::Frame.encode([issued], ack_delay_exponent: 3),
      packet_number: 900), from: CLIENT, now:)
    server.receive(client_one_rtt(keylog, dcid: "z".b * 8, payload: "\x01".b, packet_number: 901), from: CLIENT, now:)
    assert_equal [[:remote, "c".b * 8, "d".b * 8], [:local, "s".b * 8, "z".b * 8]], updates(server_tracer)
  end
end
