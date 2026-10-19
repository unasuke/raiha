require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"
require "raiha/next/support/quic_recovery"

# RFC 9000 "Authenticating Connection IDs": the connection IDs in the
# transport parameters are the ones the Initial packets used.
class RaihaNextQUICConnectionTransportParametersTest < Minitest::Test
  include NextQUICPair

  # A Config whose transport parameters say `claims`, otherwise than the
  # packets.
  def lying(**claims)
    Class.new(QUIC::Config) do
      define_method(:transport_parameters) { |**options| super(**options).with(**claims) }
    end.new
  end

  def run_pair(client_config: QUIC::Config.new, server_config: QUIC::Config.new)
    client = client_connection(config: client_config)
    server = server_connection(config: server_config)
    handshake(client, server)
    [client, server]
  end

  def test_the_client_names_another_source_connection_id
    _client, server = run_pair(client_config: lying(initial_source_connection_id: "x".b * 8))
    assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, server.close_reason&.code
  end

  def test_the_server_names_another_original_destination_connection_id
    client, = run_pair(server_config: lying(original_destination_connection_id: "x".b * 8))
    assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, client.close_reason&.code
  end

  def test_the_server_names_another_source_connection_id
    client, = run_pair(server_config: lying(initial_source_connection_id: "x".b * 8))
    assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, client.close_reason&.code
  end

  # A Retry source connection ID with no Retry.
  def test_the_server_names_a_retry_that_was_not
    client, = run_pair(server_config: lying(retry_source_connection_id: "x".b * 8))
    assert_equal QUIC::ErrorCode::TRANSPORT_PARAMETER_ERROR, client.close_reason&.code
  end

  # A server told of a Retry by its Endpoint names the client's first
  # Destination Connection ID and the Retry's Source Connection ID.
  def test_after_a_retry
    tracer = NextQUICRecovery::RecordingTracer.new
    server = server_connection(original_destination_connection_id: "o".b * 8, retry_source_connection_id: "r".b * 8, tracer:)
    server.receive(client_connection.transmits(now: 0.0).first.payload, from: CLIENT, now: 0.0)
    local = tracer.of(:parameters_set).find { _1[:owner] == :local }[:parameters]
    assert_equal ["o".b * 8, "r".b * 8], [local.original_destination_connection_id, local.retry_source_connection_id]
  end

  # An Endpoint chooses each connection's Source Connection ID, and gives a
  # server the stateless reset token of it, which the transport parameters
  # carry.
  def test_what_an_endpoint_chooses
    tracer = NextQUICRecovery::RecordingTracer.new
    client = client_connection(source_connection_id: "c".b * 8)
    server = server_connection(source_connection_id: "s".b * 8, stateless_reset_token: "t".b * 16, tracer:)
    first = client.transmits(now: 0.0).first.payload
    assert_equal "c".b * 8, QUIC::Wire::Packet.parse(first, dcid_length: 8).header.scid
    server.receive(first, from: CLIENT, now: 0.0)
    assert_equal "s".b * 8, QUIC::Wire::Packet.parse(server.transmits(now: 0.0).first.payload, dcid_length: 8).header.scid
    assert_equal "t".b * 16, tracer.of(:parameters_set).find { _1[:owner] == :local }[:parameters].stateless_reset_token
  end

  def test_matching_ones_connect
    client, server = run_pair
    assert client.handshake_confirmed?
    assert server.handshake_confirmed?
  end
end
