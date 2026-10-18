require "raiha/next/test_helper"
require "raiha/next/support/quic_pair"

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

  def test_matching_ones_connect
    client, server = run_pair
    assert client.handshake_confirmed?
    assert server.handshake_confirmed?
  end
end
