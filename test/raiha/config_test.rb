require "test_helper"
require "raiha/config"

class RaihaConfigTest < Minitest::Test
  def test_default_values
    config = Raiha::Config.new
    assert_equal 30_000, config.max_idle_timeout
    assert_equal 1200, config.max_udp_payload_size
    assert_equal 100, config.initial_max_streams_bidi
    assert_equal 100, config.initial_max_streams_uni
    assert_equal [Raiha::Quic::Protocol::Version::V1], config.versions
  end

  def test_client_default
    config = Raiha::Config.client_default
    assert_instance_of Raiha::Config, config
  end

  def test_server_default
    config = Raiha::Config.server_default
    assert_instance_of Raiha::Config, config
  end

  def test_to_transport_parameters
    config = Raiha::Config.new
    config.max_idle_timeout = 60_000
    config.initial_max_data = 2_000_000

    transport_parameters = config.to_transport_parameters
    assert_instance_of Raiha::Quic::Handshake::TransportParameters, transport_parameters
    assert_equal 60_000, transport_parameters.max_idle_timeout
    assert_equal 2_000_000, transport_parameters.initial_max_data
  end
end
