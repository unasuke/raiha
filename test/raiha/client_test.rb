require "test_helper"
require "raiha/client"

class RaihaClientTest < Minitest::Test
  def test_initialize
    client = Raiha::Client.new
    refute client.connected?
    assert_nil client.connection
  end

  def test_initialize_with_config
    config = Raiha::Config.new
    config.max_idle_timeout = 60_000
    client = Raiha::Client.new(config: config)
    refute client.connected?
  end

  def test_open_stream_before_connect_raises
    client = Raiha::Client.new
    assert_raises(RuntimeError) { client.open_stream }
  end

  def test_accept_stream_before_connect_raises
    client = Raiha::Client.new
    assert_raises(RuntimeError) { client.accept_stream }
  end

  def test_close_before_connect
    client = Raiha::Client.new
    client.close # should not raise
  end
end
