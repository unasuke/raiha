require "test_helper"
require "raiha/server"

class RaihaServerTest < Minitest::Test
  def test_initialize
    server = Raiha::Server.new
    assert_empty server.connections
  end

  def test_accept_nonblock_returns_nil_when_empty
    server = Raiha::Server.new
    assert_nil server.accept_nonblock
  end

  def test_close_before_listen
    server = Raiha::Server.new
    server.close # should not raise
  end
end
