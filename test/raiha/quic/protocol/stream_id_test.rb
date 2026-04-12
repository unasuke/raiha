require "test_helper"
require "raiha/quic/protocol"

class RaihaQuicProtocolStreamIDTest < Minitest::Test
  def test_client_initiated_bidirectional
    stream_id = Raiha::Quic::Protocol::StreamID.new(0)
    assert stream_id.client_initiated?
    assert stream_id.bidirectional?
    refute stream_id.server_initiated?
    refute stream_id.unidirectional?
  end

  def test_server_initiated_bidirectional
    stream_id = Raiha::Quic::Protocol::StreamID.new(1)
    assert stream_id.server_initiated?
    assert stream_id.bidirectional?
    refute stream_id.client_initiated?
    refute stream_id.unidirectional?
  end

  def test_client_initiated_unidirectional
    stream_id = Raiha::Quic::Protocol::StreamID.new(2)
    assert stream_id.client_initiated?
    assert stream_id.unidirectional?
    refute stream_id.server_initiated?
    refute stream_id.bidirectional?
  end

  def test_server_initiated_unidirectional
    stream_id = Raiha::Quic::Protocol::StreamID.new(3)
    assert stream_id.server_initiated?
    assert stream_id.unidirectional?
    refute stream_id.client_initiated?
    refute stream_id.bidirectional?
  end

  def test_next_bidirectional_client
    stream_id = Raiha::Quic::Protocol::StreamID.next_bidirectional(:client, nil)
    assert_equal 0, stream_id.value
    assert stream_id.client_initiated?
    assert stream_id.bidirectional?
  end

  def test_next_bidirectional_server
    stream_id = Raiha::Quic::Protocol::StreamID.next_bidirectional(:server, nil)
    assert_equal 1, stream_id.value
    assert stream_id.server_initiated?
  end

  def test_next_unidirectional_client
    stream_id = Raiha::Quic::Protocol::StreamID.next_unidirectional(:client, nil)
    assert_equal 2, stream_id.value
    assert stream_id.unidirectional?
  end

  def test_equality
    assert_equal Raiha::Quic::Protocol::StreamID.new(4), Raiha::Quic::Protocol::StreamID.new(4)
    refute_equal Raiha::Quic::Protocol::StreamID.new(4), Raiha::Quic::Protocol::StreamID.new(5)
  end

  def test_initiator
    assert_equal :client, Raiha::Quic::Protocol::StreamID.new(0).initiator
    assert_equal :server, Raiha::Quic::Protocol::StreamID.new(1).initiator
  end
end
