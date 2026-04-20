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
    assert Raiha::Quic::Protocol::StreamID.new(0).initiator.client?
    assert Raiha::Quic::Protocol::StreamID.new(1).initiator.server?
  end

  def test_readable_and_writable_by
    client_bidi = Raiha::Quic::Protocol::StreamID.new(0)
    server_bidi = Raiha::Quic::Protocol::StreamID.new(1)
    client_uni = Raiha::Quic::Protocol::StreamID.new(2)
    server_uni = Raiha::Quic::Protocol::StreamID.new(3)

    # Bidirectional streams are read/write for both sides.
    [client_bidi, server_bidi].each do |sid|
      assert sid.readable_by?(:client)
      assert sid.writable_by?(:client)
      assert sid.readable_by?(:server)
      assert sid.writable_by?(:server)
    end

    # Unidirectional: only the initiator writes; only the non-initiator reads.
    assert client_uni.writable_by?(:client)
    refute client_uni.readable_by?(:client)
    assert client_uni.readable_by?(:server)
    refute client_uni.writable_by?(:server)

    assert server_uni.writable_by?(:server)
    refute server_uni.readable_by?(:server)
    assert server_uni.readable_by?(:client)
    refute server_uni.writable_by?(:client)
  end
end
