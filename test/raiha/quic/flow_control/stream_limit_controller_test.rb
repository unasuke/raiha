require "test_helper"
require "raiha/quic/flow_control"
require "raiha/quic/protocol/stream_id"

class RaihaQuicFlowControlStreamLimitControllerTest < Minitest::Test
  def test_cannot_open_bidi_without_peer_limit
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 100, max_uni: 100)
    refute controller.can_open_bidi?
  end

  def test_can_open_bidi_after_peer_update
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 100, max_uni: 100)
    controller.update_peer_max_bidi(10)
    assert controller.can_open_bidi?
  end

  def test_open_bidi_exceeds_limit
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 100, max_uni: 100)
    controller.update_peer_max_bidi(1)
    controller.open_bidi
    assert_raises(Raiha::Quic::Qerr::StreamLimitError) do
      controller.open_bidi
    end
  end

  def test_open_uni
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 100, max_uni: 100)
    controller.update_peer_max_uni(5)
    assert controller.can_open_uni?
    controller.open_uni
    assert controller.can_open_uni?
  end

  def test_accept_stream_within_limit
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 10, max_uni: 10)
    stream_id = Raiha::Quic::Protocol::StreamID.new(1) # Server-initiated bidi
    controller.accept_stream(stream_id) # Should not raise
  end

  def test_accept_stream_exceeds_bidi_limit
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 1, max_uni: 10)
    stream_id = Raiha::Quic::Protocol::StreamID.new(4) # Second client bidi stream (id=4, index=1)
    assert_raises(Raiha::Quic::Qerr::StreamLimitError) do
      controller.accept_stream(stream_id)
    end
  end

  def test_accept_stream_exceeds_uni_limit
    controller = Raiha::Quic::FlowControl::StreamLimitController.new(max_bidi: 10, max_uni: 1)
    stream_id = Raiha::Quic::Protocol::StreamID.new(6) # Second client uni stream (id=6, index=1)
    assert_raises(Raiha::Quic::Qerr::StreamLimitError) do
      controller.accept_stream(stream_id)
    end
  end
end
